package signing

import (
	"container/list"
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/safefetch"
)

// DirectoryFetcher fetches a key directory URL. It is a trusted transport
// seam: a custom fetcher must enforce the fetch rules itself (HTTPS, SSRF
// checks, no redirects, a 256 KiB cap). The default uses an SSRF-safe
// client that does.
type DirectoryFetcher func(ctx context.Context, url string) (*DirectoryResponse, error)

// DirectoryResolverOptions configures NewDirectoryResolver.
type DirectoryResolverOptions struct {
	// Fetch defaults to an SSRF-safe HTTPS fetch.
	Fetch DirectoryFetcher
	// MaxOrigins bounds cached origins and concurrent discoveries.
	// Defaults to 256.
	MaxOrigins int
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// DirectoryResolver is the WBAKeyResolver for many signers. It discovers
// each signer's keys from the key directory at the origin the covered
// Signature-Agent names and looks keys up by (origin, thumbprint), so a
// seller needs no hand-written keyid-to-agent map. It never reads
// capabilities, brand.json, or trust.json.
//
// Caching follows the profile: a verified directory is cached for at most
// five minutes and never past its signatures' expiry; a key absent from a
// fresh directory is absent (no refetch on a miss); a failed discovery is
// not evidence of removal and is retried after a 60-second cooldown, while
// keys from an expired directory never authenticate. Concurrent lookups for
// one origin share a single fetch, and one slow origin does not block
// another.
type DirectoryResolver struct {
	fetch      DirectoryFetcher
	maxOrigins int
	clock      func() time.Time

	mu      sync.Mutex
	cache   map[string]*directoryEntry
	lru     *list.List // front = most recently used origin
	pending map[string]*directoryCall
}

type directoryEntry struct {
	origin     string
	resp       *DirectoryResponse
	keys       map[string]JWK
	expires    time.Time
	retryAfter time.Time
	elem       *list.Element
}

type directoryCall struct {
	done  chan struct{}
	entry *directoryEntry
	err   error
}

const (
	directoryCacheTTL    = 5 * time.Minute
	discoveryNegativeTTL = 60 * time.Second
	discoveryTimeout     = 10 * time.Second
)

// NewDirectoryResolver returns a DirectoryResolver.
func NewDirectoryResolver(opts DirectoryResolverOptions) *DirectoryResolver {
	d := &DirectoryResolver{
		fetch:      opts.Fetch,
		maxOrigins: opts.MaxOrigins,
		clock:      opts.Clock,
		cache:      map[string]*directoryEntry{},
		lru:        list.New(),
		pending:    map[string]*directoryCall{},
	}
	if d.maxOrigins <= 0 {
		d.maxOrigins = 256
	}
	if d.clock == nil {
		d.clock = time.Now
	}
	if d.fetch == nil {
		client := safefetch.NewClient()
		d.fetch = func(ctx context.Context, url string) (*DirectoryResponse, error) {
			r, err := safefetch.Get(ctx, client, url, safefetch.Options{Accept: DirectoryMediaType, MaxBytes: directoryMaxBytes})
			if err != nil {
				return nil, err
			}
			return &DirectoryResponse{Status: r.Status, Header: r.Header, Body: r.Body}, nil
		}
	}
	return d
}

// ResolveWBAKey implements WBAKeyResolver.
func (d *DirectoryResolver) ResolveWBAKey(ctx context.Context, origin, keyID string) (*JWK, error) {
	origin, err := webBotAuthOrigin(origin)
	if err != nil {
		return nil, &WBAError{Status: http.StatusForbidden, Reason: "invalid signer origin", Wrapped: err}
	}
	d.mu.Lock()
	now := d.clock()
	e := d.cache[origin]
	if e != nil && e.resp != nil && now.Before(e.expires) {
		d.lru.MoveToFront(e.elem)
		jwk, ok := e.keys[keyID]
		d.mu.Unlock()
		if !ok {
			return nil, nil
		}
		return &jwk, nil
	}
	if e != nil && now.Before(e.retryAfter) {
		d.lru.MoveToFront(e.elem)
		d.mu.Unlock()
		return nil, wbaFail(http.StatusForbidden, "", "key directory discovery is cooling down")
	}
	call := d.pending[origin]
	if call == nil {
		if len(d.pending) >= d.maxOrigins {
			d.mu.Unlock()
			return nil, wbaFail(http.StatusTooManyRequests, "", "key directory discovery capacity exceeded")
		}
		call = &directoryCall{done: make(chan struct{})}
		d.pending[origin] = call
		// A caller that gives up does not cancel discovery for other
		// waiters; the fetch keeps its own deadline.
		go d.refresh(context.WithoutCancel(ctx), origin, call)
	}
	d.mu.Unlock()
	select {
	case <-call.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if call.err != nil {
		return nil, call.err
	}
	jwk, ok := call.entry.keys[keyID]
	if !ok {
		return nil, nil
	}
	return &jwk, nil
}

func (d *DirectoryResolver) refresh(ctx context.Context, origin string, call *directoryCall) {
	defer close(call.done)
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	resp, err := d.fetch(ctx, origin+DirectoryPath)
	var keys map[string]JWK
	if err == nil {
		keys, err = VerifyDirectoryResponse(origin, resp, d.clock())
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.pending, origin)
	now := d.clock()
	if err != nil {
		// Keep the previous signed snapshot as evidence. A failure never
		// proves removal, and expired keys never authenticate.
		e := d.cache[origin]
		if e == nil {
			e = &directoryEntry{origin: origin}
		}
		e.retryAfter = now.Add(discoveryNegativeTTL)
		d.store(e)
		call.err = &WBAError{Status: http.StatusForbidden, Reason: "key directory discovery failed", Wrapped: err}
		return
	}
	expires := now.Add(directoryCacheTTL)
	if exp, ok := directoryExpiry(resp); ok && exp.Before(expires) {
		expires = exp
	}
	e := &directoryEntry{origin: origin, resp: resp, keys: keys, expires: expires}
	if old := d.cache[origin]; old != nil {
		e.elem = old.elem
	}
	d.store(e)
	call.entry = e
}

// store inserts or refreshes e and evicts the least recently used origins
// beyond MaxOrigins. Called with mu held.
func (d *DirectoryResolver) store(e *directoryEntry) {
	if e.elem == nil {
		e.elem = d.lru.PushFront(e.origin)
	} else {
		d.lru.MoveToFront(e.elem)
	}
	d.cache[e.origin] = e
	for d.lru.Len() > d.maxOrigins {
		back := d.lru.Back()
		d.lru.Remove(back)
		delete(d.cache, back.Value.(string))
	}
}

// Evidence returns the last verified directory response for origin, the
// record of what the verifier fetched, or nil.
func (d *DirectoryResolver) Evidence(origin string) *DirectoryResponse {
	origin, err := webBotAuthOrigin(origin)
	if err != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.cache[origin]; e != nil {
		return e.resp
	}
	return nil
}
