package signing

import (
	"container/list"
	"context"
	"errors"
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
	// MaxOrigins bounds cached origins, cooldown entries, and concurrent
	// discoveries. Defaults to 256.
	MaxOrigins int
	// MaxPendingPerOperator bounds concurrent discoveries for origins of
	// one registrable domain, so one operator (for example with wildcard
	// DNS and a stalling server) cannot hold every discovery slot. Defaults
	// to 8.
	MaxPendingPerOperator int
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
// keys from an expired directory never authenticate. A directory that
// cannot be fetched (network error, 5xx, 429, timeout) is a signer-side
// outage (ErrIdentityUnavailable, SERVICE_UNAVAILABLE); one that is fetched
// but absent (404/410), invalid, or missing the key is a signature failure. Concurrent lookups for
// one origin share a single fetch, and one slow origin does not block
// another.
type DirectoryResolver struct {
	fetch          DirectoryFetcher
	maxOrigins     int
	maxPerOperator int
	clock          func() time.Time

	mu       sync.Mutex
	cache    map[string]*directoryEntry  // verified directories only
	lru      *list.List                  // front = most recently used origin
	failures map[string]directoryFailure // discovery cooldowns, kept apart so failures never evict successes
	pending  map[string]*directoryCall
}

type directoryEntry struct {
	origin  string
	resp    *DirectoryResponse
	keys    map[string]JWK
	expires time.Time
	elem    *list.Element
}

// directoryFailure is a discovery cooldown. outage distinguishes a
// directory that could not be fetched (network error, 5xx, 429, timeout:
// SERVICE_UNAVAILABLE) from one that was fetched and is absent or invalid
// (a signature failure).
type directoryFailure struct {
	until  time.Time
	outage bool
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
		fetch:          opts.Fetch,
		maxOrigins:     opts.MaxOrigins,
		maxPerOperator: opts.MaxPendingPerOperator,
		clock:          opts.Clock,
		cache:          map[string]*directoryEntry{},
		lru:            list.New(),
		failures:       map[string]directoryFailure{},
		pending:        map[string]*directoryCall{},
	}
	if d.maxOrigins <= 0 {
		d.maxOrigins = 256
	}
	if d.maxPerOperator <= 0 {
		d.maxPerOperator = 8
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
	if e != nil && now.Before(e.expires) {
		d.lru.MoveToFront(e.elem)
		jwk, ok := e.keys[keyID]
		d.mu.Unlock()
		if !ok {
			return nil, nil
		}
		return &jwk, nil
	}
	if f, ok := d.failures[origin]; ok && now.Before(f.until) {
		d.mu.Unlock()
		if f.outage {
			return nil, identityUnavailable("key directory unavailable (cooling down)", nil)
		}
		return nil, wbaFail(http.StatusForbidden, "", "key directory discovery is cooling down")
	}
	call := d.pending[origin]
	if call == nil {
		if len(d.pending) >= d.maxOrigins {
			d.mu.Unlock()
			return nil, wbaFail(http.StatusTooManyRequests, "", "key directory discovery capacity exceeded")
		}
		op := operatorBucket(origin)
		n := 0
		for o := range d.pending {
			if operatorBucket(o) == op {
				n++
			}
		}
		if n >= d.maxPerOperator {
			d.mu.Unlock()
			return nil, wbaFail(http.StatusTooManyRequests, "", "key directory discovery capacity exceeded for operator")
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
	outage := err != nil || resp == nil || resp.Status >= 500 || resp.Status == http.StatusTooManyRequests
	var keys map[string]JWK
	if !outage {
		keys, err = VerifyDirectoryResponse(origin, resp, d.clock())
	} else if err == nil {
		err = errors.New("key directory fetch failed")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.pending, origin)
	now := d.clock()
	if err != nil {
		// A failure never proves removal and never evicts a verified
		// directory; the previous signed snapshot stays as evidence, and
		// expired keys never authenticate.
		d.failures[origin] = directoryFailure{until: now.Add(discoveryNegativeTTL), outage: outage}
		if len(d.failures) > d.maxOrigins {
			for o, f := range d.failures {
				if !now.Before(f.until) {
					delete(d.failures, o)
				}
			}
			for o := range d.failures {
				if len(d.failures) <= d.maxOrigins {
					break
				}
				if o != origin {
					delete(d.failures, o)
				}
			}
		}
		if outage {
			// The signer's directory could not be fetched: identity cannot
			// be confirmed, which is not the signer's fault (503).
			call.err = identityUnavailable("key directory could not be fetched", err)
			return
		}
		// Fetched, but absent (404/410), invalid, or without valid
		// signatures: a signature failure (403 with Accept-Signature).
		call.err = &WBAError{Status: http.StatusForbidden, Reason: "key directory absent or invalid", Wrapped: err}
		return
	}
	delete(d.failures, origin)
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
