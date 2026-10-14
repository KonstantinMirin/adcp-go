package identity

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/psl"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/safefetch"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
)

// TrustRecordError is a trust record that provides no authority. It is
// one of two kinds, which the spec treats differently for a bound origin:
//   - not listed (Unlisted or Absent): the operator's record was read and
//     does not list the origin with the role, publishes no record (a 404 or
//     410 before any 200 from that operator), or the origin has no
//     registrable domain. A bound origin falls back to identity-established.
//     Absent is also the one case that permits a configured legacy
//     (brand.json) fallback for grants.
//   - unavailable (neither flag): the record could not be fetched or read.
//     A fetch failure is never absence: spend-committing calls fail with
//     SERVICE_UNAVAILABLE, other calls continue under the cached binding.
type TrustRecordError struct {
	Absent   bool
	Unlisted bool
	Reason   string
	Wrapped  error
}

func (e *TrustRecordError) Error() string { return "identity: " + e.Reason }
func (e *TrustRecordError) Unwrap() error { return e.Wrapped }

// IsTrustRecordAbsent reports whether err is a TrustRecordError with Absent
// set.
func IsTrustRecordAbsent(err error) bool {
	var e *TrustRecordError
	return errors.As(err, &e) && e.Absent
}

// IsTrustRecordUnavailable reports whether err means the record could not
// be read (a fetch, parse, or capacity failure), as opposed to a record
// that does not list the origin. Any error that is not a TrustRecordError
// counts as unavailable.
func IsTrustRecordUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var e *TrustRecordError
	if !errors.As(err, &e) {
		return true
	}
	return !e.Absent && !e.Unlisted
}

func trustErr(reason string, wrapped error) *TrustRecordError {
	return &TrustRecordError{Reason: reason, Wrapped: wrapped}
}

// TrustRecordURL derives the trust record location for an origin or a
// domain: https://{eTLD+1}/.well-known/trust.json, using the pinned ICANN
// and PRIVATE Public Suffix List snapshot. Never a caller-supplied pointer.
// An IP literal, a public suffix, or a host with no eTLD+1 has no record.
func TrustRecordURL(originOrDomain string) (string, error) {
	domain, ok := psl.RegistrableDomain(originOrDomain)
	if !ok {
		return "", &TrustRecordError{Unlisted: true, Reason: "identity has no registrable operator domain"}
	}
	return "https://" + domain + "/.well-known/trust.json", nil
}

// TrustResponse is one trust record fetch.
type TrustResponse struct {
	Status int
	Body   []byte
}

// TrustFetcher fetches a trust record URL. It is a trusted transport seam:
// a custom fetcher must enforce the fetch rules (HTTPS, SSRF checks, no
// redirects, 2 MiB cap). The default does.
type TrustFetcher func(ctx context.Context, url string) (*TrustResponse, error)

// EvaluatedTrustRecord is a validated trust record. OperatorDomain is the
// eTLD+1 the record speaks for, derived from the identity and never read
// from the document or from an authoritative_location hop target.
type EvaluatedTrustRecord struct {
	OperatorDomain string
	SourceURL      string
	Record         *TrustRecord
	ExpiresAt      time.Time
	// Removed reports a record that was read before and is now gone (404
	// or 410): a removal, not an outage. Record is then empty, so it lists
	// no agent and makes no grant, and no legacy fallback applies.
	Removed bool
}

// Agent returns the record's single agents[] entry for origin with role.
func (e *EvaluatedTrustRecord) Agent(origin, role string) (*TrustAgent, error) {
	return e.Record.Agent(origin, role)
}

// TrustRecordEvaluatorOptions configures NewTrustRecordEvaluator.
type TrustRecordEvaluatorOptions struct {
	// Fetch defaults to an SSRF-safe HTTPS fetch with a 2 MiB cap.
	Fetch TrustFetcher
	// PollingInterval bounds how long an evaluation is cached: the
	// revocation polling interval, in (0, 30 min]. Defaults to 60 s.
	PollingInterval time.Duration
	// MaxRecords bounds cached records, negative entries, and concurrent
	// discoveries. Defaults to 256.
	MaxRecords int
	// MaxFetchesPerHost bounds concurrent fetches to one host. Defaults to 4.
	MaxFetchesPerHost int
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// TrustRecordEvaluator evaluates operator trust records at binding, grant
// evaluation, and open onboarding, never on the signature path:
//   - derive https://{eTLD+1}/.well-known/trust.json (TrustRecordURL);
//   - fetch it under the SSRF rules with a 2 MiB cap and strict parsing;
//   - follow at most one authoritative_location hop, with no HTTP redirects,
//     refusing a hop target that itself points onward;
//   - cache the result no longer than the polling interval.
//
// Fetch failures, invalid records, and expired results fail closed. Fetches
// are single-flighted per operator and per URL, bounded per host, and a
// failed fetch is negatively cached for 60 s. A 200 from an operator's
// derived URL is remembered for the evaluator's lifetime, so a later 404
// is never treated as absence (no downgrade to brand.json).
type TrustRecordEvaluator struct {
	fetch      TrustFetcher
	interval   time.Duration
	maxRecords int
	maxPerHost int
	clock      func() time.Time

	mu       sync.Mutex
	cache    map[string]*cachedRecord
	lru      *list.List
	failures map[string]trustFailure
	pending  map[string]*trustCall
	seen200  map[string]*list.Element // operators that have served a 200, LRU-bounded
	seenLRU  *list.List
	lastGood map[string]*list.Element // last record read per operator (*EvaluatedTrustRecord), LRU-bounded
	goodLRU  *list.List

	responses       map[string]cachedResponse
	responsePending map[string]*responseCall
	hostsInflight   map[string]int
	hostFailures    map[string]time.Time
}

type cachedRecord struct {
	rec  *EvaluatedTrustRecord
	elem *list.Element
}

type trustFailure struct {
	err        *TrustRecordError
	retryAfter time.Time
}

type trustCall struct {
	done chan struct{}
	rec  *EvaluatedTrustRecord
	err  error
}

type cachedResponse struct {
	expires time.Time
	resp    *TrustResponse
}

type responseCall struct {
	done chan struct{}
	res  cachedResponse
	err  error
}

const (
	trustNegativeTTL      = 60 * time.Second
	trustMaxInterval      = 30 * time.Minute
	trustDefaultInterval  = 60 * time.Second
	trustDiscoveryTimeout = 10 * time.Second
)

// NewTrustRecordEvaluator returns a TrustRecordEvaluator.
func NewTrustRecordEvaluator(opts TrustRecordEvaluatorOptions) (*TrustRecordEvaluator, error) {
	e := &TrustRecordEvaluator{
		fetch:           opts.Fetch,
		interval:        opts.PollingInterval,
		maxRecords:      opts.MaxRecords,
		maxPerHost:      opts.MaxFetchesPerHost,
		clock:           opts.Clock,
		cache:           map[string]*cachedRecord{},
		lru:             list.New(),
		failures:        map[string]trustFailure{},
		pending:         map[string]*trustCall{},
		seen200:         map[string]*list.Element{},
		seenLRU:         list.New(),
		lastGood:        map[string]*list.Element{},
		goodLRU:         list.New(),
		responses:       map[string]cachedResponse{},
		responsePending: map[string]*responseCall{},
		hostsInflight:   map[string]int{},
		hostFailures:    map[string]time.Time{},
	}
	if e.interval == 0 {
		e.interval = trustDefaultInterval
	}
	if e.interval < 0 || e.interval > trustMaxInterval {
		return nil, errors.New("identity: PollingInterval must be in (0, 30m]")
	}
	if e.maxRecords <= 0 {
		e.maxRecords = 256
	}
	if e.maxPerHost <= 0 {
		e.maxPerHost = 4
	}
	if e.clock == nil {
		e.clock = time.Now
	}
	if e.fetch == nil {
		client := safefetch.NewClient()
		e.fetch = func(ctx context.Context, u string) (*TrustResponse, error) {
			r, err := safefetch.Get(ctx, client, u, safefetch.Options{Accept: "application/json", MaxBytes: TrustRecordMaxBytes})
			if err != nil {
				return nil, err
			}
			return &TrustResponse{Status: r.Status, Body: r.Body}, nil
		}
	}
	return e, nil
}

// PollingInterval returns the evaluator's cache bound.
func (e *TrustRecordEvaluator) PollingInterval() time.Duration { return e.interval }

// Evaluate returns the trust record for the operator of originOrDomain.
// With role set, the record must list exactly one agent whose canonical
// origin is originOrDomain and that carries role. The returned record is a
// copy; mutating it cannot change cached authority.
func (e *TrustRecordEvaluator) Evaluate(ctx context.Context, originOrDomain, role string) (*EvaluatedTrustRecord, error) {
	recordURL, err := TrustRecordURL(originOrDomain)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(recordURL)
	domain := u.Hostname()
	e.mu.Lock()
	now := e.clock()
	var rec *EvaluatedTrustRecord
	var call *trustCall
	if c := e.cache[domain]; c != nil && now.Before(c.rec.ExpiresAt) {
		e.lru.MoveToFront(c.elem)
		rec = c.rec
	} else {
		if f, ok := e.failures[domain]; ok && now.Before(f.retryAfter) {
			e.mu.Unlock()
			return nil, f.err
		}
		call = e.pending[domain]
		if call == nil {
			if len(e.pending) >= e.maxRecords {
				e.mu.Unlock()
				return nil, trustErr("trust discovery capacity exceeded", nil)
			}
			call = &trustCall{done: make(chan struct{})}
			e.pending[domain] = call
			// One disconnected caller cannot cancel the shared fetch.
			go e.refresh(context.WithoutCancel(ctx), domain, recordURL, call)
		}
	}
	e.mu.Unlock()
	if call != nil {
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if call.err != nil {
			return nil, call.err
		}
		rec = call.rec
	}
	if !e.clock().Before(rec.ExpiresAt) {
		return nil, trustErr("trust record expired while being evaluated", nil)
	}
	if role != "" {
		if _, err := rec.Agent(originOrDomain, role); err != nil {
			return nil, &TrustRecordError{Unlisted: true, Reason: "trust record does not list the origin with the required role", Wrapped: err}
		}
	}
	return rec.clone(), nil
}

func (r *EvaluatedTrustRecord) clone() *EvaluatedTrustRecord {
	out := *r
	b, err := json.Marshal(r.Record)
	if err == nil {
		var rec TrustRecord
		if json.Unmarshal(b, &rec) == nil {
			out.Record = &rec
		}
	}
	return &out
}

func (e *TrustRecordEvaluator) refresh(ctx context.Context, domain, recordURL string, call *trustCall) {
	defer close(call.done)
	ctx, cancel := context.WithTimeout(ctx, trustDiscoveryTimeout)
	defer cancel()
	rec, err := e.resolve(ctx, domain, recordURL)
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.pending, domain)
	if err != nil {
		var te *TrustRecordError
		if !errors.As(err, &te) {
			te = trustErr("trust record fetch failed", err)
		}
		e.failures[domain] = trustFailure{err: te, retryAfter: e.clock().Add(trustNegativeTTL)}
		e.boundFailures()
		call.err = te
		return
	}
	if c := e.cache[domain]; c != nil {
		c.rec = rec
		e.lru.MoveToFront(c.elem)
	} else {
		e.cache[domain] = &cachedRecord{rec: rec, elem: e.lru.PushFront(domain)}
	}
	delete(e.failures, domain)
	for e.lru.Len() > e.maxRecords {
		back := e.lru.Back()
		e.lru.Remove(back)
		delete(e.cache, back.Value.(string))
	}
	e.storeLastGood(domain, rec)
	call.rec = rec
}

// boundFailures keeps the negative cache within MaxRecords, dropping
// expired entries first. Called with mu held.
func (e *TrustRecordEvaluator) boundFailures() {
	if len(e.failures) <= e.maxRecords {
		return
	}
	now := e.clock()
	for d, f := range e.failures {
		if !now.Before(f.retryAfter) {
			delete(e.failures, d)
		}
	}
	for len(e.failures) > e.maxRecords {
		var oldest string
		var at time.Time
		for d, f := range e.failures {
			if oldest == "" || f.retryAfter.Before(at) {
				oldest, at = d, f.retryAfter
			}
		}
		delete(e.failures, oldest)
	}
}

func (e *TrustRecordEvaluator) resolve(ctx context.Context, domain, recordURL string) (*EvaluatedTrustRecord, error) {
	source := recordURL
	expires := e.clock().Add(e.interval)
	for hop := 0; hop < 2; hop++ {
		if err := safefetch.ValidateTarget(source); err != nil {
			return nil, trustErr("invalid trust fetch target", err)
		}
		res, err := e.fetchResponse(ctx, source)
		if err != nil {
			return nil, trustErr("trust record fetch failed", err)
		}
		if res.expires.Before(expires) {
			expires = res.expires
		}
		status := res.resp.Status
		e.mu.Lock()
		_, seen := e.seen200[domain]
		e.mu.Unlock()
		if status == http.StatusNotFound || status == http.StatusGone {
			if seen {
				// A record read before and now gone is a removal: every
				// origin it listed is delisted, and brand.json does not
				// come back.
				return &EvaluatedTrustRecord{OperatorDomain: domain, SourceURL: source, Record: &TrustRecord{}, ExpiresAt: expires, Removed: true}, nil
			}
			if hop == 0 {
				return nil, &TrustRecordError{Absent: true, Reason: "no trust record is published"}
			}
		}
		if status != http.StatusOK || len(res.resp.Body) > TrustRecordMaxBytes {
			return nil, trustErr(fmt.Sprintf("trust record unavailable (HTTP %d)", status), nil)
		}
		e.mu.Lock()
		e.markSeen200(domain)
		e.mu.Unlock()
		rec, err := ValidateTrustRecord(res.resp.Body, TrustRecordOptions{Mode: Reading, Owner: domain})
		if err != nil {
			return nil, trustErr("trust record is invalid", err)
		}
		if rec.AuthoritativeLocation == "" {
			return &EvaluatedTrustRecord{OperatorDomain: domain, SourceURL: source, Record: rec, ExpiresAt: expires}, nil
		}
		if hop == 1 {
			return nil, trustErr("a second authoritative_location hop is forbidden", nil)
		}
		source = rec.AuthoritativeLocation
	}
	return nil, trustErr("trust record resolution failed", nil)
}

// seen200Limit bounds the operators remembered as having served a 200.
// Evicting one re-allows the legacy fallback for it after a later 404, so
// the bound is generous; deployments that need the guarantee across
// restarts persist it themselves.
const seen200Limit = 1 << 16

// markSeen200 records that domain served a 200. Called with mu held.
func (e *TrustRecordEvaluator) markSeen200(domain string) {
	if el, ok := e.seen200[domain]; ok {
		e.seenLRU.MoveToFront(el)
		return
	}
	e.seen200[domain] = e.seenLRU.PushFront(domain)
	for e.seenLRU.Len() > seen200Limit {
		back := e.seenLRU.Back()
		e.seenLRU.Remove(back)
		delete(e.seen200, back.Value.(string))
	}
}

// storeLastGood records rec as the last record read for domain. Called
// with mu held.
func (e *TrustRecordEvaluator) storeLastGood(domain string, rec *EvaluatedTrustRecord) {
	if el, ok := e.lastGood[domain]; ok {
		el.Value = rec
		e.goodLRU.MoveToFront(el)
		return
	}
	e.lastGood[domain] = e.goodLRU.PushFront(rec)
	for e.goodLRU.Len() > seen200Limit {
		back := e.goodLRU.Back()
		e.goodLRU.Remove(back)
		delete(e.lastGood, back.Value.(*EvaluatedTrustRecord).OperatorDomain)
	}
}

// ListingStatus is the outcome of CheckListing.
type ListingStatus int

const (
	// Listed: the operator's record lists the origin with the role.
	Listed ListingStatus = iota
	// Unlisted: the last record read does not list it (including a removed
	// record, no published record, or no registrable domain).
	Unlisted
	// Unavailable: the record cannot be read now, and the last record read
	// listed the origin (or there is none).
	Unavailable
)

// Listing is the outcome of CheckListing.
type Listing struct {
	Status ListingStatus
	// Record is the evaluated record when Listed.
	Record *EvaluatedTrustRecord
	// WithinGrace, for Unavailable, reports that the last record that
	// listed the origin is within 4x the polling interval past its
	// freshness, so non-spend calls may continue under a binding.
	WithinGrace bool
	// Err is the evaluation error, for logs.
	Err error
}

// CheckListing evaluates whether the origin's operator lists it with role,
// applying the outage rules: a fetch failure is not absence, and an outage
// never restores access.
//   - The last record read stays authoritative: if it did not list the
//     origin, the origin stays Unlisted even when a refresh fails, whatever
//     the cause (including a rate or concurrency cap).
//   - A 404 or 410 is Unlisted: after a record has been read it is a
//     removal, and without that history (another replica, a restart) a
//     bound origin's operator was once authoritative anyway, so the result
//     is the same on every replica.
//   - Otherwise an unreadable record is Unavailable, WithinGrace while the
//     last record that listed the origin is no more than 4x the polling
//     interval past its freshness.
func (e *TrustRecordEvaluator) CheckListing(ctx context.Context, origin, role string) Listing {
	rec, err := e.Evaluate(ctx, origin, role)
	if err == nil {
		return Listing{Status: Listed, Record: rec}
	}
	if !IsTrustRecordUnavailable(err) {
		// Not listed, absent or removed, or no registrable domain.
		return Listing{Status: Unlisted, Err: err}
	}
	domain, ok := psl.RegistrableDomain(origin)
	if !ok {
		return Listing{Status: Unlisted, Err: err}
	}
	e.mu.Lock()
	var last *EvaluatedTrustRecord
	if el, ok := e.lastGood[domain]; ok {
		last = el.Value.(*EvaluatedTrustRecord)
	}
	e.mu.Unlock()
	if last == nil {
		return Listing{Status: Unavailable, Err: err}
	}
	if _, merr := last.Agent(origin, role); merr != nil {
		return Listing{Status: Unlisted, Err: err}
	}
	grace := 4 * e.interval
	return Listing{Status: Unavailable, WithinGrace: e.clock().Before(last.ExpiresAt.Add(grace)), Err: err}
}

// fetchResponse shares transport bytes per URL while each owner validates
// them separately. A cached response's lifetime bounds the record built
// from it, so a shared hop cannot extend old authority.
func (e *TrustRecordEvaluator) fetchResponse(ctx context.Context, rawURL string) (cachedResponse, error) {
	u, _ := url.Parse(rawURL)
	host := u.Hostname()
	e.mu.Lock()
	now := e.clock()
	if c, ok := e.responses[rawURL]; ok && now.Before(c.expires) {
		e.mu.Unlock()
		return c, nil
	}
	if until, ok := e.hostFailures[host]; ok && now.Before(until) {
		e.mu.Unlock()
		return cachedResponse{}, errors.New("trust fetch host is cooling down")
	}
	call := e.responsePending[rawURL]
	if call == nil {
		if len(e.responsePending) >= e.maxRecords || e.hostsInflight[host] >= e.maxPerHost {
			e.mu.Unlock()
			return cachedResponse{}, errors.New("trust fetch host capacity exceeded")
		}
		call = &responseCall{done: make(chan struct{})}
		e.responsePending[rawURL] = call
		e.hostsInflight[host]++
		go e.refreshResponse(context.WithoutCancel(ctx), rawURL, host, call)
	}
	e.mu.Unlock()
	select {
	case <-call.done:
	case <-ctx.Done():
		return cachedResponse{}, ctx.Err()
	}
	return call.res, call.err
}

func (e *TrustRecordEvaluator) refreshResponse(ctx context.Context, rawURL, host string, call *responseCall) {
	defer close(call.done)
	ctx, cancel := context.WithTimeout(ctx, trustDiscoveryTimeout)
	defer cancel()
	resp, err := e.fetch(ctx, rawURL)
	if err == nil && len(resp.Body) > TrustRecordMaxBytes {
		err = errors.New("trust record is larger than 2 MiB")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.responsePending, rawURL)
	if e.hostsInflight[host]--; e.hostsInflight[host] <= 0 {
		delete(e.hostsInflight, host)
	}
	now := e.clock()
	if err != nil {
		// A host failure is never treated as the owner's absence.
		e.coolHost(host, now)
		call.err = err
		return
	}
	ttl := e.interval
	if resp.Status != http.StatusOK {
		ttl = trustNegativeTTL
	}
	call.res = cachedResponse{expires: now.Add(ttl), resp: resp}
	e.responses[rawURL] = call.res
	if len(e.responses) > e.maxRecords {
		for k, c := range e.responses {
			if !now.Before(c.expires) {
				delete(e.responses, k)
			}
		}
		for k := range e.responses {
			if len(e.responses) <= e.maxRecords {
				break
			}
			if k != rawURL {
				delete(e.responses, k)
			}
		}
	}
	if resp.Status >= 500 || resp.Status == http.StatusTooManyRequests {
		e.coolHost(host, now)
	}
}

// coolHost records a 60 s host cooldown. Called with mu held.
func (e *TrustRecordEvaluator) coolHost(host string, now time.Time) {
	e.hostFailures[host] = now.Add(trustNegativeTTL)
	if len(e.hostFailures) > e.maxRecords {
		for h, until := range e.hostFailures {
			if !now.Before(until) {
				delete(e.hostFailures, h)
			}
		}
		for h := range e.hostFailures {
			if len(e.hostFailures) <= e.maxRecords {
				break
			}
			if h != host {
				delete(e.hostFailures, h)
			}
		}
	}
}

// Bind evaluates the trust record of a verified Web Bot Auth signer's
// operator, which must list the signer's origin with role (default
// adcp:buying), and then records the binding in store. This is the explicit,
// audited seller decision that turns an identity-established origin into a
// principal; verification alone never does.
func (e *TrustRecordEvaluator) Bind(ctx context.Context, signer *signing.VerifiedSigner, principalID string, store BindingStore, opts BindOptions) (*EvaluatedTrustRecord, error) {
	if signer == nil || signer.Profile != signing.ProfileTagWebBotAuth || signer.AgentURL == "" {
		return nil, errors.New("identity: binding requires a verified Web Bot Auth identity")
	}
	role := opts.Role
	if role == "" {
		role = RoleBuying
	}
	rec, err := e.Evaluate(ctx, signer.AgentURL, role)
	if err != nil {
		return nil, err
	}
	if err := store.Bind(ctx, signer.AgentURL, principalID, opts); err != nil {
		return nil, err
	}
	return rec, nil
}
