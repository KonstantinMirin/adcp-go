package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/psl"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/safefetch"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/strictjson"
)

const (
	// RevocationListPath is the well-known path of an identity's signed
	// revocation list.
	RevocationListPath = "/.well-known/governance-revocations.json"

	// RevocationListTyp is the JWS typ of a revocation list.
	RevocationListTyp = "adcp-gov-revocation+jws"

	revocationMaxBytes        = 1 << 20
	revocationMinInterval     = 60 * time.Second
	revocationMaxInterval     = 15 * time.Minute
	defaultRevocationGrace    = 2.0
	revocationClockSkew       = 60 * time.Second
	defaultRevocationOrigins  = 256
	defaultOriginsPerOperator = 8
)

// RFC 5280 §5.3.1 revocation reason codes, in the JSON spelling of RFC 8555
// §7.6.
const (
	RevocationReasonUnspecified          = "unspecified"
	RevocationReasonKeyCompromise        = "keyCompromise"
	RevocationReasonCACompromise         = "cACompromise"
	RevocationReasonAffiliationChanged   = "affiliationChanged"
	RevocationReasonSuperseded           = "superseded"
	RevocationReasonCessationOfOperation = "cessationOfOperation"
	RevocationReasonCertificateHold      = "certificateHold"
	RevocationReasonRemoveFromCRL        = "removeFromCRL"
	RevocationReasonPrivilegeWithdrawn   = "privilegeWithdrawn"
	RevocationReasonAACompromise         = "aACompromise"
)

var revocationReasons = map[string]struct{}{
	RevocationReasonUnspecified: {}, RevocationReasonKeyCompromise: {}, RevocationReasonCACompromise: {},
	RevocationReasonAffiliationChanged: {}, RevocationReasonSuperseded: {}, RevocationReasonCessationOfOperation: {},
	RevocationReasonCertificateHold: {}, RevocationReasonRemoveFromCRL: {}, RevocationReasonPrivilegeWithdrawn: {},
	RevocationReasonAACompromise: {},
}

// RevocationDetails is an optional revocation_details entry: an RFC 5280
// reason and the date from which the key is known or suspected to be
// compromised (RFC 5280 §5.3.2). EXPERIMENTAL (AdCP 3.3).
type RevocationDetails struct {
	Reason         string     `json:"reason,omitempty"`
	InvalidityDate *time.Time `json:"invalidity_date,omitempty"`
}

// Merge returns the most severe combination of d and newer: keyCompromise
// if either says so, otherwise the earlier-seen reason, and the earliest
// invalidity date. A detail is never withdrawn or weakened.
func (d RevocationDetails) Merge(newer RevocationDetails) RevocationDetails {
	out := RevocationDetails{Reason: d.Reason}
	if d.Reason == RevocationReasonKeyCompromise || newer.Reason == RevocationReasonKeyCompromise {
		out.Reason = RevocationReasonKeyCompromise
	} else if out.Reason == "" {
		out.Reason = newer.Reason
	}
	switch {
	case d.InvalidityDate == nil:
		out.InvalidityDate = newer.InvalidityDate
	case newer.InvalidityDate == nil || d.InvalidityDate.Before(*newer.InvalidityDate):
		out.InvalidityDate = d.InvalidityDate
	default:
		out.InvalidityDate = newer.InvalidityDate
	}
	return out
}

// Exposes reports whether a request the seller received at receivedAt,
// verified under a key with these details, is suspect: the key was revoked
// for keyCompromise and the request arrived at or after the invalidity
// date, or at any time when there is none. receivedAt is the seller's
// receipt time, never the signature's created, which the signer controls.
// Any other reason exposes nothing.
func (d RevocationDetails) Exposes(receivedAt time.Time) bool {
	return d.Reason == RevocationReasonKeyCompromise &&
		(d.InvalidityDate == nil || !receivedAt.Before(*d.InvalidityDate))
}

// RevocationList is a verified revocation list payload. EXPERIMENTAL in its
// revocation_details handling (AdCP 3.3).
type RevocationList struct {
	Version     int
	Issuer      string
	Updated     time.Time
	NextUpdate  time.Time
	RevokedKids map[string]struct{}
	RevokedJTIs map[string]struct{}
	Details     map[string]RevocationDetails
}

// IsRevoked reports whether keyID is revoked.
func (l *RevocationList) IsRevoked(keyID string) bool {
	_, ok := l.RevokedKids[keyID]
	return ok
}

// Retain folds previous into l so a revocation is never withdrawn and a
// detail never weakened: every key and jti previous revoked stays revoked,
// and each key keeps the most severe detail either list carries.
func (l *RevocationList) Retain(previous *RevocationList) error {
	if previous == nil {
		return nil
	}
	if l.Issuer != previous.Issuer {
		return errors.New("signing: cannot merge revocation lists from different issuers")
	}
	for k := range previous.RevokedKids {
		l.RevokedKids[k] = struct{}{}
	}
	for j := range previous.RevokedJTIs {
		l.RevokedJTIs[j] = struct{}{}
	}
	for kid, old := range previous.Details {
		if cur, ok := l.Details[kid]; ok {
			l.Details[kid] = old.Merge(cur)
		} else {
			l.Details[kid] = old
		}
	}
	return nil
}

// ParseRevocationList validates a revocation list payload (the JSON inside
// the JWS) for issuer: a positive version, an issuer whose canonical origin
// is issuer, RFC 3339 updated and next_update at least 60 s apart, string
// arrays of revoked kids and jtis, and revocation_details keyed only by
// revoked kids, with known RFC 5280 reasons and timezone-qualified dates.
func ParseRevocationList(payload []byte, issuer string) (*RevocationList, error) {
	var raw struct {
		Version     *int                       `json:"version"`
		Issuer      *string                    `json:"issuer"`
		Updated     *string                    `json:"updated"`
		NextUpdate  *string                    `json:"next_update"`
		RevokedKids []string                   `json:"revoked_kids"`
		RevokedJTIs []string                   `json:"revoked_jtis"`
		Details     map[string]json.RawMessage `json:"revocation_details"`
	}
	if err := strictjson.Unmarshal(payload, 0, &raw); err != nil {
		return nil, fmt.Errorf("signing: revocation list payload: %w", err)
	}
	if raw.Version == nil || *raw.Version < 1 {
		return nil, errors.New("signing: revocation list version must be a positive integer")
	}
	if raw.Issuer == nil || raw.Updated == nil || raw.NextUpdate == nil {
		return nil, errors.New("signing: revocation list requires issuer, updated, and next_update")
	}
	if u, err := url.Parse(*raw.Issuer); err != nil || u.User != nil {
		return nil, errors.New("signing: revocation list issuer is not a valid origin")
	}
	got, err := CanonicalOrigin(*raw.Issuer)
	if err != nil || got != issuer {
		return nil, errors.New("signing: revocation list issuer does not match the identity")
	}
	updated, err1 := time.Parse(time.RFC3339Nano, *raw.Updated)
	next, err2 := time.Parse(time.RFC3339Nano, *raw.NextUpdate)
	if err1 != nil || err2 != nil {
		return nil, errors.New("signing: revocation list timestamps must be RFC 3339")
	}
	if next.Sub(updated) < revocationMinInterval {
		return nil, errors.New("signing: revocation list declared cadence is below the 60 s floor")
	}
	l := &RevocationList{
		Version:     *raw.Version,
		Issuer:      issuer,
		Updated:     updated,
		NextUpdate:  next,
		RevokedKids: map[string]struct{}{},
		RevokedJTIs: map[string]struct{}{},
		Details:     map[string]RevocationDetails{},
	}
	for _, k := range raw.RevokedKids {
		l.RevokedKids[k] = struct{}{}
	}
	for _, j := range raw.RevokedJTIs {
		l.RevokedJTIs[j] = struct{}{}
	}
	for kid, rawDetail := range raw.Details {
		if _, ok := l.RevokedKids[kid]; !ok {
			return nil, errors.New("signing: revocation_details must describe revoked_kids only")
		}
		var d struct {
			Reason         *string `json:"reason"`
			InvalidityDate *string `json:"invalidity_date"`
		}
		if err := json.Unmarshal(rawDetail, &d); err != nil || bytes.TrimSpace(rawDetail)[0] != '{' {
			return nil, errors.New("signing: revocation_details entry must be an object")
		}
		var detail RevocationDetails
		if d.Reason != nil {
			if _, ok := revocationReasons[*d.Reason]; !ok {
				return nil, errors.New("signing: unknown RFC 5280 revocation reason")
			}
			detail.Reason = *d.Reason
		}
		if d.InvalidityDate != nil {
			t, err := time.Parse(time.RFC3339Nano, *d.InvalidityDate)
			if err != nil {
				return nil, errors.New("signing: invalidity_date must be an RFC 3339 timestamp with a timezone")
			}
			detail.InvalidityDate = &t
		}
		l.Details[kid] = detail
	}
	return l, nil
}

// verifyRevocationJWS verifies a revocation list JWS in compact, flattened
// JSON, or single-signature general JSON serialization and returns its
// payload. The protected header must carry alg EdDSA or ES256, typ
// adcp-gov-revocation+jws, a kid, and no crit; the kid is resolved by
// resolve and the key's algorithm must match alg.
func verifyRevocationJWS(body []byte, resolve func(kid string) (*JWK, error)) ([]byte, error) {
	body = bytes.TrimSpace(body)
	var protected, payload, signature string
	if len(body) > 0 && body[0] == '{' {
		var doc struct {
			Payload    *string `json:"payload"`
			Protected  *string `json:"protected"`
			Signature  *string `json:"signature"`
			Signatures []struct {
				Protected *string `json:"protected"`
				Signature *string `json:"signature"`
			} `json:"signatures"`
		}
		if err := strictjson.Unmarshal(body, 0, &doc); err != nil || doc.Payload == nil {
			return nil, errors.New("signing: revocation list is not a JWS")
		}
		payload = *doc.Payload
		switch {
		case doc.Signatures != nil && doc.Protected == nil && doc.Signature == nil:
			if len(doc.Signatures) != 1 || doc.Signatures[0].Protected == nil || doc.Signatures[0].Signature == nil {
				return nil, errors.New("signing: revocation list JWS must carry exactly one signature")
			}
			protected, signature = *doc.Signatures[0].Protected, *doc.Signatures[0].Signature
		case doc.Signatures == nil && doc.Protected != nil && doc.Signature != nil:
			protected, signature = *doc.Protected, *doc.Signature
		default:
			return nil, errors.New("signing: revocation list JWS serialization is ambiguous")
		}
	} else {
		parts := strings.Split(string(body), ".")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, errors.New("signing: revocation list compact JWS is malformed")
		}
		protected, payload, signature = parts[0], parts[1], parts[2]
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return nil, errors.New("signing: JWS protected header is not base64url")
	}
	var header map[string]json.RawMessage
	if err := strictjson.Unmarshal(headerBytes, 0, &header); err != nil {
		return nil, errors.New("signing: JWS protected header is not a JSON object")
	}
	var alg, typ, kid string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["typ"], &typ)
	_ = json.Unmarshal(header["kid"], &kid)
	var want Algorithm
	switch alg {
	case string(jwkAlgEdDSA):
		want = AlgEd25519
	case string(jwkAlgES256):
		want = AlgES256
	default:
		return nil, errors.New("signing: JWS alg not allowed")
	}
	if typ != RevocationListTyp {
		return nil, errors.New("signing: JWS typ is not " + RevocationListTyp)
	}
	if crit, ok := header["crit"]; ok {
		var list []string
		if json.Unmarshal(crit, &list) != nil || len(list) > 0 {
			return nil, errors.New("signing: JWS crit is not supported")
		}
	}
	if kid == "" {
		return nil, errors.New("signing: JWS protected header must carry a kid")
	}
	jwk, err := resolve(kid)
	if err != nil {
		return nil, err
	}
	if jwk == nil {
		return nil, errors.New("signing: JWS kid is not in the identity's key directory")
	}
	keyAlg, err := wbaKeyAlgorithm(*jwk)
	if err != nil || keyAlg != want {
		return nil, errors.New("signing: JWS key does not match alg")
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.New("signing: JWS signature is not base64url")
	}
	pub, err := jwk.PublicKey()
	if err != nil || !verifySignature(want, pub, []byte(protected+"."+payload), sig) {
		return nil, errors.New("signing: revocation list signature did not verify")
	}
	out, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("signing: JWS payload is not base64url")
	}
	return out, nil
}

// RevocationFetchResult is one revocation list fetch. NotModified reports a
// 304 answer to a conditional request.
type RevocationFetchResult struct {
	Status       int
	Body         []byte
	ETag         string
	LastModified string
}

// RevocationFetcher fetches a revocation list URL, sending If-None-Match
// and If-Modified-Since when non-empty. It is a trusted transport seam; the
// default enforces HTTPS, SSRF checks, no redirects, and a 1 MiB cap.
type RevocationFetcher func(ctx context.Context, url, ifNoneMatch, ifModifiedSince string) (*RevocationFetchResult, error)

// OriginRevocationCheckerOptions configures NewOriginRevocationChecker.
type OriginRevocationCheckerOptions struct {
	// Keys resolves the list's JWS kid in the identity's own key directory.
	// Required; usually the same DirectoryResolver the verifier uses.
	Keys WBAKeyResolver
	// Fetch defaults to an SSRF-safe HTTPS fetch.
	Fetch RevocationFetcher
	// MaxOrigins bounds admitted origins (default 256), and
	// MaxOriginsPerOperator the origins per registrable domain (default 8),
	// so one operator cannot exhaust admission for others.
	MaxOrigins            int
	MaxOriginsPerOperator int
	// GraceMultiplier sets the fail-closed point at next_update plus this
	// many polling intervals. Defaults to 2, as in the Python SDK.
	GraceMultiplier float64
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// OriginRevocationChecker reads each Web Bot Auth identity's signed
// revocation list at its own origin (RevocationListPath, typ
// adcp-gov-revocation+jws, signed by a key in that origin's directory) and
// implements WBARevocationChecker.
//
// Revocation is monotonic: every key and detail ever seen for an origin is
// retained across refreshes, a list older than the cached one is refused,
// and keyCompromise and the earliest invalidity_date win. An origin is
// admitted only after its first signed, fresh list verifies; a failed first
// discovery costs a bounded 60-second cooldown entry, not an admission
// slot. Past next_update plus the grace, checks fail closed. State lives in
// memory: durable deployments should persist revocation history across
// restarts, or supply their own WBARevocationChecker.
type OriginRevocationChecker struct {
	keys           WBAKeyResolver
	fetch          RevocationFetcher
	maxOrigins     int
	maxPerOperator int
	grace          float64
	clock          func() time.Time

	mu       sync.Mutex
	origins  map[string]*originRevocations
	failures map[string]time.Time
	pending  map[string]*revocationCall
}

type revocationCall struct {
	done chan struct{}
	err  error
}

type originRevocations struct {
	origin string

	mu           sync.Mutex
	current      *RevocationList
	etag         string
	lastModified string
	lastAttempt  time.Time
	interval     time.Duration
}

// NewOriginRevocationChecker returns an OriginRevocationChecker.
func NewOriginRevocationChecker(opts OriginRevocationCheckerOptions) (*OriginRevocationChecker, error) {
	if opts.Keys == nil {
		return nil, errors.New("signing: OriginRevocationChecker requires Keys")
	}
	c := &OriginRevocationChecker{
		keys:           opts.Keys,
		fetch:          opts.Fetch,
		maxOrigins:     opts.MaxOrigins,
		maxPerOperator: opts.MaxOriginsPerOperator,
		grace:          opts.GraceMultiplier,
		clock:          opts.Clock,
		origins:        map[string]*originRevocations{},
		failures:       map[string]time.Time{},
		pending:        map[string]*revocationCall{},
	}
	if c.maxOrigins <= 0 {
		c.maxOrigins = defaultRevocationOrigins
	}
	if c.maxPerOperator <= 0 {
		c.maxPerOperator = defaultOriginsPerOperator
	}
	if c.grace <= 0 {
		c.grace = defaultRevocationGrace
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.fetch == nil {
		client := safefetch.NewClient()
		c.fetch = func(ctx context.Context, u, inm, ims string) (*RevocationFetchResult, error) {
			h := http.Header{}
			if inm != "" {
				h.Set("If-None-Match", inm)
			}
			if ims != "" {
				h.Set("If-Modified-Since", ims)
			}
			r, err := safefetch.Get(ctx, client, u, safefetch.Options{
				Accept:   "application/jose+json, application/json, application/jose",
				MaxBytes: revocationMaxBytes,
				Header:   h,
			})
			if err != nil {
				return nil, err
			}
			return &RevocationFetchResult{Status: r.Status, Body: r.Body, ETag: r.Header.Get("ETag"), LastModified: r.Header.Get("Last-Modified")}, nil
		}
	}
	return c, nil
}

// RevokedWBAKey implements WBARevocationChecker.
func (c *OriginRevocationChecker) RevokedWBAKey(ctx context.Context, origin, keyID string) (bool, error) {
	state, err := c.admit(ctx, origin)
	if err != nil {
		return false, err
	}
	list, err := state.fresh(ctx, c)
	if err != nil {
		return false, &WBAError{Status: http.StatusForbidden, Reason: "origin revocation status unavailable", Wrapped: err}
	}
	return list.IsRevoked(keyID), nil
}

// Details returns the retained revocation detail for (origin, keyID), for
// assessing compromise exposure with RevocationDetails.Exposes.
func (c *OriginRevocationChecker) Details(origin, keyID string) (RevocationDetails, bool) {
	origin, err := webBotAuthOrigin(origin)
	if err != nil {
		return RevocationDetails{}, false
	}
	c.mu.Lock()
	state := c.origins[origin]
	c.mu.Unlock()
	if state == nil {
		return RevocationDetails{}, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.current == nil || !state.current.IsRevoked(keyID) {
		return RevocationDetails{}, false
	}
	return state.current.Details[keyID], true
}

func operatorBucket(origin string) string {
	if d, ok := psl.RegistrableDomain(origin); ok {
		return d
	}
	if u, err := url.Parse(origin); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return origin
}

func (c *OriginRevocationChecker) admit(ctx context.Context, origin string) (*originRevocations, error) {
	origin, err := webBotAuthOrigin(origin)
	if err != nil {
		return nil, &WBAError{Status: http.StatusForbidden, Reason: "invalid signer origin", Wrapped: err}
	}
	for {
		c.mu.Lock()
		if state := c.origins[origin]; state != nil {
			c.mu.Unlock()
			return state, nil
		}
		now := c.clock()
		if until, ok := c.failures[origin]; ok && now.Before(until) {
			c.mu.Unlock()
			return nil, wbaFail(http.StatusForbidden, "", "origin revocation discovery is cooling down")
		}
		call := c.pending[origin]
		if call == nil {
			if len(c.origins)+len(c.pending) >= c.maxOrigins {
				c.mu.Unlock()
				return nil, wbaFail(http.StatusTooManyRequests, "", "origin revocation capacity exceeded")
			}
			op := operatorBucket(origin)
			n := 0
			for o := range c.origins {
				if operatorBucket(o) == op {
					n++
				}
			}
			for o := range c.pending {
				if operatorBucket(o) == op {
					n++
				}
			}
			if n >= c.maxPerOperator {
				c.mu.Unlock()
				return nil, wbaFail(http.StatusTooManyRequests, "", "operator revocation capacity exceeded")
			}
			call = &revocationCall{done: make(chan struct{})}
			c.pending[origin] = call
			go c.discover(context.WithoutCancel(ctx), origin, call)
		}
		c.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if call.err != nil {
			return nil, call.err
		}
	}
}

// discover primes an origin's list. The origin is admitted, and its history
// retained for the life of the checker, only once a signed, fresh list has
// verified, so a 404 or an outage cannot consume an admission slot.
func (c *OriginRevocationChecker) discover(ctx context.Context, origin string, call *revocationCall) {
	defer close(call.done)
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	state := &originRevocations{origin: origin}
	_, err := state.fresh(ctx, c)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, origin)
	if err != nil {
		c.failures[origin] = c.clock().Add(discoveryNegativeTTL)
		if len(c.failures) > c.maxOrigins {
			c.pruneFailures()
		}
		call.err = &WBAError{Status: http.StatusForbidden, Reason: "origin revocation status unavailable", Wrapped: err}
		return
	}
	delete(c.failures, origin)
	c.origins[origin] = state
}

// pruneFailures drops expired cooldowns, then the soonest-expiring, to keep
// the negative cache bounded. Called with mu held.
func (c *OriginRevocationChecker) pruneFailures() {
	now := c.clock()
	for o, until := range c.failures {
		if !now.Before(until) {
			delete(c.failures, o)
		}
	}
	for len(c.failures) > c.maxOrigins {
		var oldest string
		var at time.Time
		for o, until := range c.failures {
			if oldest == "" || until.Before(at) {
				oldest, at = o, until
			}
		}
		delete(c.failures, oldest)
	}
}

// fresh returns a list that is within next_update, or within the grace
// window after it, refreshing at most once per 60 s.
func (s *originRevocations) fresh(ctx context.Context, c *OriginRevocationChecker) (*RevocationList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := c.clock()
	if s.current == nil {
		if err := s.refresh(ctx, c, false, now); err != nil {
			return nil, err
		}
		return s.current, nil
	}
	if now.Before(s.current.NextUpdate) {
		return s.current, nil
	}
	lastErr := errors.New("refresh cooldown not elapsed")
	if now.Sub(s.lastAttempt) >= revocationMinInterval {
		if err := s.refresh(ctx, c, true, now); err != nil {
			lastErr = err
		} else if now.Before(s.current.NextUpdate) {
			return s.current, nil
		} else {
			lastErr = errors.New("refresh did not extend signed next_update")
		}
	}
	grace := time.Duration(float64(s.interval) * c.grace)
	if !now.Before(s.current.NextUpdate.Add(grace)) {
		return nil, fmt.Errorf("revocation list past next_update plus grace: %w", lastErr)
	}
	return s.current, nil
}

func (s *originRevocations) refresh(ctx context.Context, c *OriginRevocationChecker, conditional bool, now time.Time) error {
	s.lastAttempt = now
	inm, ims := "", ""
	if conditional {
		inm, ims = s.etag, s.lastModified
	}
	res, err := c.fetch(ctx, s.origin+RevocationListPath, inm, ims)
	if err != nil {
		return err
	}
	if res.Status == http.StatusNotModified && conditional {
		// A 304 authenticates no new payload, so it cannot extend the
		// signed next_update.
		return nil
	}
	if res.Status != http.StatusOK {
		return fmt.Errorf("revocation list returned HTTP %d", res.Status)
	}
	payload, err := verifyRevocationJWS(res.Body, func(kid string) (*JWK, error) {
		return c.keys.ResolveWBAKey(ctx, s.origin, kid)
	})
	if err != nil {
		return err
	}
	list, err := ParseRevocationList(payload, s.origin)
	if err != nil {
		return err
	}
	if list.Updated.After(now.Add(revocationClockSkew)) {
		return errors.New("revocation list updated is in the future")
	}
	if s.current != nil {
		if list.Updated.Before(s.current.Updated) {
			return errors.New("revocation list is older than the cached list; refusing to roll back")
		}
		if err := list.Retain(s.current); err != nil {
			return err
		}
	}
	s.current = list
	s.etag = res.ETag
	if len(res.LastModified) <= 64 && !strings.ContainsAny(res.LastModified, "\r\n") {
		s.lastModified = res.LastModified
	}
	s.interval = min(list.NextUpdate.Sub(list.Updated), revocationMaxInterval)
	return nil
}

// RevokedKids returns the sorted kids revoked for origin, for inspection.
func (c *OriginRevocationChecker) RevokedKids(origin string) []string {
	origin, err := webBotAuthOrigin(origin)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	state := c.origins[origin]
	c.mu.Unlock()
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.current == nil {
		return nil
	}
	out := make([]string, 0, len(state.current.RevokedKids))
	for k := range state.current.RevokedKids {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
