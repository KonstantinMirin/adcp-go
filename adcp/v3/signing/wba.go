package signing

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/strictjson"
)

// EXPERIMENTAL: the Web Bot Auth (WBA) profile is experimental in AdCP 3.3
// (security.mdx, Web Bot Auth identities; specs/agent-identity-3-3.md). Its
// wire rules follow the IETF Web Bot Auth draft and the AdCP profile page
// (docs/building/by-layer/L1/wba-profile.mdx, adcontextprotocol/adcp#7894),
// which may still change. Everything here is opt-in: no existing signer or
// verifier path uses it unless configured to.
//
// Verification establishes an identity, never authority. A verified origin
// the seller has not bound is identity-established: Middleware allows it
// only WebBotAuthOptions.UnboundFor, which a seller sets to its anonymous
// permissions plus get_principal. Nothing on the signature path reads a
// trust record.

const (
	// ProfileTagWebBotAuth is the Signature-Input tag, and the
	// request_signing.profiles identifier, of the Web Bot Auth profile.
	ProfileTagWebBotAuth = "web-bot-auth"

	// ProfileTagRequestSigning is the request_signing.profiles identifier
	// of the AdCP RFC 9421 profile.
	ProfileTagRequestSigning = "adcp/request-signing/v1"

	// DirectoryTag is the tag on a key directory response signature (WBA
	// Appendix B.1).
	DirectoryTag = "http-message-signatures-directory"

	// DirectoryPath is the well-known path of an origin's key directory.
	DirectoryPath = "/.well-known/http-message-signatures-directory"

	// DirectoryMediaType is the key directory's media type.
	DirectoryMediaType = "application/http-message-signatures-directory+json"

	signatureAgentHeader  = "Signature-Agent"
	acceptSignatureHeader = "Accept-Signature"

	wbaMaxWindowSeconds int64 = 300
	wbaMinNonceLen      int   = 22 // 128 bits as unpadded base64url
	wbaMaxNonceLen      int   = 256
	wbaThumbprintLen    int   = 43 // SHA-256 as unpadded base64url
)

// WBAError is a Web Bot Auth verification failure, expressed as the HTTP
// status the profile defines: 400 when the signature fields do not parse,
// 403 when a signature or a profile check fails, 429 for capacity.
//
// Authorization is set once identity is established (the signature
// verified). Every such outcome is answered with the standard AdCP error
// envelope, never 403 with Accept-Signature, which would tell a correctly
// signing agent to sign again. Code is the AdCP error code
// (PERMISSION_DENIED when empty, or SERVICE_UNAVAILABLE for a retryable
// outage on a spend-committing call).
//
// Reason is for server-side logs only and must never be sent to the caller.
type WBAError struct {
	Status        int
	Reason        string
	Label         string
	Authorization bool
	Code          string
	Wrapped       error

	// labels are the request's web-bot-auth labels in order, used to build
	// Accept-Signature.
	labels []string

	// outage marks a signer-side outage (ErrIdentityUnavailable).
	outage bool
}

func (e *WBAError) Error() string {
	return fmt.Sprintf("web bot auth %d: %s", e.Status, e.Reason)
}

func (e *WBAError) Unwrap() error { return e.Wrapped }

// AsWBAError returns err as a *WBAError, or nil.
func AsWBAError(err error) *WBAError {
	var e *WBAError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func wbaFail(status int, label, reason string) *WBAError {
	return &WBAError{Status: status, Label: label, Reason: reason}
}

func wbaDeny(reason string) *WBAError {
	return &WBAError{Status: http.StatusForbidden, Reason: reason, Authorization: true, Code: CodePermissionDenied}
}

// ErrIdentityUnavailable is matched (errors.Is) by a *WBAError for a
// signer-side outage: the verifier could not confirm the signer's identity
// because its key directory could not be fetched (a network error, a 5xx,
// a timeout) or its revocation list could not be read or is stale past
// grace. Such a request is answered with SERVICE_UNAVAILABLE (503,
// retryable, Retry-After, AdCP envelope, no Accept-Signature), and nothing
// is served under the signature: no anonymous fallback.
var ErrIdentityUnavailable = errors.New("signing: signer identity cannot be confirmed (outage)")

// IsIdentityUnavailable reports whether err is a signer-side outage.
func IsIdentityUnavailable(err error) bool { return errors.Is(err, ErrIdentityUnavailable) }

func identityUnavailable(reason string, wrapped error) *WBAError {
	return &WBAError{Status: http.StatusServiceUnavailable, Code: CodeServiceUnavailable, Reason: reason, Wrapped: wrapped, outage: true}
}

// Is reports a signer-side outage as ErrIdentityUnavailable.
func (e *WBAError) Is(target error) bool { return target == ErrIdentityUnavailable && e.outage }

// AdCP error codes used for authorization outcomes after identity is
// established.
const (
	CodePermissionDenied   = "PERMISSION_DENIED"
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// NewAuthorizationError returns the error a WBAAuthorizer returns for an
// established identity: code is an AdCP error code. PERMISSION_DENIED is
// answered with HTTP 403 and SERVICE_UNAVAILABLE (retryable) with 503, both
// in the AdCP error envelope and without Accept-Signature. reason is for
// logs only.
func NewAuthorizationError(code, reason string, wrapped error) *WBAError {
	status := http.StatusForbidden
	if code == CodeServiceUnavailable {
		status = http.StatusServiceUnavailable
	}
	return &WBAError{Status: status, Reason: reason, Authorization: true, Code: code, Wrapped: wrapped}
}

// spendCommittingOperations commit spend (security.mdx's spend-committing
// row), plus the 3.2 buy and proposal-acceptance tools.
var spendCommittingOperations = map[string]struct{}{
	"create_media_buy": {}, "update_media_buy": {}, "buy_products": {}, "accept_proposal": {}, "activate_signal": {},
}

// IsSpendCommittingOperation reports whether op commits spend: the
// operations a trust-record or revocation outage fails closed for. It
// covers create_media_buy, update_media_buy, buy_products, accept_proposal,
// activate_signal, and every acquire_* operation.
func IsSpendCommittingOperation(op string) bool {
	if _, ok := spendCommittingOperations[op]; ok {
		return true
	}
	return strings.HasPrefix(op, "acquire_")
}

// ResponseHeader returns the headers to send with the failure: for a 403
// that is not an authorization failure, Accept-Signature (RFC 9421 §5.1)
// naming the components and parameters the profile requires, with a fresh
// nonce the signer may use on its next attempt.
func (e *WBAError) ResponseHeader() http.Header {
	h := http.Header{}
	if e.Status != http.StatusForbidden || e.Authorization {
		return h
	}
	labels := e.labels
	if len(labels) == 0 {
		label := e.Label
		if label == "" || !isValidLabel(label) {
			label = "sig1"
		}
		labels = []string{label}
	}
	h.Set(acceptSignatureHeader, acceptSignatureValue(labels, newWBANonce))
	return h
}

// acceptSignatureValue lists, per label, the components and parameters the
// profile requires (RFC 9421 §5.1). A later label must also cover each
// earlier label's signature-agent, signature-input, and signature members.
func acceptSignatureValue(labels []string, nonce func() string) string {
	keyed := func(field, label string) sfItem {
		return sfItem{value: sfStringItem(field), params: []sfParam{{key: "key", value: sfStringItem(label)}}}
	}
	var out sfDict
	for i, label := range labels {
		components := []sfItem{
			{value: sfStringItem(componentMethod)},
			{value: sfStringItem(componentTargetURI)},
			{value: sfStringItem(componentAuthority)},
			{value: sfStringItem(componentContentType)},
			{value: sfStringItem(componentContentDigst)},
			keyed("signature-agent", label),
		}
		for _, prev := range labels[:i] {
			components = append(components, keyed("signature-agent", prev), keyed("signature-input", prev), keyed("signature", prev))
		}
		out = append(out, sfDictEntry{key: label, member: sfMember{inner: true, list: components, params: []sfParam{
			{key: "created", value: sfTrue()},
			{key: "expires", value: sfTrue()},
			{key: "keyid", value: sfTrue()},
			{key: "nonce", value: sfStringItem(nonce())},
			{key: "tag", value: sfStringItem(ProfileTagWebBotAuth)},
		}}})
	}
	return out.serialize()
}

func newWBANonce() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return b64UrlEncodeRaw(b[:])
}

// UsesWebBotAuth reports whether a signed message selects the Web Bot Auth
// profile: it carries a Signature-Agent field, or a Signature-Input member
// tagged web-bot-auth. Such a message is verified under that profile only;
// a verifier that has enabled Web Bot Auth never falls back to the RFC 9421
// profile for it. A Signature-Input that does not parse still selects the
// profile when it mentions the tag, so a malformed marker cannot force a
// downgrade.
func UsesWebBotAuth(h http.Header) bool {
	if len(h.Values(signatureAgentHeader)) > 0 {
		return true
	}
	raw := strings.Join(h.Values(signatureInputHeader), ", ")
	if raw == "" {
		return false
	}
	d, err := parseSFDictionary(raw)
	if err != nil {
		return strings.Contains(raw, ProfileTagWebBotAuth)
	}
	for _, e := range d {
		if tag, ok := stringParam(e.member.params, "tag"); ok && tag == ProfileTagWebBotAuth {
			return true
		}
	}
	return false
}

// WBAKeyResolver resolves a Web Bot Auth key by the pair (origin, key ID),
// never by the key ID alone (WBA §5.4): the origin is the one the covered
// Signature-Agent member names. It returns (nil, nil) when the origin's
// directory does not hold the key. It is the resolver for many signers that
// a seller with many buyers uses instead of a hand-written keyid-to-agent
// map; DirectoryResolver is the production implementation.
type WBAKeyResolver interface {
	ResolveWBAKey(ctx context.Context, origin, keyID string) (*JWK, error)
}

// WBARevocationChecker reports whether origin has revoked keyID in its
// signed revocation list (/.well-known/governance-revocations.json). An
// error means the status is unknown; verification then fails closed.
// OriginRevocationChecker is the production implementation.
type WBARevocationChecker interface {
	RevokedWBAKey(ctx context.Context, origin, keyID string) (bool, error)
}

// WBAVerifyOptions configures VerifyWebBotAuthRequest. Keys, Revocation,
// and Replay are required.
type WBAVerifyOptions struct {
	// Keys resolves (origin, thumbprint) to a directory key.
	Keys WBAKeyResolver

	// Revocation checks each verified key against its origin's list.
	Revocation WBARevocationChecker

	// Replay records each signature's nonce per identity. The identity, not
	// the key, scopes the nonce, so key rotation does not reopen a replay.
	// A store that implements ReplayClaimer (MemoryReplayStore does) records
	// atomically, so concurrent copies of one request cannot both pass.
	Replay ReplayStore

	// Clock supplies the verifier's wall clock. Defaults to time.Now.
	Clock func() time.Time

	// Scheme is the request URL scheme when the request is not absolute.
	// Defaults to "https".
	Scheme string

	// MaxBodyBytes caps the body read for the digest check. 0 selects
	// 32 MiB.
	MaxBodyBytes int64

	// Authorities, when set, lists the authorities (host[:port]) this
	// verifier serves. A request whose @authority is not among them is
	// rejected, so a signature captured at one seller cannot be replayed to
	// another seller that accepts any Host. Recommended for any verifier
	// reachable under more than one name or behind a default backend.
	Authorities []string
}

// errWBANotConfigured reports a verifier missing a required dependency.
var errWBANotConfigured = errors.New("signing: Web Bot Auth verification requires Keys, Revocation, and Replay")

// VerifyWebBotAuthRequest verifies every web-bot-auth signature on r and
// returns the verified signers in Signature-Input order. The first is the
// originating signer, the AdCP caller; any later one is a relay that covers
// the signatures before it. Each VerifiedSigner's AgentURL is the signer's
// canonical origin and its KeyID is the key's thumbprint.
//
// A failure is a *WBAError carrying the status to answer. A signer-side
// outage (key directory or revocation list unavailable) matches
// ErrIdentityUnavailable and must be answered with SERVICE_UNAVAILABLE,
// serving nothing. The function verifies identity only: it reads no trust
// record and grants no authority.
//
// A non-empty signed body must be strict JSON (AdCP bodies are JSON-RPC
// or JSON): one value, no duplicate keys, including keys that differ only
// in case, so every reader sees the same members. Anything else is 400.
func VerifyWebBotAuthRequest(r *http.Request, opts WBAVerifyOptions) ([]*VerifiedSigner, error) {
	signers, labels, err := verifyWebBotAuthRequest(r, opts)
	if we := AsWBAError(err); we != nil && we.labels == nil {
		we.labels = labels
	}
	return signers, err
}

func verifyWebBotAuthRequest(r *http.Request, opts WBAVerifyOptions) ([]*VerifiedSigner, []string, error) {
	var labels []string
	if opts.Keys == nil || opts.Revocation == nil || opts.Replay == nil {
		return nil, nil, errWBANotConfigured
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock().Unix()
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}
	if err := wbaHeaderPrecheck(r.Header); err != nil {
		return nil, labels, err
	}
	inputs, err := parseSFDictionary(r.Header.Get(signatureInputHeader))
	if err != nil {
		return nil, labels, wbaFail(http.StatusBadRequest, "", "Signature-Input does not parse")
	}
	signatures, err := parseSFDictionary(r.Header.Get(signatureHeader))
	if err != nil {
		return nil, labels, wbaFail(http.StatusBadRequest, "", "Signature does not parse")
	}
	// A missing Signature-Agent (selection by tag alone) leaves every
	// member absent, which fails each signature with 403 below; a present
	// field that does not parse is 400.
	var agents sfDict
	if raw := r.Header.Get(signatureAgentHeader); raw != "" {
		if agents, err = parseSFDictionary(raw); err != nil {
			return nil, labels, wbaFail(http.StatusBadRequest, "", "Signature-Agent does not parse")
		}
	}
	type wbaInput struct {
		label  string
		member sfMember
	}
	var wba []wbaInput
	for _, e := range inputs {
		if !e.member.inner {
			continue
		}
		if tag, ok := stringParam(e.member.params, "tag"); ok && tag == ProfileTagWebBotAuth {
			wba = append(wba, wbaInput{e.key, e.member})
		}
	}
	for _, in := range wba {
		labels = append(labels, in.label)
	}
	if len(wba) == 0 {
		return nil, labels, wbaFail(http.StatusForbidden, "", "Signature-Agent requires the Web Bot Auth profile")
	}
	if !sameKeys(inputs.keys(), signatures.keys()) {
		return nil, labels, wbaFail(http.StatusBadRequest, "", "Signature and Signature-Input labels differ")
	}

	limit := opts.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	body, err := readAndReplaceBody(r, limit)
	if err != nil {
		return nil, labels, wbaFail(http.StatusForbidden, wba[0].label, "request body unreadable or too large")
	}
	requestURL := reconstructRequestURL(r, scheme)
	if len(opts.Authorities) > 0 {
		u, err := url.Parse(requestURL)
		if err != nil || !authorityAllowed(canonicalAuthority(u.Host, strings.ToLower(u.Scheme)), strings.ToLower(u.Scheme), opts.Authorities) {
			return nil, labels, wbaFail(http.StatusForbidden, wba[0].label, "request authority is not served by this verifier")
		}
	}

	type claim struct {
		signer *VerifiedSigner
		nonce  string
		ttl    time.Duration
	}
	var verified []claim
	var earlier []string
	for _, in := range wba {
		label, member := in.label, in.member
		if err := wbaWindow(member, now, false, label); err != nil {
			return nil, labels, err
		}
		nonce, ok := stringParam(member.params, "nonce")
		if !ok || len(nonce) < wbaMinNonceLen || len(nonce) > wbaMaxNonceLen {
			return nil, labels, wbaFail(http.StatusForbidden, label, "missing or invalid nonce")
		}
		agent, ok := agents.get(label)
		if !ok || agent.inner || agent.item.value.kind != sfString {
			return nil, labels, wbaFail(http.StatusForbidden, label, "missing supported Signature-Agent member")
		}
		if typ, present := sfParamValue(agent.item.params, "type"); present && (typ.kind != sfToken && typ.kind != sfString || typ.s != "directory") {
			return nil, labels, wbaFail(http.StatusForbidden, label, "unsupported Signature-Agent member type")
		}
		origin, err := webBotAuthOrigin(agent.item.value.s)
		if err != nil {
			return nil, labels, &WBAError{Status: http.StatusForbidden, Label: label, Reason: "invalid signer origin", Wrapped: err}
		}

		covered := make(map[string]struct{}, len(member.list))
		names := make([]string, 0, len(member.list))
		for _, c := range member.list {
			id := c.serialize()
			covered[id] = struct{}{}
			names = append(names, id)
		}
		required := []string{`"@method"`, `"@target-uri"`, `"@authority"`, `"signature-agent";key=` + sfStringItem(label).serialize()}
		if len(body) > 0 {
			required = append(required, `"content-type"`, `"content-digest"`)
		}
		for _, prev := range earlier {
			key := sfStringItem(prev).serialize()
			required = append(required, `"signature-agent";key=`+key, `"signature-input";key=`+key, `"signature";key=`+key)
			// RFC 9421 §2.2.8 (via WBA §5.2.2): a signer that covers an
			// earlier signature also covers every component it covered.
			prevMember, _ := inputs.get(prev)
			for _, c := range prevMember.list {
				required = append(required, c.serialize())
			}
		}
		if len(covered) != len(member.list) {
			return nil, labels, wbaFail(http.StatusForbidden, label, "repeated covered component")
		}
		for _, id := range required {
			if _, ok := covered[id]; !ok {
				return nil, labels, wbaFail(http.StatusForbidden, label, "missing covered component")
			}
		}

		keyID, _ := stringParam(member.params, "keyid")
		jwk, err := opts.Keys.ResolveWBAKey(r.Context(), origin, keyID)
		if err != nil {
			if we := AsWBAError(err); we != nil {
				if we.Label == "" {
					we.Label = label
				}
				return nil, labels, we
			}
			return nil, labels, &WBAError{Status: http.StatusForbidden, Label: label, Reason: "signer key resolution failed", Wrapped: err}
		}
		if jwk == nil {
			return nil, labels, wbaFail(http.StatusForbidden, label, "key absent from the named origin's directory")
		}
		if tp, err := JWKThumbprint(*jwk); err != nil || tp != keyID {
			return nil, labels, wbaFail(http.StatusForbidden, label, "directory key thumbprint does not match keyid")
		}
		base, err := wbaSignatureBase(r.Method, requestURL, r.Header, member, false)
		if err != nil {
			return nil, labels, withLabel(err, label)
		}
		sigMember, _ := signatures.get(label)
		alg, err := wbaVerifyCrypto(member, sigMember, *jwk, base)
		if err != nil {
			return nil, labels, withLabel(err, label)
		}
		if len(body) > 0 && !wbaDigestMatches(r.Header.Get(contentDigestHeader), body) {
			return nil, labels, wbaFail(http.StatusForbidden, label, "request digest mismatch")
		}
		// The signature verified. A revocation list that cannot be read, or
		// is stale past grace, leaves identity unconfirmed: a signer-side
		// outage. Serve nothing under the signature (SERVICE_UNAVAILABLE),
		// never 403 with Accept-Signature and never an anonymous fallback.
		revoked, err := opts.Revocation.RevokedWBAKey(r.Context(), origin, keyID)
		if err != nil {
			if we := AsWBAError(err); we != nil && (we.Authorization || we.Status == http.StatusTooManyRequests || we.Code == CodeServiceUnavailable) {
				return nil, labels, we
			}
			return nil, labels, identityUnavailable("origin revocation status unavailable", err)
		}
		if revoked {
			return nil, labels, wbaDeny("signing key revoked")
		}
		expires, _ := intParam(member.params, "expires")
		// One extra second keeps the entry alive through the last second
		// of the window.
		ttl := time.Duration(expires-now+skewSeconds+1) * time.Second
		if ttl < time.Second {
			ttl = time.Second
		}
		verified = append(verified, claim{
			signer: &VerifiedSigner{
				KeyID:             keyID,
				AgentURL:          origin,
				VerifiedAt:        time.Unix(now, 0).UTC(),
				Algorithm:         alg,
				Label:             label,
				CoveredComponents: names,
				Profile:           ProfileTagWebBotAuth,
			},
			nonce: nonce,
			ttl:   ttl,
		})
		earlier = append(earlier, label)
	}
	// Record nonces only once every signature verified, so a request that
	// fails on a later signature leaves no replay state behind. Check every
	// signer before recording any, so a replayed relay signature does not
	// consume the originator's nonce.
	for _, c := range verified {
		id := wbaReplayIdentity(c.signer.AgentURL)
		if opts.Replay.Seen(id, c.nonce) {
			return nil, labels, wbaFail(http.StatusForbidden, c.signer.Label, "replayed nonce")
		}
		if opts.Replay.HitCap(id) {
			return nil, labels, wbaFail(http.StatusTooManyRequests, c.signer.Label, "replay store capacity exceeded")
		}
	}
	// Claim relays before the originator, so a relay that loses a race does
	// not burn the originator's nonce.
	for i := len(verified) - 1; i >= 0; i-- {
		c := verified[i]
		id := wbaReplayIdentity(c.signer.AgentURL)
		if claimer, ok := opts.Replay.(ReplayClaimer); ok {
			switch claimer.Claim(id, c.nonce, c.ttl) {
			case ReplayReplayed:
				return nil, labels, wbaFail(http.StatusForbidden, c.signer.Label, "replayed nonce")
			case ReplayCapacity:
				return nil, labels, wbaFail(http.StatusTooManyRequests, c.signer.Label, "replay store capacity exceeded")
			}
			continue
		}
		if !opts.Replay.Insert(id, c.nonce, c.ttl) {
			return nil, labels, wbaFail(http.StatusTooManyRequests, c.signer.Label, "replay store capacity exceeded")
		}
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := strictjson.Validate(body, 0); err != nil {
			return nil, labels, wbaFail(http.StatusBadRequest, "", "malformed signed JSON body")
		}
	}
	out := make([]*VerifiedSigner, len(verified))
	for i, c := range verified {
		out[i] = c.signer
	}
	return out, labels, nil
}

func authorityAllowed(authority, scheme string, allowed []string) bool {
	for _, a := range allowed {
		if canonicalAuthority(a, scheme) == authority {
			return true
		}
	}
	return false
}

// wbaReplayIdentity scopes a nonce to an identity in a ReplayStore shared
// with RFC 9421 keyids; the prefix keeps the two namespaces apart.
func wbaReplayIdentity(origin string) string { return "web-bot-auth " + origin }

func withLabel(err error, label string) error {
	if we := AsWBAError(err); we != nil && we.Label == "" {
		we.Label = label
	}
	return err
}

func sameKeys(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, k := range a {
		set[k] = struct{}{}
	}
	for _, k := range b {
		if _, ok := set[k]; !ok {
			return false
		}
	}
	return true
}

// wbaHeaderPrecheck rejects ambiguous signature fields before parsing (400):
// a signed field on more than one header line, and a comma-joined
// Content-Type.
func wbaHeaderPrecheck(h http.Header) error {
	for _, name := range []string{signatureHeader, signatureInputHeader, signatureAgentHeader, contentTypeHeader, contentDigestHeader} {
		if len(h.Values(name)) > 1 {
			return wbaFail(http.StatusBadRequest, "", name+" arrived on more than one header line")
		}
	}
	if containsTopLevelComma(h.Get(contentTypeHeader)) {
		return wbaFail(http.StatusBadRequest, "", "Content-Type carries more than one value")
	}
	if h.Get(signatureInputHeader) == "" || h.Get(signatureHeader) == "" {
		return wbaFail(http.StatusBadRequest, "", "Signature and Signature-Input are required")
	}
	return nil
}

// wbaWindow checks the signature parameters' types and validity window.
// Request signatures allow 60 s of skew and at most 300 s of lifetime;
// directory response signatures allow no skew and any lifetime.
func wbaWindow(member sfMember, now int64, directory bool, label string) error {
	if _, ok := stringParam(member.params, "tag"); !ok {
		return wbaFail(http.StatusForbidden, label, "signature tag must be an sf-string")
	}
	created, ok1 := intParam(member.params, "created")
	expires, ok2 := intParam(member.params, "expires")
	if !ok1 || !ok2 {
		return wbaFail(http.StatusForbidden, label, "missing integer time parameter")
	}
	if expires <= created || (!directory && expires-created > wbaMaxWindowSeconds) {
		return wbaFail(http.StatusForbidden, label, "invalid signature lifetime")
	}
	skew := skewSeconds
	if directory {
		skew = 0
	}
	if created > now+skew || expires < now-skew {
		return wbaFail(http.StatusForbidden, label, "signature outside its validity window")
	}
	if keyID, ok := stringParam(member.params, "keyid"); !ok || len(keyID) != wbaThumbprintLen {
		return wbaFail(http.StatusForbidden, label, "missing thumbprint keyid")
	}
	return nil
}

// wbaSignatureBase builds the RFC 9421 §2.5 signature base for member. The
// derived components use the AdCP canonicalization shared with the RFC 9421
// profile. A field component is the field's value, or with a key parameter
// the re-serialized Dictionary member; @signature-params is the
// re-serialized Inner List. A directory response signature may cover
// "@authority";req, the authority of the request the response answers.
func wbaSignatureBase(method, rawURL string, h http.Header, member sfMember, directoryResponse bool) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", wbaFail(http.StatusForbidden, "", "request URL does not parse")
	}
	var b strings.Builder
	for _, c := range member.list {
		if c.value.kind != sfString {
			return "", wbaFail(http.StatusBadRequest, "", "component identifier must be an sf-string")
		}
		name := c.value.s
		var value string
		if strings.HasPrefix(name, "@") {
			reqParam := directoryResponse && name == componentAuthority && len(c.params) == 1 &&
				c.params[0].key == "req" && c.params[0].value.kind == sfBoolean && c.params[0].value.bo
			if len(c.params) != 0 && !reqParam {
				return "", wbaFail(http.StatusForbidden, "", "unsupported derived component parameters")
			}
			switch name {
			case componentMethod:
				value = strings.ToUpper(method)
			case componentTargetURI:
				value, err = canonicalTargetURI(rawURL)
				if err != nil {
					return "", wbaFail(http.StatusForbidden, "", "request URL cannot be canonicalized")
				}
			case componentAuthority:
				value = canonicalAuthority(u.Host, strings.ToLower(u.Scheme))
			default:
				return "", wbaFail(http.StatusForbidden, "", "unsupported derived component")
			}
		} else {
			lines := h.Values(name)
			if len(lines) == 0 || !isLowercaseFieldName(name) {
				return "", wbaFail(http.StatusForbidden, "", "missing covered field")
			}
			raw := strings.Join(lines, ", ")
			if strings.ContainsAny(raw, "\r\n\x00") {
				return "", wbaFail(http.StatusBadRequest, "", "covered field carries a control character")
			}
			switch {
			case len(c.params) == 0:
				value = strings.Trim(raw, " \t")
			case len(c.params) == 1 && c.params[0].key == "key" && c.params[0].value.kind == sfString:
				d, err := parseSFDictionary(raw)
				if err != nil {
					return "", wbaFail(http.StatusBadRequest, "", "covered dictionary field does not parse")
				}
				m, ok := d.get(c.params[0].value.s)
				if !ok {
					return "", wbaFail(http.StatusForbidden, "", "missing covered dictionary member")
				}
				value = m.serialize()
			default:
				return "", wbaFail(http.StatusForbidden, "", "unsupported field component parameters")
			}
		}
		b.WriteString(c.serialize())
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(member.serialize())
	return b.String(), nil
}

// wbaKeyAlgorithm derives the signature algorithm from a directory key and
// checks the key may verify: Ed25519 or P-256, use "sig" when present, no
// private member, a matching alg when present, and key_ops containing
// "verify" when present.
func wbaKeyAlgorithm(jwk JWK) (Algorithm, error) {
	var alg Algorithm
	var jwsAlg string
	switch {
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519":
		alg, jwsAlg = AlgEd25519, string(jwkAlgEdDSA)
	case jwk.Kty == "EC" && jwk.Crv == "P-256":
		alg, jwsAlg = AlgES256, string(jwkAlgES256)
	default:
		return "", wbaFail(http.StatusForbidden, "", "unsupported directory key")
	}
	if (jwk.Use != "" && jwk.Use != "sig") || jwk.PrivateD != "" || jwk.TestOnlyPrivateD != "" {
		return "", wbaFail(http.StatusForbidden, "", "directory key is not a public signing key")
	}
	if jwk.Alg != "" && jwk.Alg != jwsAlg {
		return "", wbaFail(http.StatusForbidden, "", "directory key algorithm mismatch")
	}
	if jwk.KeyOps != nil && !containsString(jwk.KeyOps, "verify") {
		return "", wbaFail(http.StatusForbidden, "", "directory key cannot verify")
	}
	return alg, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func wbaVerifyCrypto(member, signature sfMember, jwk JWK, base string) (Algorithm, error) {
	alg, err := wbaKeyAlgorithm(jwk)
	if err != nil {
		return "", err
	}
	if v, present := sfParamValue(member.params, "alg"); present && (v.kind != sfString || Algorithm(v.s) != alg) {
		return "", wbaFail(http.StatusForbidden, "", "signature algorithm does not match key")
	}
	if signature.inner || signature.item.value.kind != sfBinary {
		return "", wbaFail(http.StatusBadRequest, "", "signature must be sf-binary")
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return "", wbaFail(http.StatusForbidden, "", "invalid directory key")
	}
	if !verifySignature(alg, pub, []byte(base), signature.item.value.b) {
		return "", wbaFail(http.StatusForbidden, "", "signature did not verify")
	}
	return alg, nil
}

// wbaDigestMatches reports whether the Content-Digest sha-256 member equals
// the SHA-256 of body.
func wbaDigestMatches(header string, body []byte) bool {
	if header == "" {
		return false
	}
	d, err := parseSFDictionary(header)
	if err != nil {
		return false
	}
	m, ok := d.get("sha-256")
	if !ok || m.inner || m.item.value.kind != sfBinary {
		return false
	}
	sum := sha256.Sum256(body)
	return bytes.Equal(m.item.value.b, sum[:])
}
