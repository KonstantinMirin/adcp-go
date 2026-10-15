package signing

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
// Verification establishes an identity, never authority. It needs only the
// signer's key directory and replay state (VerifyWebBotAuthRequest), so it
// can run in front of the server. Revocation, bindings, and grants are the
// authorization layer that runs after it. A verified origin the seller has
// not bound is identity-established: Middleware allows it only
// WebBotAuthOptions.UnboundFor, which a seller sets to its anonymous
// permissions plus get_principal. Nothing on the signature path reads a
// trust record or a revocation list.

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
	wbaNonceBytes       int   = 64 // web bot auth architecture draft §4.2.2
	wbaThumbprintLen    int   = 43 // SHA-256 as unpadded base64url
)

// validWBANonce reports whether nonce encodes exactly 64 bytes, canonically,
// as unpadded base64url or padded standard base64: the nonces the Web Bot
// Auth architecture draft (§4.2.2) describes and Cloudflare's web-bot-auth
// library accepts.
func validWBANonce(nonce string) bool {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding} {
		b, err := enc.DecodeString(nonce)
		if err == nil && len(b) == wbaNonceBytes && enc.EncodeToString(b) == nonce {
			return true
		}
	}
	return false
}

// WBAError is a Web Bot Auth failure. On the signature path it is the HTTP
// status the profile defines (DR-0023, WBA §5.3 and §5.4): 400 when the
// signature fields do not parse, 403 when a signature, a profile check, or
// key discovery fails (with Accept-Signature, except for a revoked key), and
// 429 for capacity. Any body is the generic authentication error.
//
// DiscoveryFailure marks a signature that could not be verified because the
// signer's key directory could not be resolved (WBA §6.10: a network or TLS
// error, a timeout, any status other than 200, or a response that is not a
// valid directory). The request is unverified, which says nothing about the
// signer; Middleware applies WebBotAuthOptions.OnDiscoveryFailure.
//
// Revoked marks a key the signer's origin has revoked: 403 without
// Accept-Signature, so the signer does not sign again with the same key.
//
// Authorization is set for an authorization-layer outcome once identity is
// established. It is answered with the standard AdCP error envelope, never
// 403 with Accept-Signature, which would tell a correctly signing agent to
// sign again. Code is its AdCP error code (PERMISSION_DENIED when empty, or
// SERVICE_UNAVAILABLE for a retryable outage).
//
// Reason is for server-side logs only and must never be sent to the caller.
type WBAError struct {
	Status           int
	Reason           string
	Label            string
	Authorization    bool
	Code             string
	DiscoveryFailure bool
	Revoked          bool
	Wrapped          error

	// labels are the request's web-bot-auth labels in order, used to build
	// Accept-Signature.
	labels []string
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

// ErrDiscoveryFailure is matched (errors.Is) by a *WBAError whose signature
// could not be verified because the signer's key directory could not be
// resolved and no unexpired cached copy holds the key (WBA §6.10).
var ErrDiscoveryFailure = errors.New("signing: signer key directory discovery failed")

// IsDiscoveryFailure reports whether err is a key discovery failure.
func IsDiscoveryFailure(err error) bool { return errors.Is(err, ErrDiscoveryFailure) }

func discoveryFailure(reason string, wrapped error) *WBAError {
	return &WBAError{Status: http.StatusForbidden, Reason: reason, Wrapped: wrapped, DiscoveryFailure: true}
}

// Is reports a discovery failure as ErrDiscoveryFailure.
func (e *WBAError) Is(target error) bool { return target == ErrDiscoveryFailure && e.DiscoveryFailure }

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
// operations a trust-record or revocation outage fails closed for in the
// authorization layer. It
// covers create_media_buy, update_media_buy, buy_products, accept_proposal,
// activate_signal, and every acquire_* operation.
func IsSpendCommittingOperation(op string) bool {
	if _, ok := spendCommittingOperations[op]; ok {
		return true
	}
	return strings.HasPrefix(op, "acquire_")
}

// ResponseHeader returns the headers to send with the failure: for a 403
// signature failure other than a revoked key, Accept-Signature (RFC 9421
// §5.1) naming the components and parameters the profile requires, with a
// fresh nonce the signer may use on its next attempt.
func (e *WBAError) ResponseHeader() http.Header {
	h := http.Header{}
	if e.Status != http.StatusForbidden || e.Authorization || e.Revoked {
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
	var b [wbaNonceBytes]byte
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
// directory does not hold the key. A resolver that cannot resolve the
// directory returns a *WBAError with Status 403 and DiscoveryFailure set,
// so the verifier reports ErrDiscoveryFailure. It is the resolver for many signers that
// a seller with many buyers uses instead of a hand-written keyid-to-agent
// map; DirectoryResolver is the production implementation.
type WBAKeyResolver interface {
	ResolveWBAKey(ctx context.Context, origin, keyID string) (*JWK, error)
}

// RevocationState is a verified key's status in its origin's revocation
// list, established in the authorization layer after verification.
type RevocationState int

const (
	// RevocationUnchecked: no revocation checker ran.
	RevocationUnchecked RevocationState = iota
	// RevocationCurrent: a list within its freshness (or grace) does not
	// revoke the key.
	RevocationCurrent
	// RevocationRevoked: the origin revoked the key. The request is
	// refused with 403, without Accept-Signature.
	RevocationRevoked
	// RevocationNoList: the origin serves no revocation list. The identity
	// stays identity-established: it cannot be bound, and a binding gives
	// it no principal.
	RevocationNoList
	// RevocationStale: the list could not be read, or is past its
	// next_update plus grace. The identity is not established for spend:
	// spend-committing calls fail closed with SERVICE_UNAVAILABLE in the
	// authorization layer. Other calls proceed.
	RevocationStale
	// RevocationUnavailable: the revocations retained for the origin
	// cannot be read (a revocation-store failure), so none of its calls
	// may act under a binding: the authorization layer answers
	// SERVICE_UNAVAILABLE.
	RevocationUnavailable
)

// String returns the state's name, for logs.
func (s RevocationState) String() string {
	switch s {
	case RevocationCurrent:
		return "current"
	case RevocationRevoked:
		return "revoked"
	case RevocationNoList:
		return "no_list"
	case RevocationStale:
		return "stale"
	case RevocationUnavailable:
		return "unavailable"
	default:
		return "unchecked"
	}
}

// WBARevocationChecker reports a key's state in origin's signed revocation
// list (/.well-known/governance-revocations.json). The error, when non-nil,
// explains a RevocationStale or RevocationNoList result for logs. It runs in
// the authorization layer, after verification. OriginRevocationChecker is
// the production implementation.
type WBARevocationChecker interface {
	CheckWBAKey(ctx context.Context, origin, keyID string) (RevocationState, error)
}

// CheckWBARevocation runs checker for every verified signer and records each
// result in VerifiedSigner.Revocation. A revoked key, the originator's or a
// relay's, returns a *WBAError with Revoked set (403, no Accept-Signature).
func CheckWBARevocation(ctx context.Context, checker WBARevocationChecker, signers []*VerifiedSigner) error {
	for _, s := range signers {
		state, err := checker.CheckWBAKey(ctx, s.AgentURL, s.KeyID)
		s.Revocation = state
		if state == RevocationRevoked {
			return &WBAError{Status: http.StatusForbidden, Label: s.Label, Reason: "signing key revoked", Revoked: true, Wrapped: err}
		}
	}
	return nil
}

// WBAVerifyOptions configures VerifyWebBotAuthRequest. Keys and Replay are
// required.
type WBAVerifyOptions struct {
	// Keys resolves (origin, thumbprint) to a directory key.
	Keys WBAKeyResolver

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
var errWBANotConfigured = errors.New("signing: Web Bot Auth verification requires Keys and Replay")

// VerifyWebBotAuthRequest verifies every web-bot-auth signature on r and
// returns the verified signers in Signature-Input order. The first is the
// originating signer, the AdCP caller; any later one is a relay that covers
// the signatures before it. Each VerifiedSigner's AgentURL is the signer's
// canonical origin and its KeyID is the key's thumbprint.
//
// A failure is a *WBAError carrying the status to answer. A signature whose
// key directory cannot be resolved matches ErrDiscoveryFailure: the request
// is unverified, and what to do with it is local policy (WBA §6.10). The
// function verifies identity only, from the key directory and replay state:
// it reads no revocation list and no trust record, and grants no authority.
// Run CheckWBARevocation, then bindings and grants, after it.
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
	if opts.Keys == nil || opts.Replay == nil {
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
	requestURL, ok := receivedTargetURI(r, scheme)
	if !ok {
		return nil, labels, wbaFail(http.StatusForbidden, wba[0].label, "absolute-form request-target does not match the connection's scheme and Host")
	}
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
		if !ok || !validWBANonce(nonce) {
			return nil, labels, wbaFail(http.StatusForbidden, label, "missing nonce, or not 64 bytes in canonical base64")
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

// receivedTargetURI returns the request's target URI as received (RFC 9421
// §2.2.2): the scheme, the Host field, and the request-target exactly as it
// arrived, so percent-encoding is preserved. An absolute-form
// request-target is used as is, and only when its scheme is the
// connection's and its authority is the Host field's (ok is false
// otherwise), so a signature captured over one scheme cannot be replayed
// over another.
func receivedTargetURI(r *http.Request, scheme string) (target string, ok bool) {
	raw := r.RequestURI
	switch {
	case strings.HasPrefix(raw, "/"):
		return scheme + "://" + r.Host + raw, true
	case raw != "" && raw != "*":
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			return "", false
		}
		if !strings.EqualFold(u.Scheme, scheme) || canonicalAuthority(u.Host, scheme) != canonicalAuthority(r.Host, scheme) {
			return "", false
		}
		return raw, true
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if r.URL.IsAbs() {
		scheme = r.URL.Scheme
	}
	return scheme + "://" + host + r.URL.RequestURI(), true
}

// sentTargetURI returns the target URI a client request will carry on the
// wire: Go writes the request-target as URL.RequestURI() and the Host field
// from Request.Host, else URL.Host.
func sentTargetURI(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return r.URL.Scheme + "://" + host + r.URL.RequestURI()
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

// wbaSignatureBase builds the RFC 9421 §2.5 signature base for member.
// rawURL is the target URI as sent or received, and @target-uri is that
// string unchanged; @authority is its normalized authority. A field
// component is the field's value, or with a key parameter
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
				// The target URI as received (RFC 9421 §2.2.2), not
				// canonicalized: a signer built on another HTTP stack signs
				// the URI it sent, percent-encoding included.
				value = rawURL
			case componentAuthority:
				// RFC 9421 §2.2.3: the authority normalized per HTTP
				// §4.2.3 (lowercase host, default port omitted).
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
// checks the key may verify: Ed25519, P-256, or RSA (2048 to 8192 bits,
// rsa-pss-sha512), use "sig" when present, no
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
	case jwk.Kty == "RSA" && jwk.Crv == "":
		if _, err := rsaPublicKey(jwk); err != nil {
			return "", wbaFail(http.StatusForbidden, "", "unsupported RSA directory key")
		}
		alg, jwsAlg = AlgRSAPSSSHA512, jwkAlgPS512
	default:
		return "", wbaFail(http.StatusForbidden, "", "unsupported directory key")
	}
	if (jwk.Use != "" && jwk.Use != "sig") || jwk.PrivateD != "" || jwk.TestOnlyPrivateD != "" {
		return "", wbaFail(http.StatusForbidden, "", "directory key is not a public signing key")
	}
	// One key, one thumbprint: key members must be canonical unpadded
	// base64url, so the same key cannot appear under several thumbprints.
	for _, m := range []string{jwk.X, jwk.Y, jwk.N, jwk.E} {
		if m != "" && !canonicalB64URL(m) {
			return "", wbaFail(http.StatusForbidden, "", "directory key member is not canonical base64url")
		}
	}
	if jwk.Alg != "" && jwk.Alg != jwsAlg {
		return "", wbaFail(http.StatusForbidden, "", "directory key algorithm mismatch")
	}
	if jwk.KeyOps != nil && !containsString(jwk.KeyOps, "verify") {
		return "", wbaFail(http.StatusForbidden, "", "directory key cannot verify")
	}
	return alg, nil
}

func canonicalB64URL(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && base64.RawURLEncoding.EncodeToString(b) == s
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
	if !verifyWithJWK(alg, jwk, []byte(base), signature.item.value.b) {
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
