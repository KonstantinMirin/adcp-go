package signing

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/strictjson"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// contextKey is the private context key type used to attach VerifiedSigner
// to a request context.
type contextKey struct{}

// VerifiedSignerFromContext returns the VerifiedSigner attached to ctx by the
// middleware. Returns nil if the request was not signed (or signing was not
// required and the request had no signature).
func VerifiedSignerFromContext(ctx context.Context) *VerifiedSigner {
	v, _ := ctx.Value(contextKey{}).(*VerifiedSigner)
	return v
}

// OperationResolver returns the AdCP protocol operation name for a given
// request. Typical implementations inspect the request path or the MCP/A2A
// tool/skill name derived from the transport envelope.
//
// Returning "" disables RequiredFor enforcement for that request (unsigned
// requests pass through). Middleware callers using the /adcp/<operation>
// convention can use DefaultOperationResolver.
type OperationResolver func(*http.Request) string

// DefaultOperationResolver derives the AdCP operation name from the last
// segment of the request path (e.g. /adcp/create_media_buy → create_media_buy).
// Returns "" if the path does not match /adcp/<op>.
func DefaultOperationResolver(r *http.Request) string {
	p := r.URL.Path
	const prefix = "/adcp/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	op := p[len(prefix):]
	if i := strings.IndexByte(op, '/'); i >= 0 {
		op = op[:i]
	}
	return op
}

// MiddlewareOptions configures the HTTP middleware.
type MiddlewareOptions struct {
	// Profile selects the signing profile accepted by this middleware. Zero
	// value is ProfileRequestSigning. Webhook receivers MUST set
	// ProfileWebhookSigning so a request-signing signature presented to a
	// webhook endpoint is rejected with webhook_signature_tag_invalid.
	Profile Profile

	// Resolver resolves keyid to a JWK and the signing agent's URL.
	// Typical implementations: StaticJWKSResolver for tests / specialized
	// deployments; HTTPJWKSResolver for production with brand.json-derived
	// agent mappings.
	Resolver JWKSResolver

	// Replay deduplicates (keyid, nonce) pairs. Defaults to a fresh
	// NewMemoryReplayStore(0) when nil — appropriate for single-instance
	// verifiers; distributed deployments SHOULD supply a shared backing
	// store (Redis, etc.) implementing ReplayStore with atomic cap+insert
	// semantics at step 13. Defaulting to nil silently disabled the replay
	// check, the exact security regression AdCP verifier checklist step 13
	// exists to prevent.
	Replay ReplayStore

	// Revocation reports per-keyid revocation state and whether the verifier's
	// cached list is stale. Passing nil skips revocation checks — acceptable
	// for dev/test, unsafe for production; the middleware logs a warning
	// at construction time when RequiredFor is non-empty and Revocation is nil.
	Revocation RevocationSource

	// OperationResolver returns the AdCP operation name for a request. Used
	// to check RequiredFor at the pre-check step. Supply DefaultOperationResolver
	// for the /adcp/<op> path convention.
	OperationResolver OperationResolver

	// RequiredFor lists operations whose unsigned requests must be rejected
	// with request_signature_required. Empty by default (AdCP 3.0 opt-in);
	// AdCP 4.0 normatively requires spend-committing operations to appear here.
	RequiredFor []string

	// ProtocolMethodsRequiredFor lists JSON-RPC protocol method names whose
	// unsigned requests must be rejected. It is distinct from RequiredFor,
	// which contains AdCP tool-operation names.
	ProtocolMethodsRequiredFor []string

	// ContentDigestPolicy controls whether signers MUST, MUST NOT, or MAY
	// cover content-digest. Defaults to DigestEither.
	ContentDigestPolicy DigestPolicy

	// MaxBodyBytes caps the body buffered for content-digest recompute
	// (step 11). 0 selects a 32 MiB default. Set lower if your upstream
	// already enforces a tighter body-size limit.
	MaxBodyBytes int64

	// OnReject, if non-nil, is called instead of the default 401 response on
	// verification failure. Useful for MCP / JSON-RPC servers that need to
	// shape the error as a protocol-specific envelope. The handler MUST write
	// both a status code and a body.
	//
	// The default behavior is 401 Unauthorized with WWW-Authenticate set to
	// `Signature error="<code>"` and a text/plain "unauthorized" body.
	OnReject func(w http.ResponseWriter, r *http.Request, e *Error)

	// Logger is used to log verification failures server-side. If nil,
	// slog.Default() is used. The middleware logs the error code, detail,
	// operation name, and (when known) keyid — enough to trace "which
	// counterparty is sending broken signatures."
	Logger *slog.Logger

	// SchemeOverride forces a specific URL scheme (https/http) for signature
	// base reconstruction. Most deployments should leave this empty; the
	// middleware derives "https" for TLS requests and "http" otherwise.
	// Set this when your reverse proxy terminates TLS and the verifier sees
	// plain HTTP.
	SchemeOverride string

	// ObserveOnly puts this middleware instance in shadow mode. Verification
	// still runs, but a request that fails it — including an unsigned
	// request to an operation in RequiredFor — is NOT rejected: next is
	// invoked with no VerifiedSigner in the context, exactly as if the
	// request had arrived unsigned. The failure is logged at INFO level
	// (instead of the usual WARN + 401) via Logger, so operators can watch
	// the failure rate before promoting the operation to full enforcement.
	//
	// This maps to the spec's `warn_for` rollout stop — the shadow-mode
	// bridge between `supported_for` (verified when present, never required)
	// and `required_for` (verified and mandatory). Wire a dedicated
	// Middleware instance with ObserveOnly=true for the operations you've
	// moved to `warn_for`; RequiredFor should normally be empty on that
	// instance, since `warn_for` and `required_for` are disjoint per spec —
	// see https://adcontextprotocol.org/docs/building/implementation/security#transport-capability-advertisement.
	//
	// One case still hard-rejects even under ObserveOnly: a partial or
	// malformed Signature/Signature-Input header pair (one header present
	// without the other, or either header present but unparseable) —
	// surfaced as *Error{Code: CodeHeaderMalformed}. The spec requires this
	// because a broken pair "cannot be safely interpreted as either signed
	// or unsigned traffic"; a well-formed signature that merely fails
	// verification (bad crypto, unknown key, expired window, replay, ...) is
	// the case ObserveOnly is for and passes through.
	ObserveOnly bool

	// WebBotAuth, when non-nil, enables the experimental AdCP 3.3 Web Bot
	// Auth profile on this middleware alongside the RFC 9421 profile. A
	// request carrying Signature-Agent or a web-bot-auth tag is then
	// verified under Web Bot Auth only and never falls back to the RFC 9421
	// profile, including under ObserveOnly. Failures are answered with the
	// profile's statuses (400, 403 with Accept-Signature, 429), not
	// request_signature_* codes. A non-empty Web Bot Auth signed body must be
	// strict JSON (no duplicate or case-folded duplicate keys) or it is
	// rejected with 400. With WebBotAuth set, the verified signer also
	// reaches MCP tool handlers per request (VerifiedSignerFromToolRequest).
	// When nil, the middleware behaves exactly as before, and logs at INFO
	// that the RFC 9421 profile is deprecated in 3.3.
	WebBotAuth *WebBotAuthOptions

	// BoundOrigins enforces "no downgrade": once an origin is bound to a
	// principal under Web Bot Auth, an RFC 9421 signature from any agent URL
	// at that origin is refused with PERMISSION_DENIED. Nil disables the
	// check.
	BoundOrigins OriginBindingLookup
}

// WebBotAuthOptions configures the Web Bot Auth profile on Middleware.
// EXPERIMENTAL (AdCP 3.3).
type WebBotAuthOptions struct {
	// Keys resolves (origin, thumbprint). Required; NewDirectoryResolver is
	// the production resolver.
	Keys WBAKeyResolver

	// Revocation checks each key against its origin's list. Required;
	// NewOriginRevocationChecker is the production checker. A revocation
	// status that cannot be established fails closed.
	Revocation WBARevocationChecker

	// Authorizer decides authority for a verified origin and returns its
	// bound principal ID, or "" for an identity-established signer. It runs
	// after verification and is where a binding is re-evaluated against the
	// operator's trust record; the signature path itself never reads one.
	// Nil treats every verified origin as unbound.
	Authorizer WBAAuthorizer

	// UnboundFor lists the operations (AdCP tool names or JSON-RPC methods)
	// an identity-established signer may call. The spec gives it what an
	// anonymous caller gets, reads included, plus get_principal: set this to
	// your anonymous permissions plus get_principal. Defaults to
	// get_adcp_capabilities, get_principal, and the MCP session methods
	// initialize, notifications/initialized, ping, and tools/list. Add
	// sync_principal only when its handler implements an explicit open
	// onboarding policy.
	UnboundFor []string

	// OnReject, if non-nil, writes the response for a Web Bot Auth failure.
	// It must write a status and a body, and must not echo e.Reason.
	OnReject func(w http.ResponseWriter, r *http.Request, e *WBAError)

	// Clock supplies the verifier's wall clock. Defaults to time.Now.
	Clock func() time.Time

	// Authorities lists the host[:port] values this endpoint serves; see
	// WBAVerifyOptions.Authorities. Recommended.
	Authorities []string
}

// WBAAuthorizer is the binding hook for verified Web Bot Auth origins. It
// returns the principal bound to signer.AgentURL, re-evaluating the binding
// as its freshness rules require, or "" when the origin is not bound. A
// non-nil error denies the request with PERMISSION_DENIED.
type WBAAuthorizer interface {
	AuthorizeWBA(ctx context.Context, signer *VerifiedSigner, operation string) (principalID string, err error)
}

// OriginBindingLookup reports the principal bound to a canonical origin.
type OriginBindingLookup interface {
	PrincipalForOrigin(ctx context.Context, origin string) (principalID string, bound bool, err error)
}

// verifiedSignersKey attaches every verified Web Bot Auth signer.
type verifiedSignersKey struct{}

// VerifiedSignersFromContext returns every signer the middleware verified
// on the request: under Web Bot Auth, the originating signer first and then
// each relay. The first entry is also returned by
// VerifiedSignerFromContext. Relays never acquire the originator's
// authority.
func VerifiedSignersFromContext(ctx context.Context) []*VerifiedSigner {
	if v, ok := ctx.Value(verifiedSignersKey{}).([]*VerifiedSigner); ok {
		return v
	}
	if s := VerifiedSignerFromContext(ctx); s != nil {
		return []*VerifiedSigner{s}
	}
	return nil
}

// rfc9421Deprecation is logged by each Middleware built without WebBotAuth.
const rfc9421Deprecation = "signing.Middleware: the AdCP RFC 9421 request-signing profile is deprecated in AdCP 3.3; " +
	"it remains supported through 3.x and is removed in 4.0. Set MiddlewareOptions.WebBotAuth to also accept the Web Bot Auth profile."

// defaultUnboundFor is what an identity-established signer may call by
// default: capability discovery, get_principal, and the MCP session
// methods needed to reach them.
var defaultUnboundFor = []string{"get_adcp_capabilities", "get_principal", "initialize", "notifications/initialized", "ping", "tools/list"}

// Middleware returns an http.Handler middleware that verifies incoming AdCP
// request signatures per the profile.
//
// On success, the VerifiedSigner is attached to the request context and next
// is invoked.
//
// On failure, the middleware writes 401 Unauthorized with the
// `WWW-Authenticate: Signature error="<code>"` header (no realm, per spec) and
// a text/plain "unauthorized" body. Callers that need a protocol-specific
// error body (e.g. JSON-RPC-shaped MCP error) should wrap this middleware and
// translate the 401 into the outer protocol's error format.
//
// For requests that are not signed AND not in RequiredFor, the middleware
// invokes next with no signer context — callers that want to enforce signing
// universally should populate RequiredFor.
func Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	profile := opts.Profile
	if profile.Tag == "" {
		profile = ProfileRequestSigning
	}
	// Construct the default replay store once at wire-up so every request
	// served by this middleware shares the same dedup state — lazy
	// per-request construction would defeat replay detection entirely.
	// Pass an explicit shared store (Redis, etc.) for multi-replica
	// deployments where replay state must be coordinated across processes.
	replay := opts.Replay
	if replay == nil {
		replay = NewMemoryReplayStore(0)
	}
	if (len(opts.RequiredFor) > 0 || len(opts.ProtocolMethodsRequiredFor) > 0) && opts.Revocation == nil {
		logger.Warn("signing.Middleware: RequiredFor is non-empty but Revocation is nil — verifier will not enforce key revocation")
	}
	wba := opts.WebBotAuth
	if wba == nil {
		logger.Info(rfc9421Deprecation)
	}
	unboundList := defaultUnboundFor
	if wba != nil && wba.UnboundFor != nil {
		unboundList = wba.UnboundFor
	}
	unboundFor := map[string]struct{}{}
	for _, op := range unboundList {
		unboundFor[op] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			opName := ""
			if opts.OperationResolver != nil {
				opName = opts.OperationResolver(r)
			}
			scheme := opts.SchemeOverride
			if scheme == "" {
				if r.TLS != nil {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}
			if wba != nil && UsesWebBotAuth(r.Header) {
				serveWebBotAuth(w, r, next, wba, unboundFor, replay, scheme, opName, opts.MaxBodyBytes, logger)
				return
			}
			signer, err := VerifyRequestSignature(r, VerifyOptions{
				OperationName:              opName,
				RequiredFor:                opts.RequiredFor,
				ProtocolMethodsRequiredFor: opts.ProtocolMethodsRequiredFor,
				Profile:                    profile,
				ContentDigestPolicy:        opts.ContentDigestPolicy,
				Scheme:                     scheme,
				Resolver:                   opts.Resolver,
				Revocation:                 opts.Revocation,
				Replay:                     replay,
				MaxBodyBytes:               opts.MaxBodyBytes,
			})
			if err != nil {
				e := AsError(err)
				if e == nil {
					e = wrapError(CodeInvalid, "untyped verifier error", err)
				}
				// Best-effort keyid extraction for logs — helps operators
				// trace "which buyer is sending broken signatures."
				keyid := ""
				if parsed, perr := parseSignatureInput(r.Header.Get(signatureInputHeader)); perr == nil {
					keyid = parsed.keyID
				}
				// ObserveOnly never overrides a malformed header pair — that
				// case cannot be safely treated as unsigned traffic (see the
				// ObserveOnly doc comment).
				observing := opts.ObserveOnly && e.Code != CodeHeaderMalformed
				level := slog.LevelWarn
				msg := "signature rejected"
				if observing {
					level = slog.LevelInfo
					msg = "signature verification failed (ObserveOnly: request allowed through unverified)"
				}
				logger.Log(r.Context(), level, msg,
					"code", e.WireCode(profile),
					"detail", e.Detail,
					"op", opName,
					"keyid", keyid,
					"profile", profile.Tag,
					"observe_only", observing,
				)
				if observing {
					// No VerifiedSigner is attached — downstream sees this
					// exactly as an unsigned request.
					next.ServeHTTP(w, r)
					return
				}
				if opts.OnReject != nil {
					opts.OnReject(w, r, e)
					return
				}
				w.Header().Set("WWW-Authenticate", `Signature error="`+e.WireCode(profile)+`"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if signer != nil && opts.BoundOrigins != nil {
				// No downgrade: a bound origin is refused the RFC 9421 profile.
				if origin, err := CanonicalOrigin(signer.AgentURL); err == nil {
					_, bound, lerr := opts.BoundOrigins.PrincipalForOrigin(r.Context(), origin)
					if lerr != nil || bound {
						logger.Warn("signature rejected", "code", "PERMISSION_DENIED", "detail", "bound origin requires Web Bot Auth", "op", opName, "profile", profile.Tag)
						writeWBAReject(w, r, wbaDeny("bound origin requires Web Bot Auth"), nil)
						return
					}
				}
			}
			if signer != nil {
				ctx := context.WithValue(r.Context(), contextKey{}, signer)
				r = r.WithContext(ctx)
				if wba != nil {
					serveWithToolRequestSigner(w, r, next, signer)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// serveWebBotAuth verifies a request selected for the Web Bot Auth profile,
// applies the binding gate, and dispatches or rejects it.
func serveWebBotAuth(w http.ResponseWriter, r *http.Request, next http.Handler, wba *WebBotAuthOptions,
	unboundFor map[string]struct{}, replay ReplayStore, scheme, opName string, maxBody int64, logger *slog.Logger) {
	signers, err := VerifyWebBotAuthRequest(r, WBAVerifyOptions{
		Keys:         wba.Keys,
		Revocation:   wba.Revocation,
		Replay:       replay,
		Scheme:       scheme,
		MaxBodyBytes: maxBody,
		Clock:        wba.Clock,
		Authorities:  wba.Authorities,
	})
	if err == nil {
		// The originating signer is the AdCP caller; relays are verified
		// independently and acquire none of its authority.
		caller := signers[0]
		op := opName
		if op == "" {
			op = jsonRPCOperation(r)
		}
		principal := ""
		if wba.Authorizer != nil {
			principal, err = wba.Authorizer.AuthorizeWBA(r.Context(), caller, op)
			if err != nil && AsWBAError(err) == nil {
				err = &WBAError{Status: http.StatusForbidden, Authorization: true, Reason: "signer origin is not authorized", Wrapped: err}
			}
		}
		if err == nil && principal == "" {
			if _, ok := unboundFor[op]; !ok {
				err = wbaDeny("signer identity is not bound")
			}
		}
		if err == nil {
			caller.PrincipalID = principal
			ctx := context.WithValue(r.Context(), contextKey{}, caller)
			ctx = context.WithValue(ctx, verifiedSignersKey{}, signers)
			serveWithToolRequestSigner(w, r.WithContext(ctx), next, caller)
			return
		}
	}
	e := AsWBAError(err)
	if e == nil {
		logger.Error("web bot auth verification error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Warn("signature rejected",
		"status", e.Status,
		"detail", e.Reason,
		"op", opName,
		"label", e.Label,
		"authorization", e.Authorization,
		"profile", ProfileTagWebBotAuth,
	)
	writeWBAReject(w, r, e, wba.OnReject)
}

// writeWBAReject writes the profile's failure response. An authorization
// failure is a generic AdCP PERMISSION_DENIED with no Accept-Signature; any
// other failure is its status with Accept-Signature on a 403. Neither body
// carries signature-specific detail.
func writeWBAReject(w http.ResponseWriter, r *http.Request, e *WBAError, onReject func(http.ResponseWriter, *http.Request, *WBAError)) {
	if onReject != nil {
		onReject(w, r, e)
		return
	}
	for k, vs := range e.ResponseHeader() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if e.Authorization {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":"PERMISSION_DENIED","message":"permission denied"}]}`))
		return
	}
	http.Error(w, http.StatusText(e.Status), e.Status)
}

// jsonRPCOperation names the operation of a JSON-RPC request body: the
// tool name of an MCP tools/call, or otherwise the JSON-RPC method (for
// example initialize or tools/list). It reads members by exact,
// case-sensitive name, as the MCP SDK does, and returns "" (no operation,
// so nothing is allowed for an unbound signer) for a body it cannot read
// unambiguously, including one whose keys collide under case folding.
// A2A deployments resolve skills with MiddlewareOptions.OperationResolver.
// The body has already been buffered, and strict-validated, by verification.
func jsonRPCOperation(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := readAndReplaceBody(r, defaultMaxBodyBytes)
	if err != nil || strictjson.Validate(body, 0) != nil {
		return ""
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	var version, method string
	if json.Unmarshal(envelope["jsonrpc"], &version) != nil || version != "2.0" ||
		json.Unmarshal(envelope["method"], &method) != nil || method == "" {
		return ""
	}
	if method != "tools/call" {
		return method
	}
	var params map[string]json.RawMessage
	var name string
	if json.Unmarshal(envelope["params"], &params) != nil || json.Unmarshal(params["name"], &name) != nil {
		return ""
	}
	return name
}

// TokenInfoSignerKey is the auth.TokenInfo.Extra key under which Middleware
// carries the verified signer to MCP tool handlers when WebBotAuth is set.
// Read it with VerifiedSignerFromToolRequest.
const TokenInfoSignerKey = "adcp.verified_signer" // #nosec G101 -- a map key, not a credential.

// VerifiedSignerFromToolRequest returns the signer Middleware verified for
// the HTTP request that carried this MCP tool call, or nil.
//
// Use it, not VerifiedSignerFromContext, inside MCP tool handlers: a
// stateful go-sdk session binds handlers to the context of its initialize
// request, so a context value can belong to a different, earlier request.
// The MCP SDK copies auth.TokenInfo from each HTTP request into
// req.Extra.TokenInfo, and Middleware places the signer there when
// MiddlewareOptions.WebBotAuth is set. Install Middleware inside (after)
// any bearer-token middleware, which replaces TokenInfo; if the signer is
// lost that way, this returns nil and callers fail closed.
func VerifiedSignerFromToolRequest(req *mcp.CallToolRequest) *VerifiedSigner {
	if req == nil || req.Extra == nil {
		return nil
	}
	return VerifiedSignerFromTokenInfo(req.Extra.TokenInfo)
}

// VerifiedSignerFromTokenInfo returns the signer stored under
// TokenInfoSignerKey, or nil.
func VerifiedSignerFromTokenInfo(ti *auth.TokenInfo) *VerifiedSigner {
	if ti == nil {
		return nil
	}
	s, _ := ti.Extra[TokenInfoSignerKey].(*VerifiedSigner)
	return s
}

// serveWithToolRequestSigner calls next with signer added to the request's
// auth.TokenInfo, which the MCP SDK forwards per HTTP request into
// CallToolRequest.Extra. go-sdk sets TokenInfo only through
// auth.RequireBearerToken, so this runs it with a verifier that returns the
// existing TokenInfo (if any) plus the signer, presenting a placeholder
// bearer value only for that step and restoring the original Authorization
// header before next runs. The UserID and scopes of an existing TokenInfo
// are preserved; none are invented.
func serveWithToolRequestSigner(w http.ResponseWriter, r *http.Request, next http.Handler, signer *VerifiedSigner) {
	ti := &auth.TokenInfo{}
	if existing := auth.TokenInfoFromContext(r.Context()); existing != nil {
		c := *existing
		ti = &c
		ti.Extra = maps.Clone(existing.Extra)
	}
	if ti.Expiration.IsZero() {
		ti.Expiration = time.Now().Add(time.Duration(wbaMaxWindowSeconds+skewSeconds) * time.Second)
	}
	if ti.Extra == nil {
		ti.Extra = map[string]any{}
	}
	ti.Extra[TokenInfoSignerKey] = signer
	original, hadAuthorization := r.Header["Authorization"]
	inner := http.HandlerFunc(func(w http.ResponseWriter, r2 *http.Request) {
		r2.Header = r2.Header.Clone()
		if hadAuthorization {
			r2.Header["Authorization"] = original
		} else {
			r2.Header.Del("Authorization")
		}
		next.ServeHTTP(w, r2)
	})
	staged := r.Clone(r.Context())
	staged.Body = r.Body
	staged.Header.Set("Authorization", "Bearer adcp-verified-signer")
	auth.RequireBearerToken(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return ti, nil
	}, nil)(inner).ServeHTTP(w, staged)
}
