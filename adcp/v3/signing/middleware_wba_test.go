package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/stretchr/testify/require"
)

// fakeAuthorizer binds origins to principals and can deny.
type fakeAuthorizer struct {
	principals map[string]string
	deny       map[string]bool
	calls      []string
}

func (f *fakeAuthorizer) AuthorizeWBA(_ context.Context, s *VerifiedSigner, op string) (string, error) {
	f.calls = append(f.calls, op)
	if f.deny[s.AgentURL] {
		return "", errors.New("operator delisted the origin")
	}
	return f.principals[s.AgentURL], nil
}

type fakeBoundOrigins map[string]string

func (f fakeBoundOrigins) PrincipalForOrigin(_ context.Context, origin string) (string, bool, error) {
	p, ok := f[origin]
	return p, ok, nil
}

type captured struct {
	signer  *VerifiedSigner
	signers []*VerifiedSigner
	body    string
	called  bool
}

func captureHandler(c *captured) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.called = true
		c.signer = VerifiedSignerFromContext(r.Context())
		c.signers = VerifiedSignersFromContext(r.Context())
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		c.body = buf.String()
		w.WriteHeader(http.StatusOK)
	})
}

func mcpCall(tool string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
}

func TestMiddlewareWebBotAuthBindingGate(t *testing.T) {
	const (
		withIdentity = "identity"  // handler runs with the verified signer
		anonymous    = "anonymous" // handler runs as an anonymous request
		refused      = "refused"   // AdCP error envelope, handler not run
	)
	bound := map[string]string{"https://buyer.example.com": "principal_7"}
	cases := []struct {
		name        string
		body        string
		authorizer  WBAAuthorizer
		unboundFor  []string
		requiredFor []string
		want        string
		principal   string
		code        string
	}{
		{"identity-established may call get_principal", mcpCall("get_principal"), &fakeAuthorizer{}, nil, nil, withIdentity, "", ""},
		{"identity-established may call get_adcp_capabilities", mcpCall("get_adcp_capabilities"), nil, nil, nil, withIdentity, "", ""},
		{"beyond UnboundFor: served as an anonymous caller", mcpCall("create_media_buy"), &fakeAuthorizer{}, nil, nil, anonymous, "", ""},
		{"sync_accounts from an unbound origin: anonymous", mcpCall("sync_accounts"), nil, nil, nil, anonymous, "", ""},
		{"beyond UnboundFor on a signature-required operation: PERMISSION_DENIED", mcpCall("create_media_buy"), nil, nil, []string{"create_media_buy"}, refused, "", CodePermissionDenied},
		{"configured anonymous reads", mcpCall("get_products"), &fakeAuthorizer{}, []string{"get_products"}, nil, withIdentity, "", ""},
		{"bound origin gets its principal", mcpCall("create_media_buy"), &fakeAuthorizer{principals: bound}, nil, nil, withIdentity, "principal_7", ""},
		{"authorizer error: PERMISSION_DENIED envelope", mcpCall("create_media_buy"), &fakeAuthorizer{principals: bound, deny: map[string]bool{"https://buyer.example.com": true}}, nil, nil, refused, "", CodePermissionDenied},
		{"authorizer outage on spend: SERVICE_UNAVAILABLE", mcpCall("create_media_buy"), outageAuthorizer{}, nil, nil, refused, "", CodeServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newWBARig(t)
			opts := &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, UnboundFor: tc.unboundFor, Clock: wbaClock}
			if tc.authorizer != nil {
				opts.Authorizer = tc.authorizer
			}
			var c captured
			h := Middleware(MiddlewareOptions{WebBotAuth: opts, Replay: rig.replay, RequiredFor: tc.requiredFor,
				OperationResolver: func(*http.Request) string { return "" }, Logger: discardLogger()})(captureHandler(&c))
			r := rig.signedRequest(t, tc.body)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			// A correctly signed request never gets Accept-Signature.
			require.Empty(t, rec.Header().Get("Accept-Signature"))
			switch tc.want {
			case withIdentity:
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.True(t, c.called)
				require.Equal(t, "https://buyer.example.com", c.signer.AgentURL)
				require.Equal(t, tc.principal, c.signer.PrincipalID)
				require.Equal(t, tc.body, c.body, "the handler still reads the body")
			case anonymous:
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.True(t, c.called)
				require.Nil(t, c.signer, "no identity is attached beyond the unbound surface")
				require.Equal(t, tc.body, c.body)
			case refused:
				require.False(t, c.called)
				requireAdCPEnvelope(t, rec, tc.code)
				require.NotContains(t, rec.Body.String(), "delisted", "no detail leaks")
			}
		})
	}
}

type outageAuthorizer struct{}

func (outageAuthorizer) AuthorizeWBA(context.Context, *VerifiedSigner, string) (string, error) {
	return "", NewAuthorizationError(CodeServiceUnavailable, "trust record unreachable", nil)
}

// requireAdCPEnvelope asserts the standard AdCP error envelope with code,
// the matching HTTP status, and no Accept-Signature.
func requireAdCPEnvelope(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	require.Empty(t, rec.Header().Get("Accept-Signature"))
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body struct {
		Errors []struct{ Code, Message, Recovery string } `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	require.Len(t, body.Errors, 1)
	require.Equal(t, code, body.Errors[0].Code)
	switch code {
	case CodeServiceUnavailable:
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Equal(t, "transient", body.Errors[0].Recovery)
		require.NotEmpty(t, rec.Header().Get("Retry-After"))
	default:
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Equal(t, "correctable", body.Errors[0].Recovery)
	}
}

// TestMiddlewareSignerSideOutage: when identity cannot be confirmed (the
// revocation list cannot be read, or the key directory cannot be fetched),
// every signed request gets SERVICE_UNAVAILABLE and nothing is served
// under the signature: no anonymous fallback, no Accept-Signature. A
// revoked key is PERMISSION_DENIED; an absent directory is a signature
// failure.
func TestMiddlewareSignerSideOutage(t *testing.T) {
	serve := func(t *testing.T, rig *wbaRig, body string) (*httptest.ResponseRecorder, *captured) {
		var c captured
		auth := &fakeAuthorizer{principals: map[string]string{rig.origin: "p"}}
		h := Middleware(MiddlewareOptions{WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, Authorizer: auth, Clock: wbaClock},
			Replay: rig.replay, Logger: discardLogger()})(captureHandler(&c))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rig.signedRequest(t, body))
		return rec, &c
	}
	for _, op := range []string{"create_media_buy", "get_media_buys", "get_adcp_capabilities"} {
		rig := newWBARig(t)
		rig.revs.fetchErr = errors.New("connection refused")
		rec, c := serve(t, rig, mcpCall(op))
		requireAdCPEnvelope(t, rec, CodeServiceUnavailable)
		require.False(t, c.called, "nothing is served under an unconfirmed signature: %s", op)
	}

	rig := newWBARig(t)
	rig.dirs.fail(rig.origin, errors.New("i/o timeout"))
	rec, c := serve(t, rig, mcpCall("get_adcp_capabilities"))
	requireAdCPEnvelope(t, rec, CodeServiceUnavailable)
	require.False(t, c.called)

	rig = newWBARig(t)
	rig.dirs.mu.Lock()
	delete(rig.dirs.dirs, rig.origin) // the fake serves 404
	rig.dirs.mu.Unlock()
	rec, c = serve(t, rig, mcpCall("get_adcp_capabilities"))
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.NotEmpty(t, rec.Header().Get("Accept-Signature"), "an absent directory is a signature failure")
	require.False(t, c.called)

	rig = newWBARig(t)
	jwk, _ := PublicDirectoryKey(rig.key)
	rig.revs.set(t, revocationPayload{Updated: rfc3339(wbaTestNow.Add(-time.Minute)), NextUpdate: rfc3339(wbaTestNow.Add(10 * time.Minute)), RevokedKids: []string{jwk.Kid}})
	rec, _ = serve(t, rig, mcpCall("get_media_buys"))
	requireAdCPEnvelope(t, rec, CodePermissionDenied)
}

func TestMiddlewareWebBotAuthFailuresUseStatusCodes(t *testing.T) {
	rig := newWBARig(t)
	var c captured
	h := Middleware(MiddlewareOptions{
		WebBotAuth:  &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, Clock: wbaClock},
		Replay:      rig.replay,
		ObserveOnly: true, // a WBA failure rejects even in shadow mode
		Logger:      discardLogger(),
	})(captureHandler(&c))

	r := rig.signedRequest(t, mcpCall("get_principal"))
	r.Header.Set("Signature-Agent", `sig1="https://attacker.example.com"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.NotEmpty(t, rec.Header().Get("Accept-Signature"))
	require.Empty(t, rec.Header().Get("WWW-Authenticate"), "no request_signature_* codes under Web Bot Auth")
	require.NotContains(t, rec.Body.String(), "request_signature")
	require.False(t, c.called)

	r = rig.signedRequest(t, mcpCall("get_principal"))
	r.Header.Set("Signature-Input", "garbage(")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, rec.Header().Get("Accept-Signature"))

	// Custom rejection rendering.
	var seen *WBAError
	h2 := Middleware(MiddlewareOptions{
		WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, Clock: wbaClock, OnReject: func(w http.ResponseWriter, _ *http.Request, e *WBAError) {
			seen = e
			w.WriteHeader(e.Status)
		}},
		Replay: rig.replay, Logger: discardLogger(),
	})(captureHandler(&c))
	jwk, _ := PublicDirectoryKey(rig.key)
	rig.revs.set(t, revocationPayload{Updated: rfc3339(wbaTestNow.Add(-time.Minute)), NextUpdate: rfc3339(wbaTestNow.Add(10 * time.Minute)), RevokedKids: []string{jwk.Kid}})
	r = rig.signedRequest(t, mcpCall("get_principal"))
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, r)
	require.NotNil(t, seen)
	require.True(t, seen.Authorization)
}

func TestMiddlewareWebBotAuthRelaysDoNotInheritAuthority(t *testing.T) {
	rig := newWBARig(t)
	relayKey := newEd25519(t)
	relay := "https://relay.agency.example.com"
	rig.dirs.publish(t, relay, wbaTestNow.Add(-time.Hour), 24*time.Hour, relayKey)
	relayRevs := newRevocationServer(t, relay, relayKey)
	relayRevs.set(t, revocationPayload{Updated: rfc3339(wbaTestNow.Add(-time.Minute)), NextUpdate: rfc3339(wbaTestNow.Add(10 * time.Minute))})
	fetch := func(ctx context.Context, url, inm, ims string) (*RevocationFetchResult, error) {
		if strings.HasPrefix(url, relay) {
			return relayRevs.fetch(ctx, url, inm, ims)
		}
		return rig.revs.fetch(ctx, url, inm, ims)
	}
	checker, _ := NewOriginRevocationChecker(OriginRevocationCheckerOptions{Keys: rig.resolver, Fetch: fetch, Clock: wbaClock})
	auth := &fakeAuthorizer{principals: map[string]string{relay: "relay_principal"}}
	var c captured
	h := Middleware(MiddlewareOptions{WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: checker, Authorizer: auth, Clock: wbaClock}, Logger: discardLogger()})(captureHandler(&c))
	sign := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://seller.example.com/mcp", strings.NewReader(mcpCall("create_media_buy")))
		r.Header.Set("Content-Type", "application/json")
		require.NoError(t, SignWebBotAuthRequest(r, rig.key, WBASignOptions{AgentOrigin: rig.origin, Label: "brand", Clock: wbaClock}))
		require.NoError(t, SignWebBotAuthRelay(r, relayKey, WBASignOptions{AgentOrigin: relay, Label: "relay", Clock: wbaClock}))
		return r
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sign())
	// The caller is the originating (unbound) brand agent; the bound relay
	// does not lend it authority, so it is served as anonymous.
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Nil(t, c.signer)

	auth.principals[rig.origin] = "brand_principal"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, sign())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "brand_principal", c.signer.PrincipalID)
	require.Len(t, c.signers, 2)
	require.Equal(t, relay, c.signers[1].AgentURL)
	require.Empty(t, c.signers[1].PrincipalID)
}

func TestMiddlewareRFC9421Coexistence(t *testing.T) {
	res, err := GenerateSigningKey(AlgEd25519, "legacy-key")
	require.NoError(t, err)
	priv, _, _ := LoadPrivateKey(res.PrivateKeyPEM)
	resolver := NewStaticJWKSResolver()
	jwk := res.PublicJWK
	resolver.Put("legacy-key", &jwk, "https://buyer.example.com/mcp")
	legacy, err := NewSigner(SignerOptions{KeyID: "legacy-key", PrivateKey: priv})
	require.NoError(t, err)

	sign := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://seller.example.com/adcp/create_media_buy", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		require.NoError(t, legacy.SignRequest(r, SignOptions{CoverContentDigest: true}))
		return r
	}
	rig := newWBARig(t)
	wba := &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, Clock: wbaClock}

	// RFC 9421 still works with Web Bot Auth enabled.
	var c captured
	h := Middleware(MiddlewareOptions{Resolver: resolver, WebBotAuth: wba, SchemeOverride: "https", Logger: discardLogger()})(captureHandler(&c))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sign())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, ProfileRequestSigning.Tag, c.signer.Profile)

	// No downgrade: once the origin is bound, RFC 9421 from it is refused,
	// with or without Web Bot Auth enabled.
	for _, w := range []*WebBotAuthOptions{wba, nil} {
		c = captured{}
		h = Middleware(MiddlewareOptions{Resolver: resolver, WebBotAuth: w, SchemeOverride: "https", Logger: discardLogger(),
			BoundOrigins: fakeBoundOrigins{"https://buyer.example.com": "principal_7"}})(captureHandler(&c))
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, sign())
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")
		require.False(t, c.called)
	}

	// An RFC 9421 signature carrying an uncovered Signature-Agent is
	// verified under Web Bot Auth only when it is enabled, and fails there:
	// the base64url RFC 9421 Signature does not parse as an RFC 8941
	// Dictionary (400), and it has no web-bot-auth member (403) either way.
	r := sign()
	r.Header.Set("Signature-Agent", `sig1="https://buyer.example.com"`)
	c = captured{}
	h = Middleware(MiddlewareOptions{Resolver: resolver, WebBotAuth: wba, SchemeOverride: "https", Logger: discardLogger()})(captureHandler(&c))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, rec.Code)
	require.Empty(t, rec.Header().Get("WWW-Authenticate"))
	require.False(t, c.called)

	// Without Web Bot Auth the middleware behaves exactly as before.
	r = sign()
	r.Header.Set("Signature-Agent", `sig1="https://buyer.example.com"`)
	c = captured{}
	h = Middleware(MiddlewareOptions{Resolver: resolver, SchemeOverride: "https", Logger: discardLogger()})(captureHandler(&c))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareLogsRFC9421Deprecation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	_ = Middleware(MiddlewareOptions{Logger: logger})
	require.Equal(t, 1, strings.Count(buf.String(), "deprecated in AdCP 3.3"))
	require.Contains(t, buf.String(), "level=INFO")
	buf.Reset()
	rig := newWBARig(t)
	_ = Middleware(MiddlewareOptions{Logger: logger, WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker}})
	require.NotContains(t, buf.String(), "deprecated")
}

// TestMiddlewareUnboundGateReadsExactKeys: the operation the unbound gate
// sees is the one the MCP SDK dispatches. A case-variant duplicate key
// ("Name" beside "name") must not smuggle a tool past the gate.
func TestMiddlewareUnboundGateReadsExactKeys(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"exact get_principal (positive control)", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_principal","arguments":{}}}`, http.StatusOK},
		{"name and Name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_media_buy","arguments":{},"Name":"get_principal"}}`, http.StatusBadRequest},
		{"method and Method", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"initialize","params":{"name":"create_media_buy"}}`, http.StatusBadRequest},
		// Without an exact name the request names no allowed operation, so
		// it is served as anonymous: no identity is attached.
		{"Name only", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"Name":"get_principal","arguments":{}}}`, http.StatusOK},
		{"Method only", `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"get_principal"}}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newWBARig(t)
			var c captured
			h := Middleware(MiddlewareOptions{WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, Clock: wbaClock}, Replay: rig.replay, Logger: discardLogger()})(captureHandler(&c))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, rig.signedRequest(t, tc.body))
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			require.Equal(t, tc.status == http.StatusOK, c.called)
			if c.called {
				require.Equal(t, strings.HasPrefix(tc.name, "exact"), c.signer != nil, "identity only for the exact allowed operation")
			}
		})
	}
	req := func(body string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://s.example.com/mcp", strings.NewReader(body))
	}
	require.Equal(t, "get_principal", jsonRPCOperation(req(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_principal"}}`), 0))
	require.Equal(t, "tools/list", jsonRPCOperation(req(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), 0))
	require.Empty(t, jsonRPCOperation(req(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"Name":"get_principal"}}`), 0))
	require.Empty(t, jsonRPCOperation(req(`{"jsonrpc":"1.0","method":"tools/list"}`), 0))
	require.Empty(t, jsonRPCOperation(req(`not json`), 0))
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)) }

// TestMiddlewareSessionMethodsAndTransportRequests: an identity-established
// signer can always open and close an MCP session, whatever UnboundFor
// lists, but a bodyless request that names an operation is still gated.
func TestMiddlewareSessionMethodsAndTransportRequests(t *testing.T) {
	rig := newWBARig(t)
	var c captured
	h := Middleware(MiddlewareOptions{
		WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, Clock: wbaClock, UnboundFor: []string{"get_products"}},
		Replay:     rig.replay, Logger: discardLogger(), OperationResolver: DefaultOperationResolver,
	})(captureHandler(&c))
	serve := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	for _, body := range []string{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`} {
		require.Equal(t, http.StatusOK, serve(rig.signedRequest(t, body)), body)
	}
	c = captured{}
	require.Equal(t, http.StatusOK, serve(rig.signedRequest(t, mcpCall("get_principal"))))
	require.Nil(t, c.signer, "UnboundFor replaced the default: get_principal is served as anonymous")
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		r := httptest.NewRequest(method, "https://seller.example.com/mcp", nil)
		require.NoError(t, SignWebBotAuthRequest(r, rig.key, WBASignOptions{AgentOrigin: rig.origin, Clock: wbaClock}))
		require.Equal(t, http.StatusOK, serve(r), method)
	}
	r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/create_media_buy", nil)
	require.NoError(t, SignWebBotAuthRequest(r, rig.key, WBASignOptions{AgentOrigin: rig.origin, Clock: wbaClock}))
	c = captured{}
	require.Equal(t, http.StatusOK, serve(r))
	require.Nil(t, c.signer, "a resolved operation beyond UnboundFor is served as anonymous, even without a body")
}

// TestMiddlewareCarriesSignerToToolRequests: every verified signer, under
// either profile, is placed in the request's auth.TokenInfo for MCP tool
// handlers, without inventing a UserID or disturbing the Authorization
// header.
func TestMiddlewareCarriesSignerToToolRequests(t *testing.T) {
	res, err := GenerateSigningKey(AlgEd25519, "legacy-key")
	require.NoError(t, err)
	priv, _, _ := LoadPrivateKey(res.PrivateKeyPEM)
	resolver := NewStaticJWKSResolver()
	jwk := res.PublicJWK
	resolver.Put("legacy-key", &jwk, "https://buyer.example.com/mcp")
	legacy, _ := NewSigner(SignerOptions{KeyID: "legacy-key", PrivateKey: priv})
	var ti *auth.TokenInfo
	var authz string
	h := Middleware(MiddlewareOptions{Resolver: resolver, SchemeOverride: "https", Logger: discardLogger()})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ti = auth.TokenInfoFromContext(r.Context())
		authz = r.Header.Get("Authorization")
	}))
	r := httptest.NewRequest(http.MethodPost, "https://seller.example.com/adcp/x", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Basic abc")
	require.NoError(t, legacy.SignRequest(r, SignOptions{CoverContentDigest: true}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	require.NotNil(t, ti)
	require.Empty(t, ti.UserID)
	s := VerifiedSignerFromTokenInfo(ti)
	require.NotNil(t, s)
	require.Equal(t, "legacy-key", s.KeyID)
	require.Equal(t, "Basic abc", authz, "the original Authorization header is restored")
	require.Nil(t, VerifiedSignerFromToolRequest(nil))
}
