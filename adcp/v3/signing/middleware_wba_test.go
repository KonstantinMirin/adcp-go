package signing

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	cases := []struct {
		name       string
		body       string
		authorizer *fakeAuthorizer
		unboundFor []string
		wantStatus int
		principal  string
	}{
		{"identity-established may call get_principal", mcpCall("get_principal"), &fakeAuthorizer{}, nil, http.StatusOK, ""},
		{"identity-established may call get_adcp_capabilities", mcpCall("get_adcp_capabilities"), nil, nil, http.StatusOK, ""},
		{"identity-established gets no authority for create_media_buy", mcpCall("create_media_buy"), &fakeAuthorizer{}, nil, http.StatusForbidden, ""},
		{"identity-established gets no authority for sync_accounts", mcpCall("sync_accounts"), nil, nil, http.StatusForbidden, ""},
		{"configured anonymous reads", mcpCall("get_products"), &fakeAuthorizer{}, []string{"get_products", "tools/list"}, http.StatusOK, ""},
		{"configured protocol method", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, &fakeAuthorizer{}, []string{"get_products", "tools/list"}, http.StatusOK, ""},
		{"bound origin gets its principal", mcpCall("create_media_buy"), &fakeAuthorizer{principals: map[string]string{"https://buyer.example.com": "principal_7"}}, nil, http.StatusOK, "principal_7"},
		{"bound but delisted origin is denied", mcpCall("create_media_buy"), &fakeAuthorizer{principals: map[string]string{"https://buyer.example.com": "principal_7"}, deny: map[string]bool{"https://buyer.example.com": true}}, nil, http.StatusForbidden, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newWBARig(t)
			opts := &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker, UnboundFor: tc.unboundFor, Clock: wbaClock}
			if tc.authorizer != nil {
				opts.Authorizer = tc.authorizer
			}
			var c captured
			h := Middleware(MiddlewareOptions{WebBotAuth: opts, Replay: rig.replay, Logger: discardLogger()})(captureHandler(&c))
			r := rig.signedRequest(t, tc.body)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
			if tc.wantStatus == http.StatusOK {
				require.True(t, c.called)
				require.Equal(t, "https://buyer.example.com", c.signer.AgentURL)
				require.Equal(t, tc.principal, c.signer.PrincipalID)
				require.Equal(t, tc.body, c.body, "the handler still reads the body")
				return
			}
			require.False(t, c.called)
			require.Empty(t, rec.Header().Get("Accept-Signature"), "an authorization failure carries no Accept-Signature")
			require.Contains(t, rec.Body.String(), `"PERMISSION_DENIED"`)
			require.NotContains(t, rec.Body.String(), "delisted", "no detail leaks")
		})
	}
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
	r = rig.signedRequest(t, mcpCall("create_media_buy"))
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
	// does not lend it authority.
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

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
	rfc9421DeprecationOnce = &sync.Once{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	_ = Middleware(MiddlewareOptions{Logger: logger})
	_ = Middleware(MiddlewareOptions{Logger: logger})
	require.Equal(t, 1, strings.Count(buf.String(), "deprecated in AdCP 3.3"))
	buf.Reset()
	rfc9421DeprecationOnce = &sync.Once{}
	rig := newWBARig(t)
	_ = Middleware(MiddlewareOptions{Logger: logger, WebBotAuth: &WebBotAuthOptions{Keys: rig.resolver, Revocation: rig.checker}})
	require.NotContains(t, buf.String(), "deprecated")
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)) }
