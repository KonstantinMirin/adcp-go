package signing

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3"
	"github.com/stretchr/testify/require"
)

func TestCanonicalOrigin(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		// The url-canonicalization.mdx example.
		{"HTTPS://User@Seller.Example.COM.:443/mcp?x=1", "https://seller.example.com", true},
		{"https://seller.example.com:8443/a/b", "https://seller.example.com:8443", true},
		{"http://seller.example.com:80/", "http://seller.example.com", true},
		{"https://[2001:db8::1]:443/x", "https://[2001:db8::1]", true},
		{"https://seller.example.com", "https://seller.example.com", true},
		{"https://seller..example.com/x", "", false},
		{"https://seller.example.com../x", "", false},
		{"ftp://seller.example.com/x", "", false},
		{"/relative", "", false},
		{"https://bücher.example/x", "", false},
	}
	for _, tc := range cases {
		got, err := CanonicalOrigin(tc.in)
		if tc.ok {
			require.NoError(t, err, tc.in)
			require.Equal(t, tc.want, got, tc.in)
		} else {
			require.Error(t, err, tc.in)
		}
	}
}

func TestWebBotAuthOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://Buyer.Example.com/agent/mcp": "https://buyer.example.com",
		"https://buyer.example.com.":          "https://buyer.example.com",
	} {
		got, err := webBotAuthOrigin(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got)
	}
	for _, in := range []string{
		"http://buyer.example.com", "https://user@buyer.example.com", "https://buyer.example.com/a b",
		"https://127.0.0.1", "https://10.0.0.8", "https://localhost", "https://[::1]", "not a url", "",
	} {
		_, err := webBotAuthOrigin(in)
		require.Error(t, err, in)
	}
}

func TestJWKThumbprint(t *testing.T) {
	// RFC 8037 Appendix A.3.
	tp, err := JWKThumbprint(JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
	require.NoError(t, err)
	require.Equal(t, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", tp)
	// Members outside the required set do not change the thumbprint.
	tp2, err := JWKThumbprint(JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", Kid: "x", Use: "sig", Alg: "EdDSA"})
	require.NoError(t, err)
	require.Equal(t, tp, tp2)
	for _, bad := range []JWK{{Kty: "OKP"}, {Kty: "EC", Crv: "P-256", X: "a"}, {Kty: "RSA"}} {
		_, err := JWKThumbprint(bad)
		require.Error(t, err)
	}
	for _, key := range []any{newEd25519(t), newP256(t)} {
		jwk, err := PublicDirectoryKey(key)
		require.NoError(t, err)
		require.Len(t, jwk.Kid, wbaThumbprintLen)
		require.Equal(t, "sig", jwk.Use)
		require.Empty(t, jwk.AdcpUse, "purpose belongs to the origin, not the key")
		require.Empty(t, jwk.PrivateD)
	}
}

func TestUsesWebBotAuth(t *testing.T) {
	cases := []struct {
		name   string
		header map[string]string
		want   bool
	}{
		{"unsigned", nil, false},
		{"rfc 9421", map[string]string{"Signature-Input": `sig1=("@method");created=1;tag="adcp/request-signing/v1"`}, false},
		{"signature-agent present", map[string]string{"Signature-Agent": `sig1="https://b.example.com"`}, true},
		{"uncovered signature-agent on rfc 9421", map[string]string{"Signature-Agent": `x`, "Signature-Input": `sig1=("@method");tag="adcp/request-signing/v1"`}, true},
		{"wba tag", map[string]string{"Signature-Input": `sig1=("@method");tag="web-bot-auth"`}, true},
		{"wba tag on a second label", map[string]string{"Signature-Input": `a=("@method");tag="adcp/request-signing/v1", b=("@method");tag="web-bot-auth"`}, true},
		{"malformed input naming the tag", map[string]string{"Signature-Input": `sig1=("@method";tag="web-bot-auth"`}, true},
	}
	for _, tc := range cases {
		h := http.Header{}
		for k, v := range tc.header {
			h.Set(k, v)
		}
		require.Equal(t, tc.want, UsesWebBotAuth(h), tc.name)
	}
}

func TestWBASignVerifyRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  any
		body string
	}{
		{"ed25519 with body", newEd25519(t), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_products"}}`},
		{"ed25519 read without body", newEd25519(t), ""},
		{"p256 with body", newP256(t), `{"a":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dirs := newFakeDirectories()
			origin := "https://agent.buyer.example.com"
			other := newEd25519(t)
			dirs.publish(t, origin, wbaTestNow.Add(-time.Hour), 24*time.Hour, other, tc.key)
			resolver := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: wbaClock})
			var r *http.Request
			if tc.body == "" {
				r = httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_products?x=1", nil)
			} else {
				r = httptest.NewRequest(http.MethodPost, "https://seller.example.com/mcp", strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/json")
			}
			require.NoError(t, SignWebBotAuthRequest(r, tc.key, WBASignOptions{AgentOrigin: origin + "/mcp", Clock: wbaClock}))
			require.Equal(t, `sig1="https://agent.buyer.example.com"`, r.Header.Get("Signature-Agent"))
			if tc.body == "" {
				require.Empty(t, r.Header.Get("Content-Digest"))
			}
			signers, err := VerifyWebBotAuthRequest(r, WBAVerifyOptions{Keys: resolver, Revocation: noRevocations{}, Replay: NewMemoryReplayStore(0), Clock: wbaClock})
			require.NoError(t, err)
			require.Len(t, signers, 1)
			jwk, _ := PublicDirectoryKey(tc.key)
			require.Equal(t, origin, signers[0].AgentURL)
			require.Equal(t, jwk.Kid, signers[0].KeyID)
			require.Equal(t, ProfileTagWebBotAuth, signers[0].Profile)
			if tc.body != "" {
				// The body is still readable downstream.
				b := make([]byte, len(tc.body))
				_, _ = r.Body.Read(b)
				require.Equal(t, tc.body, string(b))
			}
		})
	}
}

func TestWBARejections(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_media_buy"}}`
	type tamper func(t *testing.T, rig *wbaRig, r *http.Request)
	resign := func(t *testing.T, rig *wbaRig, r *http.Request, opts WBASignOptions) {
		for _, h := range []string{"Signature", "Signature-Input", "Signature-Agent"} {
			r.Header.Del(h)
		}
		opts.AgentOrigin = rig.origin
		if opts.Clock == nil {
			opts.Clock = wbaClock
		}
		require.NoError(t, SignWebBotAuthRequest(r, rig.key, opts))
	}
	cases := []struct {
		name   string
		body   string
		tamper tamper
		status int
		authz  bool
	}{
		{"body changed after signing", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Body = http.NoBody
			r.Body = newBody(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"other"}}`)
		}, http.StatusForbidden, false},
		{"signature-agent swapped to another origin", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Agent", `sig1="https://attacker.example.com"`)
		}, http.StatusForbidden, false},
		{"signature-agent type other than directory", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Agent", `sig1="https://buyer.example.com";type=jwks`)
		}, http.StatusForbidden, false},
		{"signature-agent member missing", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Agent", `other="https://buyer.example.com"`)
		}, http.StatusForbidden, false},
		{"signature-agent not an sf-string", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Agent", `sig1=buyer`)
		}, http.StatusForbidden, false},
		{"signature-agent over http", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Agent", `sig1="http://buyer.example.com"`)
		}, http.StatusForbidden, false},
		{"expired", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			resign(t, rig, r, WBASignOptions{CreatedOverride: wbaTestNow.Add(-10 * time.Minute).Unix()})
		}, http.StatusForbidden, false},
		{"created in the future beyond skew", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			resign(t, rig, r, WBASignOptions{CreatedOverride: wbaTestNow.Add(2 * time.Minute).Unix()})
		}, http.StatusForbidden, false},
		{"short nonce", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `nonce="`, `nonce="x`, 1))
			in, _ := parseSFDictionary(r.Header.Get("Signature-Input"))
			m, _ := in.get("sig1")
			for i := range m.params {
				if m.params[i].key == "nonce" {
					m.params[i].value = sfStringItem("short")
				}
			}
			r.Header.Set("Signature-Input", sfDict{{key: "sig1", member: m}}.serialize())
		}, http.StatusForbidden, false},
		{"alg does not match key", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `alg="ed25519"`, `alg="ecdsa-p256-sha256"`, 1))
		}, http.StatusForbidden, false},
		{"keyid not a thumbprint", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			in, _ := parseSFDictionary(r.Header.Get("Signature-Input"))
			m, _ := in.get("sig1")
			for i := range m.params {
				if m.params[i].key == "keyid" {
					m.params[i].value = sfStringItem("buyer-key-1")
				}
			}
			r.Header.Set("Signature-Input", sfDict{{key: "sig1", member: m}}.serialize())
		}, http.StatusForbidden, false},
		{"key from another origin's directory", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			other := newEd25519(t)
			rig.dirs.publish(t, "https://other.example.com", wbaTestNow.Add(-time.Hour), 24*time.Hour, other)
			for _, h := range []string{"Signature", "Signature-Input", "Signature-Agent"} {
				r.Header.Del(h)
			}
			require.NoError(t, SignWebBotAuthRequest(r, other, WBASignOptions{AgentOrigin: rig.origin, Clock: wbaClock}))
		}, http.StatusForbidden, false},
		{"content-type not covered on a body", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `"content-type" `, ``, 1))
		}, http.StatusForbidden, false},
		{"signature-agent not covered", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), ` "signature-agent";key="sig1"`, ``, 1))
		}, http.StatusForbidden, false},
		{"repeated covered component", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `("@method"`, `("@method" "@method"`, 1))
		}, http.StatusForbidden, false},
		{"unsupported derived component", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `("@method"`, `("@path" "@method"`, 1))
		}, http.StatusForbidden, false},
		{"labels differ between Signature and Signature-Input", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature", strings.Replace(r.Header.Get("Signature"), "sig1=", "sig2=", 1))
		}, http.StatusBadRequest, false},
		{"duplicate Signature-Input member", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", r.Header.Get("Signature-Input")+", "+r.Header.Get("Signature-Input"))
		}, http.StatusBadRequest, false},
		{"duplicate parameter", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Input", r.Header.Get("Signature-Input")+`;tag="web-bot-auth"`)
		}, http.StatusBadRequest, false},
		{"Signature-Input on two lines", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Add("Signature-Input", `sig2=("@method");tag="web-bot-auth"`)
		}, http.StatusBadRequest, false},
		{"Signature-Agent on two lines", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Add("Signature-Agent", `sig2="https://b.example.com"`)
		}, http.StatusBadRequest, false},
		{"Signature-Agent missing with a wba tag", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Del("Signature-Agent")
		}, http.StatusForbidden, false},
		{"Signature-Agent that does not parse", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature-Agent", `sig1="unterminated`)
		}, http.StatusBadRequest, false},
		{"signed body with case-folded duplicate keys", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","Name":"b"}}`, nil, http.StatusBadRequest, false},
		{"Signature not sf-binary", body, func(t *testing.T, _ *wbaRig, r *http.Request) {
			r.Header.Set("Signature", `sig1="abc"`)
		}, http.StatusBadRequest, false},
		{"malformed signed JSON body", "{not json", nil, http.StatusBadRequest, false},
		{"duplicate keys in signed JSON body", `{"a":1,"a":2}`, nil, http.StatusBadRequest, false},
		{"revoked key", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			jwk, _ := PublicDirectoryKey(rig.key)
			rig.revs.set(t, revocationPayload{Updated: rfc3339(wbaTestNow.Add(-time.Minute)), NextUpdate: rfc3339(wbaTestNow.Add(10 * time.Minute)), RevokedKids: []string{jwk.Kid}})
		}, http.StatusForbidden, true},
		{"revocation list unavailable fails closed (an outage, not a signature failure)", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			rig.revs.fetchErr = errors.New("connection refused")
		}, http.StatusServiceUnavailable, true},
		{"directory discovery fails", body, func(t *testing.T, rig *wbaRig, r *http.Request) {
			rig.dirs.fail(rig.origin, errors.New("timeout"))
		}, http.StatusForbidden, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newWBARig(t)
			r := rig.signedRequest(t, tc.body)
			if tc.tamper != nil {
				tc.tamper(t, rig, r)
			}
			_, err := VerifyWebBotAuthRequest(r, rig.opts())
			we := requireWBAError(t, err, tc.status)
			require.Equal(t, tc.authz, we.Authorization)
			if tc.status == http.StatusForbidden && !tc.authz {
				require.NotEmpty(t, we.ResponseHeader().Get("Accept-Signature"))
			} else {
				require.Empty(t, we.ResponseHeader().Get("Accept-Signature"))
			}
		})
	}
}

func newBody(s string) *readCloser { return &readCloser{strings.NewReader(s)} }

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

func TestWBARequiresVerifierDependencies(t *testing.T) {
	rig := newWBARig(t)
	r := rig.signedRequest(t, "")
	for _, opts := range []WBAVerifyOptions{
		{Revocation: rig.checker, Replay: rig.replay},
		{Keys: rig.resolver, Replay: rig.replay},
		{Keys: rig.resolver, Revocation: rig.checker},
	} {
		_, err := VerifyWebBotAuthRequest(r, opts)
		require.ErrorIs(t, err, errWBANotConfigured)
	}
}

// TestWBAReplayIsPerOriginAcrossKeyRotation: the identity, not the key,
// scopes a nonce, so rotating keys does not reopen a replay.
func TestWBAReplayIsPerOriginAcrossKeyRotation(t *testing.T) {
	rig := newWBARig(t)
	second := newEd25519(t)
	rig.dirs.publish(t, rig.origin, wbaTestNow.Add(-time.Hour), 24*time.Hour, rig.key, second)
	nonce := "Mn-ZM8SnGESx0-rmyYMuTkJFerfbwEii2C0qNkDP8ug"
	sign := func(key ed25519.PrivateKey) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_principal", nil)
		require.NoError(t, SignWebBotAuthRequest(r, key, WBASignOptions{AgentOrigin: rig.origin, Clock: wbaClock, NonceOverride: nonce}))
		return r
	}
	_, err := VerifyWebBotAuthRequest(sign(rig.key), rig.opts())
	require.NoError(t, err)
	_, err = VerifyWebBotAuthRequest(sign(rig.key), rig.opts())
	we := requireWBAError(t, err, http.StatusForbidden)
	accept := we.ResponseHeader().Get("Accept-Signature")
	require.Contains(t, accept, `nonce="`)
	require.NotContains(t, accept, nonce, "the verifier supplies a fresh nonce")
	_, err = VerifyWebBotAuthRequest(sign(second), rig.opts())
	requireWBAStatus(t, err, http.StatusForbidden)

	// The same nonce from a different identity is not a replay.
	otherKey := newEd25519(t)
	rig.dirs.publish(t, "https://other.example.com", wbaTestNow.Add(-time.Hour), 24*time.Hour, otherKey)
	r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_principal", nil)
	require.NoError(t, SignWebBotAuthRequest(r, otherKey, WBASignOptions{AgentOrigin: "https://other.example.com", Clock: wbaClock, NonceOverride: nonce}))
	_, err = VerifyWebBotAuthRequest(r, WBAVerifyOptions{Keys: rig.resolver, Revocation: noRevocations{}, Replay: rig.replay, Clock: wbaClock})
	require.NoError(t, err)
}

func TestWBAReplayCapacityIs429(t *testing.T) {
	rig := newWBARig(t)
	rig.replay.MarkKeyIDAtCap(wbaReplayIdentity(rig.origin))
	_, err := VerifyWebBotAuthRequest(rig.signedRequest(t, ""), rig.opts())
	we := requireWBAError(t, err, http.StatusTooManyRequests)
	require.Empty(t, we.ResponseHeader().Get("Accept-Signature"))
}

// TestWBARelayMustCoverEveryEarlierComponent: a relay that covers an
// earlier signature must also cover every component it covered, including
// an application header field (RFC 9421 §2.2.8 via WBA §5.2.2).
func TestWBARelayMustCoverEveryEarlierComponent(t *testing.T) {
	rig := newWBARig(t)
	relayKey := newEd25519(t)
	relayOrigin := "https://relay.agency.example.com"
	rig.dirs.publish(t, relayOrigin, wbaTestNow.Add(-time.Hour), 24*time.Hour, relayKey)
	keys := rig.resolver

	r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_principal", nil)
	r.Header.Set("X-Trace", "t-1")
	require.NoError(t, SignWebBotAuthRequest(r, rig.key, WBASignOptions{AgentOrigin: rig.origin, Label: "brand", Clock: wbaClock}))
	// Make the brand signature also cover x-trace, by re-signing it by hand.
	in, _ := parseSFDictionary(r.Header.Get("Signature-Input"))
	m, _ := in.get("brand")
	m.list = append(m.list, sfItem{value: sfStringItem("x-trace")})
	base, err := wbaSignatureBase(r.Method, r.URL.String(), r.Header, m, false)
	require.NoError(t, err)
	sig, _ := signWithKey(rig.key, []byte(base))
	r.Header.Set("Signature-Input", sfDict{{key: "brand", member: m}}.serialize())
	r.Header.Set("Signature", sfDict{{key: "brand", member: sfMember{item: sfItem{value: sfBare{kind: sfBinary, b: sig}}}}}.serialize())

	good := r.Clone(context.Background())
	require.NoError(t, SignWebBotAuthRelay(good, relayKey, WBASignOptions{AgentOrigin: relayOrigin, Label: "relay", Clock: wbaClock}))
	require.Contains(t, good.Header.Get("Signature-Input"), `"x-trace"`, "the relay signer covers the earlier signature's components")
	signers, err := VerifyWebBotAuthRequest(good, WBAVerifyOptions{Keys: keys, Revocation: noRevocations{}, Replay: NewMemoryReplayStore(0), Clock: wbaClock})
	require.NoError(t, err)
	require.Equal(t, []string{rig.origin, relayOrigin}, []string{signers[0].AgentURL, signers[1].AgentURL})

	// A relay signature that omits x-trace is rejected even though it
	// covers the brand's three members and verifies cryptographically.
	bad := r.Clone(context.Background())
	require.NoError(t, SignWebBotAuthRelay(bad, relayKey, WBASignOptions{AgentOrigin: relayOrigin, Label: "relay", Clock: wbaClock}))
	in2, _ := parseSFDictionary(bad.Header.Get("Signature-Input"))
	rm, _ := in2.get("relay")
	var kept []sfItem
	for _, c := range rm.list {
		if c.value.s != "x-trace" {
			kept = append(kept, c)
		}
	}
	rm.list = kept
	brandMember, _ := in2.get("brand")
	staged := bad.Header.Clone()
	base, err = wbaSignatureBase(bad.Method, bad.URL.String(), staged, rm, false)
	require.NoError(t, err)
	rsig, _ := signWithKey(relayKey, []byte(base))
	sigs, _ := parseSFDictionary(bad.Header.Get("Signature"))
	brandSig, _ := sigs.get("brand")
	bad.Header.Set("Signature-Input", sfDict{{key: "brand", member: brandMember}, {key: "relay", member: rm}}.serialize())
	bad.Header.Set("Signature", sfDict{{key: "brand", member: brandSig}, {key: "relay", member: sfMember{item: sfItem{value: sfBare{kind: sfBinary, b: rsig}}}}}.serialize())
	_, err = VerifyWebBotAuthRequest(bad, WBAVerifyOptions{Keys: keys, Revocation: noRevocations{}, Replay: NewMemoryReplayStore(0), Clock: wbaClock})
	we := requireWBAError(t, err, http.StatusForbidden)
	require.Equal(t, "relay", we.Label)
}

// TestWBANoReplayStateOnLaterFailure: nonces are recorded only once every
// signature verified.
func TestWBANoReplayStateOnLaterFailure(t *testing.T) {
	rig := newWBARig(t)
	relayKey := newEd25519(t)
	r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_principal", nil)
	require.NoError(t, SignWebBotAuthRequest(r, rig.key, WBASignOptions{AgentOrigin: rig.origin, Label: "brand", Clock: wbaClock}))
	// The relay's origin publishes no directory, so its signature fails.
	require.NoError(t, SignWebBotAuthRelay(r, relayKey, WBASignOptions{AgentOrigin: "https://relay.example.com", Label: "relay", Clock: wbaClock}))
	_, err := VerifyWebBotAuthRequest(r, rig.opts())
	requireWBAStatus(t, err, http.StatusForbidden)
	in, _ := parseSFDictionary(r.Header.Get("Signature-Input"))
	m, _ := in.get("brand")
	nonce, _ := stringParam(m.params, "nonce")
	require.False(t, rig.replay.Seen(wbaReplayIdentity(rig.origin), nonce))
}

func TestWBASignerOptions(t *testing.T) {
	key := newEd25519(t)
	jwk, _ := PublicDirectoryKey(key)

	// KeyID, when given, must be the thumbprint.
	_, err := NewSigner(SignerOptions{KeyID: "operator-chosen", PrivateKey: key, AgentOrigin: "https://buyer.example.com"})
	require.Error(t, err)
	s, err := NewSigner(SignerOptions{PrivateKey: key, AgentOrigin: "https://buyer.example.com"})
	require.NoError(t, err)
	require.Equal(t, ProfileTagWebBotAuth, s.SigningProfile())
	_, err = NewSigner(SignerOptions{PrivateKey: key, AgentOrigin: "http://buyer.example.com"})
	require.Error(t, err)

	// Header emission is opt-in: the RFC 9421 signer never sets or covers
	// Signature-Agent.
	legacy, err := NewSigner(SignerOptions{KeyID: "k", PrivateKey: key})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "https://seller.example.com/adcp/x", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	require.NoError(t, legacy.SignRequest(r, SignOptions{CoverContentDigest: true}))
	require.Empty(t, r.Header.Get("Signature-Agent"))
	require.NotContains(t, r.Header.Get("Signature-Input"), "signature-agent")
	require.Equal(t, ProfileRequestSigning.Tag, legacy.SigningProfile())

	// The WBA signer overwrites a stale digest.
	r = httptest.NewRequest(http.MethodPost, "https://seller.example.com/mcp", strings.NewReader(`{"a":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header["content-digest"] = []string{"sha-256=:AAAA:"}
	r.Header.Set("Content-Digest", "sha-256=:AAAA:")
	delete(r.Header, "content-digest")
	require.NoError(t, s.SignRequest(r, SignOptions{}))
	require.NotEqual(t, "sha-256=:AAAA:", r.Header.Get("Content-Digest"))
	require.Contains(t, r.Header.Get("Signature-Input"), `keyid="`+jwk.Kid+`"`)
	require.Contains(t, r.Header.Get("Signature-Input"), `tag="web-bot-auth"`)

	// A body requires Content-Type, and a signed request needs the relay API.
	r = httptest.NewRequest(http.MethodPost, "https://seller.example.com/mcp", strings.NewReader(`{}`))
	require.Error(t, SignWebBotAuthRequest(r, key, WBASignOptions{AgentOrigin: "https://buyer.example.com"}))
	r.Header.Set("Content-Type", "application/json")
	require.NoError(t, SignWebBotAuthRequest(r, key, WBASignOptions{AgentOrigin: "https://buyer.example.com"}))
	require.Error(t, SignWebBotAuthRequest(r, key, WBASignOptions{AgentOrigin: "https://buyer.example.com"}))
	require.Error(t, SignWebBotAuthRelay(r, key, WBASignOptions{AgentOrigin: "https://relay.example.com", Label: "sig1"}), "label in use")
	require.Error(t, SignWebBotAuthRelay(r, key, WBASignOptions{AgentOrigin: "https://relay.example.com"}), "label required")
	require.Error(t, SignWebBotAuthRequest(httptest.NewRequest(http.MethodGet, "https://s.example.com/", nil), key,
		WBASignOptions{AgentOrigin: "https://buyer.example.com", ValidityWindow: 301 * time.Second}))
	// The Signer refuses to clobber another party's signature too.
	signed := httptest.NewRequest(http.MethodGet, "https://s.example.com/", nil)
	signed.Header.Set("Signature", "other=:AAAA:")
	require.Error(t, s.SignRequest(signed, SignOptions{}))
	require.Error(t, SignWebBotAuthRequest(httptest.NewRequest(http.MethodGet, "https://s.example.com/", nil), key,
		WBASignOptions{AgentOrigin: "https://buyer.example.com", NonceOverride: "short"}))
}

// TestRFC9421VerifierNeverAttributesWBA: the RFC 9421 verifier never
// accepts a Web Bot Auth signature, so it cannot attribute one.
func TestRFC9421VerifierNeverAttributesWBA(t *testing.T) {
	rig := newWBARig(t)
	r := rig.signedRequest(t, `{"a":1}`)
	resolver := NewStaticJWKSResolver()
	jwk, _ := PublicDirectoryKey(rig.key)
	jwk.KeyOps = []string{"verify"}
	jwk.AdcpUse = "request-signing"
	resolver.Put(jwk.Kid, &jwk, rig.origin)
	signer, err := VerifyRequestSignature(r, VerifyOptions{Resolver: resolver, Replay: NewMemoryReplayStore(0), Clock: wbaClock})
	require.Error(t, err)
	require.Nil(t, signer)
}

func TestSignedHTTPClientRequiresAdvertisedRFC9421(t *testing.T) {
	key := newEd25519(t)
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	})
	for _, tc := range []struct {
		profiles []string
		wantErr  bool
	}{{nil, false}, {[]string{ProfileTagRequestSigning, ProfileTagWebBotAuth}, false}, {[]string{ProfileTagWebBotAuth}, true}} {
		client, err := NewSignedHTTPClient(SignedHTTPClientOptions{KeyID: "k", PrivateKey: key, Inner: inner,
			CapabilityProvider: alwaysSignCapability, ProfilesProvider: func(*http.Request) []string { return tc.profiles }})
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodPost, "https://seller.example.com/adcp/create_media_buy", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if tc.wantErr {
			require.ErrorIs(t, err, ErrRequestSigningNotAdvertised)
			continue
		}
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
}

func TestSignedHTTPClientRequiresAdvertisedWBA(t *testing.T) {
	key := newEd25519(t)
	var sent int
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent++
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	})
	for _, tc := range []struct {
		name     string
		profiles []string
		wantErr  bool
	}{
		{"profile not advertised", []string{ProfileTagRequestSigning}, true},
		{"profiles omitted means RFC 9421 only", nil, true},
		{"profile advertised", []string{ProfileTagRequestSigning, ProfileTagWebBotAuth}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent = 0
			client, err := NewSignedHTTPClient(SignedHTTPClientOptions{
				PrivateKey:         key,
				AgentOrigin:        "https://buyer.example.com",
				Inner:              inner,
				CapabilityProvider: alwaysSignCapability,
				ProfilesProvider:   func(*http.Request) []string { return tc.profiles },
			})
			require.NoError(t, err)
			req, _ := http.NewRequest(http.MethodPost, "https://seller.example.com/adcp/create_media_buy", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrWebBotAuthNotAdvertised)
				require.Zero(t, sent, "nothing is sent on a profile mismatch")
				return
			}
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, 1, sent)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func alwaysSignCapability(*http.Request) *adcp.RequestSigningCapabilities {
	return &adcp.RequestSigningCapabilities{Supported: true, RequiredFor: []string{"create_media_buy"}}
}

// TestWBAConcurrentReplay: of many concurrent copies of one signed
// request, exactly one is accepted.
func TestWBAConcurrentReplay(t *testing.T) {
	rig := newWBARig(t)
	r := rig.signedRequest(t, "")
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := VerifyWebBotAuthRequest(r.Clone(context.Background()), rig.opts()); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), accepted.Load())
}

func TestMemoryReplayStoreClaim(t *testing.T) {
	m := NewMemoryReplayStore(2)
	require.Equal(t, ReplayClaimed, m.Claim("k", "n1", time.Minute))
	require.Equal(t, ReplayReplayed, m.Claim("k", "n1", time.Minute))
	require.Equal(t, ReplayClaimed, m.Claim("k", "n2", time.Minute))
	require.Equal(t, ReplayCapacity, m.Claim("k", "n3", time.Minute))
	require.Equal(t, ReplayClaimed, m.Claim("other", "n1", time.Minute))
}

func TestWBAAuthorities(t *testing.T) {
	rig := newWBARig(t)
	opts := rig.opts()
	opts.Authorities = []string{"seller.example.com:443", "api.seller.example.com"}
	_, err := VerifyWebBotAuthRequest(rig.signedRequest(t, ""), opts)
	require.NoError(t, err)
	// A request signed for another seller, replayed here with that seller's
	// Host, is refused even though the signature is valid.
	r := httptest.NewRequest(http.MethodGet, "https://other-seller.example.com/adcp/get_principal", nil)
	require.NoError(t, SignWebBotAuthRequest(r, rig.key, WBASignOptions{AgentOrigin: rig.origin, Clock: wbaClock}))
	_, err = VerifyWebBotAuthRequest(r, opts)
	requireWBAStatus(t, err, http.StatusForbidden)
}
