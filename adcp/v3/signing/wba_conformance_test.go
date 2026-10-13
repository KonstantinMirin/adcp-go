package signing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// wbaVector is the subset of the test-vectors/wba-profile format these tests
// read (see testdata/wba-profile/README.md and the upstream README).
type wbaVector struct {
	Name         string `json:"name"`
	ReferenceNow int64  `json:"reference_now"`
	Request      struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"request"`
	Response *struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"response"`
	Directories map[string]struct {
		KeysRef []string `json:"keys_ref"`
	} `json:"directories"`
	TestHarnessState *struct {
		ReplayCacheEntries []struct {
			Identity   string `json:"identity"`
			Nonce      string `json:"nonce"`
			TTLSeconds int    `json:"ttl_seconds"`
		} `json:"replay_cache_entries"`
	} `json:"test_harness_state"`
	ExpectedSignatureBase map[string]string `json:"expected_signature_base"`
	ExpectedOutcome       struct {
		Success         bool              `json:"success"`
		Status          int               `json:"status"`
		Identities      map[string]string `json:"identities"`
		AcceptSignature *struct {
			Label      string   `json:"label"`
			Components string   `json:"components"`
			Parameters []string `json:"parameters"`
		} `json:"accept_signature"`
	} `json:"expected_outcome"`
}

type wbaVectorKey struct {
	JWK
	Identity string `json:"identity"`
}

func loadWBAKeys(t *testing.T) map[string]wbaVectorKey {
	t.Helper()
	data, err := os.ReadFile("testdata/wba-profile/keys.json")
	require.NoError(t, err)
	var doc struct {
		Keys []wbaVectorKey `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	out := map[string]wbaVectorKey{}
	for _, k := range doc.Keys {
		tp, err := JWKThumbprint(k.JWK)
		require.NoError(t, err)
		require.Equal(t, k.Kid, tp, "vector kid must be the RFC 7638 thumbprint")
		out[k.Kid] = k
	}
	return out
}

func loadWBAVectors(t *testing.T, dir string) map[string]wbaVector {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata/wba-profile", dir, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	out := map[string]wbaVector{}
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- test reads vectors matched by a fixed glob under testdata.
		require.NoError(t, err)
		var v wbaVector
		require.NoError(t, json.Unmarshal(data, &v), f)
		out[filepath.Base(f)] = v
	}
	return out
}

// staticWBAKeys is a WBAKeyResolver over fixed per-origin directories.
type staticWBAKeys map[string]map[string]JWK

func (s staticWBAKeys) ResolveWBAKey(_ context.Context, origin, keyID string) (*JWK, error) {
	if k, ok := s[origin][keyID]; ok {
		pub := k.Public()
		return &pub, nil
	}
	return nil, nil
}

type noRevocations struct{}

func (noRevocations) RevokedWBAKey(context.Context, string, string) (bool, error) { return false, nil }

func vectorDirectories(t *testing.T, v wbaVector, keys map[string]wbaVectorKey) staticWBAKeys {
	t.Helper()
	dirs := staticWBAKeys{}
	for origin, d := range v.Directories {
		dirs[origin] = map[string]JWK{}
		for _, kid := range d.KeysRef {
			k, ok := keys[kid]
			require.True(t, ok, kid)
			dirs[origin][kid] = k.JWK
		}
	}
	return dirs
}

func vectorRequest(v wbaVector) *http.Request {
	r := httptest.NewRequest(v.Request.Method, v.Request.URL, strings.NewReader(v.Request.Body))
	if v.Request.Body == "" {
		r = httptest.NewRequest(v.Request.Method, v.Request.URL, nil)
	}
	for k, val := range v.Request.Headers {
		r.Header.Set(k, val)
	}
	return r
}

func verifyWBAVector(t *testing.T, v wbaVector, keys map[string]wbaVectorKey) ([]*VerifiedSigner, error) {
	t.Helper()
	replay := NewMemoryReplayStore(0)
	if v.TestHarnessState != nil {
		for _, e := range v.TestHarnessState.ReplayCacheEntries {
			replay.Preload(wbaReplayIdentity(e.Identity), e.Nonce, time.Duration(e.TTLSeconds)*time.Second)
		}
	}
	return VerifyWebBotAuthRequest(vectorRequest(v), WBAVerifyOptions{
		Keys:       vectorDirectories(t, v, keys),
		Revocation: noRevocations{},
		Replay:     replay,
		Clock:      func() time.Time { return time.Unix(v.ReferenceNow, 0) },
	})
}

func TestWBAPositiveVectors(t *testing.T) {
	keys := loadWBAKeys(t)
	for name, v := range loadWBAVectors(t, "positive") {
		if v.Response != nil {
			continue // the directory-response vector has its own test
		}
		t.Run(name, func(t *testing.T) {
			// The signature base we compute must match the committed base
			// byte for byte, label by label.
			r := vectorRequest(v)
			inputs, err := parseSFDictionary(r.Header.Get(signatureInputHeader))
			require.NoError(t, err)
			for label, want := range v.ExpectedSignatureBase {
				m, ok := inputs.get(label)
				require.True(t, ok, label)
				got, err := wbaSignatureBase(r.Method, v.Request.URL, r.Header, m, false)
				require.NoError(t, err)
				require.Equal(t, want, got, label)
			}

			signers, err := verifyWBAVector(t, v, keys)
			require.NoError(t, err)
			got := map[string]string{}
			for _, s := range signers {
				got[s.Label] = s.AgentURL
				require.Equal(t, ProfileTagWebBotAuth, s.Profile)
				require.Empty(t, s.PrincipalID, "verification alone never binds a principal")
			}
			require.Equal(t, v.ExpectedOutcome.Identities, got)
		})
	}
}

func TestWBANegativeVectors(t *testing.T) {
	keys := loadWBAKeys(t)
	for name, v := range loadWBAVectors(t, "negative") {
		t.Run(name, func(t *testing.T) {
			_, err := verifyWBAVector(t, v, keys)
			we := AsWBAError(err)
			require.NotNil(t, we, "want a *WBAError, got %v", err)
			require.Equal(t, v.ExpectedOutcome.Status, we.Status, we.Reason)
			h := we.ResponseHeader()
			if v.ExpectedOutcome.Status == http.StatusForbidden {
				require.False(t, we.Authorization)
				accept := h.Get(acceptSignatureHeader)
				require.NotEmpty(t, accept)
				d, err := parseSFDictionary(accept)
				require.NoError(t, err)
				want := v.ExpectedOutcome.AcceptSignature
				m, ok := d.get(want.Label)
				require.True(t, ok, "Accept-Signature label %q in %q", want.Label, accept)
				components := sfMember{inner: true, list: m.list}.serialize()
				require.Equal(t, want.Components, components)
				var params []string
				for _, p := range m.params {
					params = append(params, p.key)
				}
				for _, p := range want.Parameters {
					require.Contains(t, params, p)
				}
				nonce, ok := stringParam(m.params, "nonce")
				require.True(t, ok)
				require.GreaterOrEqual(t, len(nonce), wbaMinNonceLen)
			} else {
				require.Empty(t, h.Get(acceptSignatureHeader))
			}
		})
	}
}

func TestWBADirectoryResponseVector(t *testing.T) {
	keys := loadWBAKeys(t)
	v := loadWBAVectors(t, "positive")["003-signed-directory-response.json"]
	require.NotNil(t, v.Response)
	resp := &DirectoryResponse{Status: v.Response.Status, Header: http.Header{}, Body: []byte(v.Response.Body)}
	for k, val := range v.Response.Headers {
		resp.Header.Set(k, val)
	}
	inputs, err := parseSFDictionary(resp.Header.Get(signatureInputHeader))
	require.NoError(t, err)
	for label, want := range v.ExpectedSignatureBase {
		m, _ := inputs.get(label)
		got, err := wbaSignatureBase(http.MethodGet, "https://buyer-7k3q.com"+DirectoryPath, resp.Header, m, true)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	got, err := VerifyDirectoryResponse("https://buyer-7k3q.com", resp, time.Unix(v.ReferenceNow, 0))
	require.NoError(t, err)
	var kids []string
	for kid := range got {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	require.Equal(t, []string{"6WsKMCObba49V3uN0vIENnk1BKAk7c9zjBJcWKyQ9_I"}, kids)
	require.Equal(t, keys[kids[0]].X, got[kids[0]].X)

	// Covering the request authority stops the key set being replayed from
	// another domain.
	_, err = VerifyDirectoryResponse("https://agent.brand-7k3q.com", resp, time.Unix(v.ReferenceNow, 0))
	require.Error(t, err)
}

// TestWBASignerReproducesVector signs the committed request with the
// published seed. Ed25519 is deterministic, so the Signature must match
// byte for byte.
func TestWBASignerReproducesVector(t *testing.T) {
	keys := loadWBAKeys(t)
	v := loadWBAVectors(t, "positive")["001-single-signer-request.json"]
	seed, err := b64UrlDecode(keys["6WsKMCObba49V3uN0vIENnk1BKAk7c9zjBJcWKyQ9_I"].TestOnlyPrivateD)
	require.NoError(t, err)
	priv := ed25519.NewKeyFromSeed(seed)

	r := httptest.NewRequest(v.Request.Method, v.Request.URL, strings.NewReader(v.Request.Body))
	r.Header.Set("Content-Type", "application/json")
	inputs, err := parseSFDictionary(v.Request.Headers["Signature-Input"])
	require.NoError(t, err)
	m, _ := inputs.get("sig1")
	created, _ := intParam(m.params, "created")
	nonce, _ := stringParam(m.params, "nonce")
	require.NoError(t, SignWebBotAuthRequest(r, priv, WBASignOptions{
		AgentOrigin:     "https://buyer-7k3q.com",
		CreatedOverride: created,
		NonceOverride:   nonce,
	}))
	require.Equal(t, v.Request.Headers["Signature-Agent"], r.Header.Get("Signature-Agent"))
	require.Equal(t, v.Request.Headers["Content-Digest"], r.Header.Get("Content-Digest"))
	require.Equal(t, v.Request.Headers["Signature-Input"], r.Header.Get("Signature-Input"))
	require.Equal(t, v.Request.Headers["Signature"], r.Header.Get("Signature"))
}

// TestWBARelaySignerReproducesVector rebuilds the two-signature relay
// request: the brand signs, then the relay adds a signature covering the
// brand's members.
func TestWBARelaySignerReproducesVector(t *testing.T) {
	keys := loadWBAKeys(t)
	v := loadWBAVectors(t, "positive")["002-relay-request-two-signatures.json"]
	priv := func(kid string) ed25519.PrivateKey {
		seed, err := b64UrlDecode(keys[kid].TestOnlyPrivateD)
		require.NoError(t, err)
		return ed25519.NewKeyFromSeed(seed)
	}
	inputs, err := parseSFDictionary(v.Request.Headers["Signature-Input"])
	require.NoError(t, err)
	param := func(label string) (int64, string) {
		m, _ := inputs.get(label)
		c, _ := intParam(m.params, "created")
		n, _ := stringParam(m.params, "nonce")
		return c, n
	}
	r := httptest.NewRequest(v.Request.Method, v.Request.URL, strings.NewReader(v.Request.Body))
	r.Header.Set("Content-Type", "application/json")
	created, nonce := param("brand")
	require.NoError(t, SignWebBotAuthRequest(r, priv("hHurKlVBnPJ4AGiPyl6HWMhxgkIcRBzaC8qWwEtnuVI"), WBASignOptions{
		AgentOrigin: "https://agent.brand-7k3q.com", Label: "brand", CreatedOverride: created, NonceOverride: nonce,
	}))
	created, nonce = param("relay")
	require.NoError(t, SignWebBotAuthRelay(r, priv("ZtaFf5jj-EzorJmZn6mX3YnmK_QyZKVLbbinzIQKOjQ"), WBASignOptions{
		AgentOrigin: "https://relay.agency-7k3q.com", Label: "relay", CreatedOverride: created, NonceOverride: nonce,
	}))
	for _, h := range []string{"Signature-Agent", "Signature-Input", "Signature", "Content-Digest"} {
		require.Equal(t, v.Request.Headers[h], r.Header.Get(h), h)
	}
}
