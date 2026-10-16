package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// rfc9421TestKeyRSAPSS is test-key-rsa-pss, RFC 9421 Appendix B.1.2: the key
// the Web Bot Auth draft's Appendix E vectors sign with.
const rfc9421TestKeyRSAPSS = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`

// TestWBARSAPSSAppendixEVector checks draft-ietf-webbotauth-httpsig-protocol-00
// Appendix E.1.1 (generated with another implementation): the RSA JWK
// thumbprint, the signature base, the 64-byte padded-base64 nonce, and the
// rsa-pss-sha512 signature. The vector covers only @authority and the
// Signature-Agent member, less than the AdCP profile requires, so only its
// building blocks are checked here.
func TestWBARSAPSSAppendixEVector(t *testing.T) {
	block, _ := pem.Decode([]byte(rfc9421TestKeyRSAPSS))
	require.NotNil(t, block)
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub := pubAny.(*rsa.PublicKey)
	jwk := JWK{Kty: "RSA", N: b64UrlEncodeRaw(pub.N.Bytes()), E: b64UrlEncodeRaw(big.NewInt(int64(pub.E)).Bytes())}
	kid, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	require.Equal(t, "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA", kid)
	alg, err := wbaKeyAlgorithm(jwk)
	require.NoError(t, err)
	require.Equal(t, AlgRSAPSSSHA512, alg)

	const nonce = "wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg=="
	require.True(t, validWBANonce(nonce), "padded standard base64 of 64 bytes")
	input := `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="` + nonce + `";tag="web-bot-auth"`
	signature := `sig2=:gHzpLNeHaHIO19NaJH9YMW5dcVSi2s0wOMBr6p18vcofS106sfC4KBIS0/szPlBBd1vIcyQ88B6CTEWIhRAiVrb9zfX0mx1aG12CSGWcYkSirHeyTxhbuJvXd27ed6skWoy4PjXItq38936ivUQjfdIwXh1aX6HxkAC3vRnEdSNfntkLWeEuIQ5BLIOBGE39fSwg27Qjq6OVWYas/9/aFUr3HA34MXWYdp+//cvlEKDp3kRoLOw9ro0AOr6srHrTeEtxon2afcws1aZVSlPdd2fZSEIGmw9HAHLDCEkFTERu1gH2k/zIEqgy7CAYXI9E5slog0cLg/Vc6+f8gih33g==:`
	h := http.Header{}
	h.Set("Signature-Agent", `agent2="https://signature-agent.test"`)
	inputs, err := parseSFDictionary(input)
	require.NoError(t, err)
	sigs, err := parseSFDictionary(signature)
	require.NoError(t, err)
	member, _ := inputs.get("sig2")
	sigMember, _ := sigs.get("sig2")
	base, err := wbaSignatureBase(http.MethodGet, "https://example.com/", h, member, false)
	require.NoError(t, err)
	require.Equal(t, `"@authority": example.com`+"\n"+
		`"signature-agent";key="agent2": "https://signature-agent.test"`+"\n"+
		`"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="`+nonce+`";tag="web-bot-auth"`, base)
	got, err := wbaVerifyCrypto(member, sigMember, jwk, base)
	require.NoError(t, err)
	require.Equal(t, AlgRSAPSSSHA512, got)
	_, err = wbaVerifyCrypto(member, sigMember, jwk, strings.Replace(base, "example.com", "example.net", 1))
	require.Error(t, err)
}

// TestWBARSAPSSRoundTrip: an RSA identity publishes a signed directory and
// signs requests with rsa-pss-sha512; keys under 2048 bits are refused.
func TestWBARSAPSSRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rig := newWBARig(t)
	rig.dirs.publish(t, rig.origin, wbaTestNow.Add(-time.Hour), 24*time.Hour, key)
	r := httptest.NewRequest(http.MethodPost, "https://seller.example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	r.Header.Set("Content-Type", "application/json")
	require.NoError(t, SignWebBotAuthRequest(r, key, WBASignOptions{AgentOrigin: rig.origin, Clock: wbaClock}))
	require.Contains(t, r.Header.Get("Signature-Input"), `alg="rsa-pss-sha512"`)
	signer, err := VerifyWebBotAuthRequest(r, rig.opts())
	require.NoError(t, err)
	require.Equal(t, AlgRSAPSSSHA512, signer.Algorithm)

	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: proves small keys are refused
	require.NoError(t, err)
	_, err = PublicDirectoryKey(small)
	require.Error(t, err)
	_, err = wbaKeyAlgorithm(JWK{Kty: "RSA", N: b64UrlEncodeRaw(small.N.Bytes()), E: "AQAB"})
	require.Error(t, err)
	_, err = wbaKeyAlgorithm(JWK{Kty: "RSA", N: b64UrlEncodeRaw(key.N.Bytes()), E: "AQAA"})
	require.Error(t, err, "even exponent")
}

// TestSignerRSAOnlyUnderWebBotAuth: the Signer accepts an RSA key only with
// AgentOrigin, and its requests verify.
func TestSignerRSAOnlyUnderWebBotAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = NewSigner(SignerOptions{KeyID: "k", PrivateKey: key})
	require.Error(t, err, "the RFC 9421 profile admits no RSA keys")
	rig := newWBARig(t)
	rig.dirs.publish(t, rig.origin, wbaTestNow.Add(-time.Hour), 24*time.Hour, key)
	s, err := NewSigner(SignerOptions{PrivateKey: key, AgentOrigin: rig.origin, Clock: wbaClock})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_principal", nil)
	require.NoError(t, s.SignRequest(r, SignOptions{}))
	_, err = VerifyWebBotAuthRequest(r, rig.opts())
	require.NoError(t, err)
}
