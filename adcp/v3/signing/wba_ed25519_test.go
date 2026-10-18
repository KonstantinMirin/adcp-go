package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestWBAIsEd25519Only: the Web Bot Auth path signs and verifies with
// Ed25519 only. An RSA key cannot sign a request or a directory, and an RSA
// key in a directory is a key the profile cannot use: it is skipped, needs
// no signature, and a signature naming it is not read.
func TestWBAIsEd25519Only(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	origin := "https://buyer.example.com"

	r := httptest.NewRequest(http.MethodGet, "https://seller.example.com/adcp/get_principal", nil)
	require.Error(t, SignWebBotAuthRequest(r, rsaKey, WBASignOptions{AgentOrigin: origin, Clock: wbaClock}))
	_, err = NewSigner(SignerOptions{PrivateKey: rsaKey, AgentOrigin: origin, Clock: wbaClock})
	require.Error(t, err)
	_, err = NewSigner(SignerOptions{KeyID: "k", PrivateKey: rsaKey})
	require.Error(t, err, "the RFC 9421 profile admits no RSA keys either")
	_, err = PublicDirectoryKey(rsaKey)
	require.Error(t, err)
	_, err = SignKeyDirectory(origin, []any{newEd25519(t), rsaKey}, wbaTestNow, time.Hour)
	require.Error(t, err)

	rsaJWK, err := jwkFromPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	_, err = wbaKeyAlgorithm(rsaJWK)
	require.Error(t, err)
	rsaKid, err := JWKThumbprint(rsaJWK)
	require.NoError(t, err)

	ed := newEd25519(t)
	edJWK, err := PublicDirectoryKey(ed)
	require.NoError(t, err)
	resp := signDirectoryBody(t, origin, []byte(`{"keys":[`+mustJSON(t, rsaJWK)+`,`+mustJSON(t, edJWK)+`]}`), ed)
	resp.Header.Set("Signature-Input", resp.Header.Get("Signature-Input")+`, key9=("@authority";req "content-digest");created=1;expires=2;keyid="`+rsaKid+`";alg="rsa-pss-sha512";tag="`+DirectoryTag+`"`)
	resp.Header.Set("Signature", resp.Header.Get("Signature")+", key9=:AAAA:")
	keys, err := VerifyDirectoryResponse(origin, resp, wbaTestNow)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Contains(t, keys, edJWK.Kid)

	only := signDirectoryBody(t, origin, []byte(`{"keys":[`+mustJSON(t, rsaJWK)+`]}`))
	_, err = VerifyDirectoryResponse(origin, only, wbaTestNow)
	require.ErrorContains(t, err, "no usable key")
}
