package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWKThumbprint returns the RFC 7638 SHA-256 thumbprint of jwk's public key,
// base64url-encoded without padding (RFC 8037 Appendix A.3 for Ed25519).
// Only the required members take part: crv, kty, x for OKP; crv, kty, x, y
// for EC; e, kty, n for RSA. Under the Web Bot Auth profile a key's kid is its thumbprint.
func JWKThumbprint(jwk JWK) (string, error) {
	// The required members, in lexicographic order, with no whitespace
	// (RFC 7638 §3.3). Struct fields marshal in declaration order.
	var members any
	switch jwk.Kty {
	case "OKP":
		if jwk.Crv == "" || jwk.X == "" {
			return "", errors.New("signing: incomplete OKP JWK")
		}
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{jwk.Crv, jwk.Kty, jwk.X}
	case "EC":
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return "", errors.New("signing: incomplete EC JWK")
		}
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{jwk.Crv, jwk.Kty, jwk.X, jwk.Y}
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return "", errors.New("signing: incomplete RSA JWK")
		}
		members = struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{jwk.E, jwk.Kty, jwk.N}
	default:
		return "", fmt.Errorf("signing: unsupported JWK kty %q", jwk.Kty)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(members); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return b64UrlEncodeRaw(sum[:]), nil
}

// PublicDirectoryKey returns the public JWK a Web Bot Auth key directory
// publishes for privateKey (ed25519.PrivateKey, a P-256 *ecdsa.PrivateKey, or
// an *rsa.PrivateKey of 2048 to 8192 bits, which signs with rsa-pss-sha512):
// kid set to the RFC 7638 thumbprint, use "sig", and no AdCP purpose member,
// since purpose belongs to the origin under the profile.
func PublicDirectoryKey(privateKey any) (JWK, error) {
	var jwk JWK
	switch k := privateKey.(type) {
	case ed25519.PrivateKey:
		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return JWK{}, errors.New("signing: invalid Ed25519 key")
		}
		jwk = JWK{Kty: "OKP", Crv: "Ed25519", X: b64UrlEncodeRaw(pub)}
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve == nil || k.Curve.Params().Name != "P-256" {
			return JWK{}, errors.New("signing: Web Bot Auth supports Ed25519 and P-256 keys")
		}
		x, y := pad32(k.X), pad32(k.Y)
		jwk = JWK{Kty: "EC", Crv: "P-256", X: b64UrlEncodeRaw(x), Y: b64UrlEncodeRaw(y)}
	case *rsa.PrivateKey:
		if k == nil || k.N.BitLen() < rsaMinModulus || k.N.BitLen() > rsaMaxModulus {
			return JWK{}, errors.New("signing: Web Bot Auth RSA keys are 2048 to 8192 bits")
		}
		jwk = JWK{Kty: "RSA", N: b64UrlEncodeRaw(k.N.Bytes()), E: b64UrlEncodeRaw(big.NewInt(int64(k.E)).Bytes())}
	default:
		return JWK{}, fmt.Errorf("signing: unsupported private key type %T", privateKey)
	}
	kid, err := JWKThumbprint(jwk)
	if err != nil {
		return JWK{}, err
	}
	jwk.Kid = kid
	jwk.Use = "sig"
	return jwk, nil
}

func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}
