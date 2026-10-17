package signing

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"math"
	"math/big"

	jose "github.com/go-jose/go-jose/v4"
)

// JWKThumbprint returns the RFC 7638 SHA-256 thumbprint of jwk's public key,
// base64url-encoded without padding (RFC 8037 Appendix A.3 for Ed25519).
// Only the required members take part: crv, kty, x for OKP; crv, kty, x, y
// for EC; e, kty, n for RSA. Under the Web Bot Auth profile a key's kid is its thumbprint.
//
// go-jose computes the thumbprint from the decoded key, so jwk must be a key
// go-jose can represent: Ed25519, an EC key on P-256, P-384 or P-521, or RSA.
// The members enter the hash in their RFC 7518 form (unpadded base64url,
// full-length EC coordinates, minimal RSA integers), so a JWK spelled
// non-canonically (padded, or an RSA integer with leading zero bytes) has
// the thumbprint of its canonical spelling. Web Bot Auth refuses such
// spellings before thumbprinting (wbaKeyAlgorithm), so one key has one kid.
func JWKThumbprint(jwk JWK) (string, error) {
	var pub any
	switch jwk.Kty {
	case "OKP", "EC":
		if jwk.Crv == "" || jwk.X == "" || (jwk.Kty == "EC" && jwk.Y == "") {
			return "", fmt.Errorf("signing: incomplete %s JWK", jwk.Kty)
		}
		key, err := jwk.joseKey("")
		if err != nil {
			return "", fmt.Errorf("signing: unsupported %s JWK", jwk.Kty)
		}
		pub = key.Key
	case "RSA":
		// go-jose's JWK decoder refuses moduli over jose.MaxRSAModulusBits
		// (4096, a process-wide setting), and Web Bot Auth admits RSA keys
		// up to 8192 bits, so n and e are decoded here. The thumbprint
		// itself is still go-jose's.
		if jwk.N == "" || jwk.E == "" {
			return "", errors.New("signing: incomplete RSA JWK")
		}
		n, err := b64UrlDecode(jwk.N)
		mod := new(big.Int).SetBytes(n)
		if err != nil || mod.Sign() <= 0 {
			return "", errors.New("signing: invalid RSA modulus")
		}
		e, err := b64UrlDecode(jwk.E)
		exp := new(big.Int).SetBytes(e)
		if err != nil || exp.Sign() <= 0 || !exp.IsInt64() || exp.Int64() > math.MaxInt {
			return "", errors.New("signing: invalid RSA exponent")
		}
		pub = &rsa.PublicKey{N: mod, E: int(exp.Int64())}
	default:
		return "", fmt.Errorf("signing: unsupported JWK kty %q", jwk.Kty)
	}
	sum, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("signing: unsupported %s JWK", jwk.Kty)
	}
	return b64UrlEncodeRaw(sum), nil
}

// PublicDirectoryKey returns the public JWK a Web Bot Auth key directory
// publishes for privateKey (ed25519.PrivateKey, which signs with ed25519, or
// an *rsa.PrivateKey of 2048 to 8192 bits, which signs with rsa-pss-sha512;
// the profile admits no other algorithm, so a P-256 key is refused):
// kid set to the RFC 7638 thumbprint, use "sig", and no AdCP purpose member,
// since purpose belongs to the origin under the profile.
func PublicDirectoryKey(privateKey any) (JWK, error) {
	var pub any
	switch k := privateKey.(type) {
	case ed25519.PrivateKey:
		p, ok := k.Public().(ed25519.PublicKey)
		if !ok || len(p) != ed25519.PublicKeySize {
			return JWK{}, errors.New("signing: invalid Ed25519 key")
		}
		pub = p
	case *rsa.PrivateKey:
		if k == nil || k.N.BitLen() < rsaMinModulus || k.N.BitLen() > rsaMaxModulus {
			return JWK{}, errors.New("signing: Web Bot Auth RSA keys are 2048 to 8192 bits")
		}
		pub = &k.PublicKey
	default:
		return JWK{}, fmt.Errorf("signing: Web Bot Auth keys are Ed25519 or RSA, not %T", privateKey)
	}
	jwk, err := jwkFromPublicKey(pub)
	if err != nil {
		return JWK{}, errors.New("signing: cannot encode the public key")
	}
	kid, err := JWKThumbprint(jwk)
	if err != nil {
		return JWK{}, err
	}
	jwk.Kid = kid
	jwk.Use = "sig"
	return jwk, nil
}
