package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"math/big"
)

// AlgRSAPSSSHA512 is RFC 9421's rsa-pss-sha512 (RSASSA-PSS with SHA-512,
// MGF1 with SHA-512, and a 64-byte salt), the algorithm of the Web Bot Auth
// drafts' Appendix E test vectors. EXPERIMENTAL: the Web Bot Auth profile
// accepts it; the AdCP RFC 9421 profile does not.
const AlgRSAPSSSHA512 Algorithm = "rsa-pss-sha512"

const (
	jwkAlgPS512    = "PS512"
	rsaMinModulus  = 2048
	rsaMaxModulus  = 8192
	rsaMaxExponent = 1<<31 - 1
)

// rsaPublicKey decodes an RSA JWK, refusing moduli outside 2048 to 8192
// bits and exponents that are even, below 3, or beyond 31 bits.
func rsaPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	n, err := b64UrlDecode(jwk.N)
	if err != nil || len(n) == 0 || n[0] == 0 {
		return nil, errors.New("signing: invalid RSA modulus")
	}
	e, err := b64UrlDecode(jwk.E)
	if err != nil || len(e) == 0 || len(e) > 4 || e[0] == 0 {
		return nil, errors.New("signing: invalid RSA exponent")
	}
	mod := new(big.Int).SetBytes(n)
	if mod.BitLen() < rsaMinModulus || mod.BitLen() > rsaMaxModulus {
		return nil, errors.New("signing: RSA modulus size not allowed")
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > rsaMaxExponent || exp.Bit(0) == 0 {
		return nil, errors.New("signing: RSA exponent not allowed")
	}
	return &rsa.PublicKey{N: mod, E: int(exp.Int64())}, nil
}

func verifyRSAPSS(pub *rsa.PublicKey, base, sig []byte) bool {
	h := sha512.Sum512(base)
	return rsa.VerifyPSS(pub, crypto.SHA512, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}) == nil
}

func signRSAPSS(k *rsa.PrivateKey, base []byte) ([]byte, error) {
	if k.N.BitLen() < rsaMinModulus || k.N.BitLen() > rsaMaxModulus {
		return nil, errors.New("signing: RSA modulus size not allowed")
	}
	h := sha512.Sum512(base)
	return rsa.SignPSS(rand.Reader, k, crypto.SHA512, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512})
}

// verifyWithJWK verifies sig over base under a Web Bot Auth directory key
// with the algorithm wbaKeyAlgorithm derived for it.
func verifyWithJWK(alg Algorithm, jwk JWK, base, sig []byte) bool {
	if alg == AlgRSAPSSSHA512 {
		pub, err := rsaPublicKey(jwk)
		return err == nil && verifyRSAPSS(pub, base, sig)
	}
	pub, err := jwk.PublicKey()
	return err == nil && verifySignature(alg, pub, base, sig)
}
