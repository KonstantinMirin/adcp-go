package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WBASignOptions configures a Web Bot Auth signature. EXPERIMENTAL (AdCP
// 3.3).
type WBASignOptions struct {
	// AgentOrigin is the signer's identity, an HTTPS origin whose key
	// directory publishes the signing key. Required. A URL with a path is
	// reduced to its canonical origin.
	AgentOrigin string

	// Label is the signature label. Defaults to "sig1" for a first
	// signature. A relay signature needs a label not already in use.
	Label string

	// ValidityWindow is the signature lifetime, at most 300 s. Defaults to
	// 300 s.
	ValidityWindow time.Duration

	// Clock defaults to time.Now.
	Clock func() time.Time

	// CreatedOverride and NonceOverride are for tests and vectors only.
	CreatedOverride int64
	NonceOverride   string

	// NonceReader supplies nonce randomness. Defaults to crypto/rand.
	NonceReader io.Reader
}

// SignWebBotAuthRequest signs r under the opt-in Web Bot Auth profile. It
// sets Signature-Agent to the agent's origin under the label and covers it,
// sets tag="web-bot-auth", a 256-bit nonce, the key's RFC 7638 thumbprint
// as keyid, and an algorithm derived from the key. A request with a body
// must carry Content-Type; the signer sets Content-Digest and covers both.
// Signatures use RFC 8941 sf-binary (standard Base64).
//
// A request that already carries Signature, Signature-Input, or
// Signature-Agent is refused: use SignWebBotAuthRelay to add a signature.
func SignWebBotAuthRequest(r *http.Request, privateKey any, opts WBASignOptions) error {
	if r == nil {
		return errors.New("signing: nil request")
	}
	for _, name := range []string{signatureHeader, signatureInputHeader, signatureAgentHeader} {
		if len(r.Header.Values(name)) > 0 {
			return errors.New("signing: request is already signed; use SignWebBotAuthRelay to add a signature")
		}
	}
	if opts.Label == "" {
		opts.Label = "sig1"
	}
	return signWBA(r, privateKey, opts, nil, nil, nil)
}

// SignWebBotAuthRelay adds a relay's Web Bot Auth signature to a request
// that already carries web-bot-auth signatures. The relay signature covers
// the request components and every earlier signature's signature-agent,
// signature-input, and signature members, plus every component those
// signatures cover (WBA §5.2.2). The relay must not change any covered
// component or the body. opts.Label must be a label not already in use.
func SignWebBotAuthRelay(r *http.Request, privateKey any, opts WBASignOptions) error {
	if r == nil {
		return errors.New("signing: nil request")
	}
	if opts.Label == "" {
		return errors.New("signing: a relay signature needs an explicit, unused label")
	}
	inputs, err1 := parseSFDictionary(r.Header.Get(signatureInputHeader))
	signatures, err2 := parseSFDictionary(r.Header.Get(signatureHeader))
	agents, err3 := parseSFDictionary(r.Header.Get(signatureAgentHeader))
	if err1 != nil || err2 != nil || err3 != nil || !sameKeys(inputs.keys(), signatures.keys()) {
		return errors.New("signing: relay requires existing, well-formed Web Bot Auth signature fields")
	}
	if _, used := inputs.get(opts.Label); used {
		return errors.New("signing: relay label is already in use")
	}
	if _, used := agents.get(opts.Label); used {
		return errors.New("signing: relay label is already in use")
	}
	return signWBA(r, privateKey, opts, inputs, signatures, agents)
}

func signWBA(r *http.Request, privateKey any, opts WBASignOptions, inputs, signatures, agents sfDict) error {
	if !isValidLabel(opts.Label) {
		return fmt.Errorf("signing: invalid signature label %q", opts.Label)
	}
	origin, err := webBotAuthOrigin(opts.AgentOrigin)
	if err != nil {
		return fmt.Errorf("signing: agent origin: %w", err)
	}
	window := opts.ValidityWindow
	if window == 0 {
		window = time.Duration(wbaMaxWindowSeconds) * time.Second
	}
	if window <= 0 || window > time.Duration(wbaMaxWindowSeconds)*time.Second {
		return errors.New("signing: Web Bot Auth validity window must be in (0, 300s]")
	}
	if r.URL == nil || !r.URL.IsAbs() {
		return errors.New("signing: request URL must be absolute")
	}
	jwk, err := PublicDirectoryKey(privateKey)
	if err != nil {
		return err
	}
	alg, _ := wbaKeyAlgorithm(jwk)

	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("signing: read body: %w", err)
		}
		_ = r.Body.Close()
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	created := clock().Unix()
	if opts.CreatedOverride != 0 {
		created = opts.CreatedOverride
	}
	nonce := opts.NonceOverride
	if nonce == "" {
		reader := opts.NonceReader
		if reader == nil {
			reader = rand.Reader
		}
		var buf [32]byte
		if _, err := io.ReadFull(reader, buf[:]); err != nil {
			return fmt.Errorf("signing: generate nonce: %w", err)
		}
		nonce = b64UrlEncodeRaw(buf[:])
	}
	if len(nonce) < wbaMinNonceLen || len(nonce) > wbaMaxNonceLen {
		return errors.New("signing: nonce must carry at least 128 bits and be at most 256 characters")
	}

	// The signer's own headers.
	agents = append(agents, sfDictEntry{key: opts.Label, member: sfMember{item: sfItem{value: sfStringItem(origin)}}})
	staged := r.Header.Clone()
	staged.Set(signatureAgentHeader, agents.serialize())
	components := []sfItem{
		{value: sfStringItem(componentMethod)},
		{value: sfStringItem(componentTargetURI)},
		{value: sfStringItem(componentAuthority)},
	}
	if len(body) > 0 {
		if staged.Get(contentTypeHeader) == "" {
			return errors.New("signing: a Web Bot Auth request with a body requires Content-Type")
		}
		staged.Set(contentDigestHeader, computeSHA256DigestHeaderForEncoding(body, BinaryEncodingRFC8941))
		components = append(components, sfItem{value: sfStringItem(componentContentType)}, sfItem{value: sfStringItem(componentContentDigst)})
	}
	keyed := func(field, label string) sfItem {
		return sfItem{value: sfStringItem(field), params: []sfParam{{key: "key", value: sfStringItem(label)}}}
	}
	components = append(components, keyed("signature-agent", opts.Label))
	have := map[string]struct{}{}
	for _, c := range components {
		have[c.serialize()] = struct{}{}
	}
	add := func(c sfItem) {
		if _, ok := have[c.serialize()]; !ok {
			have[c.serialize()] = struct{}{}
			components = append(components, c)
		}
	}
	for _, e := range inputs {
		if tag, ok := stringParam(e.member.params, "tag"); !ok || tag != ProfileTagWebBotAuth {
			continue
		}
		add(keyed("signature-agent", e.key))
		add(keyed("signature-input", e.key))
		add(keyed("signature", e.key))
		for _, c := range e.member.list {
			add(c)
		}
	}
	member := sfMember{inner: true, list: components, params: []sfParam{
		{key: "created", value: sfIntItem(created)},
		{key: "expires", value: sfIntItem(created + int64(window/time.Second))},
		{key: "nonce", value: sfStringItem(nonce)},
		{key: "keyid", value: sfStringItem(jwk.Kid)},
		{key: "alg", value: sfStringItem(string(alg))},
		{key: "tag", value: sfStringItem(ProfileTagWebBotAuth)},
	}}
	if inputs != nil {
		staged.Set(signatureInputHeader, inputs.serialize())
		staged.Set(signatureHeader, signatures.serialize())
	}
	signURL := *r.URL
	if r.Host != "" {
		signURL.Host = r.Host
	}
	base, err := wbaSignatureBase(r.Method, signURL.String(), staged, member, false)
	if err != nil {
		return fmt.Errorf("signing: build Web Bot Auth signature base: %w", err)
	}
	sig, err := signWithKey(privateKey, []byte(base))
	if err != nil {
		return err
	}
	inputs = append(inputs, sfDictEntry{key: opts.Label, member: member})
	signatures = append(signatures, sfDictEntry{key: opts.Label, member: sfMember{item: sfItem{value: sfBare{kind: sfBinary, b: sig}}}})
	r.Header.Set(signatureAgentHeader, staged.Get(signatureAgentHeader))
	if len(body) > 0 {
		r.Header.Set(contentDigestHeader, staged.Get(contentDigestHeader))
	}
	r.Header.Set(signatureInputHeader, inputs.serialize())
	r.Header.Set(signatureHeader, signatures.serialize())
	return nil
}

// signWithKey signs base with an Ed25519 or P-256 private key, producing a
// raw Ed25519 signature or an IEEE P1363 (r||s) ECDSA signature.
func signWithKey(privateKey any, base []byte) ([]byte, error) {
	switch k := privateKey.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, base), nil
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve.Params().Name != "P-256" {
			return nil, errors.New("signing: unsupported ECDSA curve")
		}
		h := sha256.Sum256(base)
		rInt, sInt, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, err
		}
		return encodeP1363(rInt, sInt, 32), nil
	default:
		return nil, fmt.Errorf("signing: unsupported private key type %T", privateKey)
	}
}
