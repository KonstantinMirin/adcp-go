package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/strictjson"
)

const (
	directoryMaxBytes = 256 << 10
	directoryMaxKeys  = 100

	// DefaultDirectoryLifetime is how long SignKeyDirectory's signatures
	// stay valid when no lifetime is given.
	DefaultDirectoryLifetime = 24 * time.Hour

	// DirectorySkewAllowance is how far SignKeyDirectory and
	// DirectoryPublisher backdate created, because directory signature
	// verification allows no clock skew.
	DirectorySkewAllowance = 5 * time.Minute
)

// DirectoryResponse is a key directory HTTP response: the exact body bytes
// and the headers, including the per-key Signature-Input and Signature. A
// verifier keeps the signed response as its record of the fetch.
type DirectoryResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// VerifyDirectoryResponse validates a key directory served at origin and
// returns its usable keys indexed by RFC 7638 thumbprint. It checks:
//   - status 200, a body of at most 256 KiB, and a JWK Set media type
//     (application/http-message-signatures-directory+json,
//     application/jwk-set+json, or application/json);
//   - strict JSON with 1 to 100 keys and no private key material. Keys the
//     profile cannot use (other key types, use other than sig, key_ops
//     without verify) are skipped, at least one must remain, and a kid,
//     when present, does not affect lookup: a key is found by its
//     thumbprint, which the request's keyid must equal;
//   - when the response carries signatures (WBA Appendix B.1, RECOMMENDED):
//     Content-Digest against the body, and every signature tagged
//     http-message-signatures-directory, covering "@authority";req and
//     content-digest, inside its validity window with no clock skew, and
//     verifying under the key it names, each key at most once.
//
// An unsigned directory (a plain JWK Set) is accepted; DirectoryResolver
// can be configured to require signatures.
func VerifyDirectoryResponse(origin string, resp *DirectoryResponse, now time.Time) (map[string]JWK, error) {
	return verifyDirectoryResponse(origin, resp, now, false)
}

func verifyDirectoryResponse(origin string, resp *DirectoryResponse, now time.Time, requireSigned bool) (map[string]JWK, error) {
	origin, err := webBotAuthOrigin(origin)
	if err != nil {
		return nil, fmt.Errorf("signing: directory origin: %w", err)
	}
	if resp == nil || resp.Status != http.StatusOK || len(resp.Body) > directoryMaxBytes {
		return nil, errors.New("signing: invalid key directory response")
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get(contentTypeHeader))
	switch mediaType {
	case DirectoryMediaType, "application/jwk-set+json", "application/json":
	default:
		return nil, errors.New("signing: key directory has the wrong media type")
	}
	keys, err := parseDirectoryKeys(resp.Body)
	if err != nil {
		return nil, err
	}
	rawInput, rawSig := resp.Header.Get(signatureInputHeader), resp.Header.Get(signatureHeader)
	if rawInput == "" && rawSig == "" {
		if requireSigned {
			return nil, errors.New("signing: key directory is not signed")
		}
		return keys, nil
	}
	if !wbaDigestMatches(resp.Header.Get(contentDigestHeader), resp.Body) {
		return nil, errors.New("signing: key directory digest mismatch")
	}
	inputs, err := parseSFDictionary(rawInput)
	if err != nil || len(inputs) == 0 {
		return nil, errors.New("signing: key directory Signature-Input does not parse")
	}
	signatures, err := parseSFDictionary(rawSig)
	if err != nil {
		return nil, errors.New("signing: key directory Signature does not parse")
	}
	if !sameKeys(inputs.keys(), signatures.keys()) {
		return nil, errors.New("signing: key directory Signature and Signature-Input labels differ")
	}
	verified := map[string]struct{}{}
	for _, e := range inputs {
		m := e.member
		if tag, ok := stringParam(m.params, "tag"); !m.inner || !ok || tag != DirectoryTag {
			return nil, errors.New("signing: key directory signature has the wrong profile")
		}
		if err := wbaWindow(m, now.Unix(), true, e.key); err != nil {
			return nil, fmt.Errorf("signing: key directory signature: %w", err)
		}
		covered := map[string]struct{}{}
		for _, c := range m.list {
			covered[c.serialize()] = struct{}{}
		}
		_, a := covered[`"@authority";req`]
		_, d := covered[`"content-digest"`]
		if !a || !d {
			return nil, errors.New("signing: key directory signature does not bind authority and digest")
		}
		keyID, _ := stringParam(m.params, "keyid")
		jwk, ok := keys[keyID]
		if _, dup := verified[keyID]; !ok || dup {
			return nil, errors.New("signing: key directory signature key is absent or repeated")
		}
		base, err := wbaSignatureBase(http.MethodGet, origin+DirectoryPath, resp.Header, m, true)
		if err != nil {
			return nil, fmt.Errorf("signing: key directory signature base: %w", err)
		}
		sig, _ := signatures.get(e.key)
		if _, err := wbaVerifyCrypto(m, sig, jwk, base); err != nil {
			return nil, fmt.Errorf("signing: key directory signature: %w", err)
		}
		verified[keyID] = struct{}{}
	}
	return keys, nil
}

// directoryExpiry returns the earliest expires of a verified directory's
// signatures.
func directoryExpiry(resp *DirectoryResponse) (time.Time, bool) {
	inputs, err := parseSFDictionary(resp.Header.Get(signatureInputHeader))
	if err != nil || len(inputs) == 0 {
		return time.Time{}, false
	}
	var earliest int64
	for i, e := range inputs {
		exp, ok := intParam(e.member.params, "expires")
		if !ok {
			return time.Time{}, false
		}
		if i == 0 || exp < earliest {
			earliest = exp
		}
	}
	return time.Unix(earliest, 0), true
}

func parseDirectoryKeys(body []byte) (map[string]JWK, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := strictjson.Unmarshal(body, 0, &doc); err != nil {
		return nil, errors.New("signing: key directory is not strict JSON")
	}
	if len(doc.Keys) < 1 || len(doc.Keys) > directoryMaxKeys {
		return nil, errors.New("signing: key directory must hold 1 to 100 keys")
	}
	out := make(map[string]JWK, len(doc.Keys))
	for _, raw := range doc.Keys {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return nil, errors.New("signing: key directory entry is not an object")
		}
		// encoding/json matches struct fields case-insensitively, so match
		// private member names under case folding too.
		for name := range members {
			switch strictjson.Fold(name) {
			case strictjson.Fold("d"), strictjson.Fold("p"), strictjson.Fold("q"), strictjson.Fold("dp"), strictjson.Fold("dq"), strictjson.Fold("qi"), strictjson.Fold("k"):
				return nil, errors.New("signing: key directory entry carries private key material")
			}
		}
		if ops, ok := members["key_ops"]; ok {
			var list []string
			if json.Unmarshal(ops, &list) != nil {
				return nil, errors.New("signing: key directory key_ops is not a string array")
			}
		}
		var jwk JWK
		if err := json.Unmarshal(raw, &jwk); err != nil {
			return nil, errors.New("signing: key directory entry does not parse")
		}
		if _, err := wbaKeyAlgorithm(jwk); err != nil {
			// A key the profile cannot verify with: skip it, as a plain JWK
			// Set may hold keys for other uses.
			continue
		}
		tp, err := JWKThumbprint(jwk)
		if err != nil {
			continue
		}
		if _, dup := out[tp]; dup {
			return nil, errors.New("signing: key directory repeats a key")
		}
		jwk.Kid = tp
		out[tp] = jwk
	}
	if len(out) == 0 {
		return nil, errors.New("signing: key directory holds no usable key")
	}
	return out, nil
}

// SignKeyDirectory builds the signed key directory response an origin
// serves at DirectoryPath (WBA §5.5 and Appendix B.1). Each private key
// (ed25519.PrivateKey or P-256 *ecdsa.PrivateKey) is published as its
// PublicDirectoryKey and signs the response once, covering "@authority";req
// and content-digest. created is the signatures' created time (time.Now
// minus DirectorySkewAllowance when zero) and lifetime their validity from
// created (DefaultDirectoryLifetime when zero). Serve Body byte for byte
// with Header, and re-sign before the signatures expire; DirectoryPublisher
// does both.
func SignKeyDirectory(agentOrigin string, privateKeys []any, created time.Time, lifetime time.Duration) (*DirectoryResponse, error) {
	origin, err := webBotAuthOrigin(agentOrigin)
	if err != nil {
		return nil, err
	}
	if len(privateKeys) < 1 || len(privateKeys) > directoryMaxKeys {
		return nil, errors.New("signing: a key directory holds 1 to 100 keys")
	}
	if lifetime == 0 {
		lifetime = DefaultDirectoryLifetime
	}
	if lifetime < time.Second {
		return nil, errors.New("signing: directory lifetime must be positive")
	}
	if created.IsZero() {
		// Verifiers allow no clock skew on directory signatures, so a
		// verifier slightly behind would reject a just-signed directory and
		// cool down for 60 s. Backdate created to absorb skew.
		created = time.Now().Add(-DirectorySkewAllowance)
	}
	jwks := make([]JWK, len(privateKeys))
	seen := map[string]struct{}{}
	for i, k := range privateKeys {
		jwk, err := PublicDirectoryKey(k)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[jwk.Kid]; dup {
			return nil, errors.New("signing: directory keys must be distinct")
		}
		seen[jwk.Kid] = struct{}{}
		jwks[i] = jwk
	}
	body, err := json.Marshal(struct {
		Keys []JWK `json:"keys"`
	}{jwks})
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set(contentTypeHeader, DirectoryMediaType)
	header.Set(contentDigestHeader, computeSHA256DigestHeaderForEncoding(body, BinaryEncodingRFC8941))
	header.Set("Cache-Control", "max-age=300")
	var inputs, signatures sfDict
	for i, k := range privateKeys {
		alg, _ := wbaKeyAlgorithm(jwks[i])
		m := sfMember{inner: true, list: []sfItem{
			{value: sfStringItem(componentAuthority), params: []sfParam{{key: "req", value: sfTrue()}}},
			{value: sfStringItem(componentContentDigst)},
		}, params: []sfParam{
			{key: "created", value: sfIntItem(created.Unix())},
			{key: "expires", value: sfIntItem(created.Add(lifetime).Unix())},
			{key: "keyid", value: sfStringItem(jwks[i].Kid)},
			{key: "alg", value: sfStringItem(string(alg))},
			{key: "tag", value: sfStringItem(DirectoryTag)},
		}}
		base, err := wbaSignatureBase(http.MethodGet, origin+DirectoryPath, header, m, true)
		if err != nil {
			return nil, err
		}
		sig, err := signWithKey(k, []byte(base))
		if err != nil {
			return nil, err
		}
		label := "key" + strconv.Itoa(i+1)
		inputs = append(inputs, sfDictEntry{key: label, member: m})
		signatures = append(signatures, sfDictEntry{key: label, member: sfMember{item: sfItem{value: sfBare{kind: sfBinary, b: sig}}}})
	}
	header.Set(signatureInputHeader, inputs.serialize())
	header.Set(signatureHeader, signatures.serialize())
	return &DirectoryResponse{Status: http.StatusOK, Header: header, Body: body}, nil
}

// DirectoryPublisher is an http.Handler that serves an origin's signed key
// directory at DirectoryPath and re-signs it before its signatures expire.
// Mount it at DirectoryPath on the agent's origin.
type DirectoryPublisher struct {
	origin   string
	keys     []any
	lifetime time.Duration
	refresh  time.Duration
	clock    func() time.Time

	mu      sync.Mutex
	current *DirectoryResponse
	expires time.Time
}

// DirectoryPublisherOptions configures NewDirectoryPublisher.
type DirectoryPublisherOptions struct {
	// AgentOrigin is the origin the directory is served from.
	AgentOrigin string
	// PrivateKeys are the keys to publish (1 to 100). Publish a new key
	// before signing with it; verifiers cache directories for at most five
	// minutes.
	PrivateKeys []any
	// Lifetime is each signing's validity. Defaults to
	// DefaultDirectoryLifetime.
	Lifetime time.Duration
	// RefreshBefore is how long before expiry the publisher re-signs.
	// Defaults to half of Lifetime.
	RefreshBefore time.Duration
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// NewDirectoryPublisher signs the directory once to validate the options.
func NewDirectoryPublisher(opts DirectoryPublisherOptions) (*DirectoryPublisher, error) {
	p := &DirectoryPublisher{
		origin:   opts.AgentOrigin,
		keys:     append([]any(nil), opts.PrivateKeys...),
		lifetime: opts.Lifetime,
		refresh:  opts.RefreshBefore,
		clock:    opts.Clock,
	}
	if p.lifetime == 0 {
		p.lifetime = DefaultDirectoryLifetime
	}
	if p.refresh <= 0 || p.refresh >= p.lifetime {
		p.refresh = p.lifetime / 2
	}
	if p.clock == nil {
		p.clock = time.Now
	}
	if _, err := p.Current(); err != nil {
		return nil, err
	}
	return p, nil
}

// Current returns the signed response, re-signing when the current one is
// within RefreshBefore of expiring.
func (p *DirectoryPublisher) Current() (*DirectoryResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	if p.current != nil && now.Before(p.expires.Add(-p.refresh)) {
		return p.current, nil
	}
	created := now.Add(-DirectorySkewAllowance)
	resp, err := SignKeyDirectory(p.origin, p.keys, created, p.lifetime+DirectorySkewAllowance)
	if err != nil {
		return nil, err
	}
	p.current, p.expires = resp, now.Add(p.lifetime)
	return resp, nil
}

// ServeHTTP answers GET and HEAD with the current signed directory.
func (p *DirectoryPublisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := p.Current()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(resp.Body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(resp.Body)
	}
}
