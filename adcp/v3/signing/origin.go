package signing

import (
	"errors"
	"net/url"
	"strings"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/safefetch"
)

// CanonicalOrigin returns the canonical origin of rawURL: its scheme and
// authority after AdCP URL canonicalization steps 1 to 4 (lowercase scheme
// and host, one trailing DNS root dot removed, userinfo stripped, default
// port stripped), written scheme://authority with no path, query, or
// fragment. Only absolute http and https URLs have an origin; a URL the
// canonicalization rejects has none.
//
// Under the AdCP 3.3 Web Bot Auth profile an agent's identity is its
// canonical origin (docs/reference/url-canonicalization, Canonical origin).
// Like the rest of this package, it requires A-label (ASCII) hosts.
func CanonicalOrigin(rawURL string) (string, error) {
	canonical, err := canonicalTargetURI(rawURL)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(canonical)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("signing: an origin requires an absolute URL")
	}
	return u.Scheme + "://" + u.Host, nil
}

// webBotAuthOrigin validates a Signature-Agent value (or any URL naming a
// Web Bot Auth identity) and returns its canonical origin: HTTPS, no
// userinfo, no whitespace or control characters, and a host that passes the
// static SSRF rules. A path is permitted and discarded, as in the Python
// SDK; the identity is the origin.
func webBotAuthOrigin(rawURL string) (string, error) {
	for i := 0; i < len(rawURL); i++ {
		if rawURL[i] < 0x21 || rawURL[i] == 0x7f {
			return "", errors.New("signing: origin URL contains whitespace or a control character")
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.User != nil {
		return "", errors.New("signing: Web Bot Auth origins must not carry userinfo")
	}
	origin, err := CanonicalOrigin(rawURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(origin, "https://") {
		return "", errors.New("signing: Web Bot Auth origins require HTTPS")
	}
	if err := safefetch.ValidateTarget(origin + "/"); err != nil {
		return "", err
	}
	return origin, nil
}
