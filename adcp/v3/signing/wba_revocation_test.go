package signing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ts(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func TestRevocationDetailsMergeAndExposure(t *testing.T) {
	early, late := ts("2026-04-17T09:00:00Z"), ts("2026-04-18T09:00:00Z")
	cases := []struct {
		name       string
		old, newer RevocationDetails
		want       RevocationDetails
	}{
		{"keyCompromise wins over a later weaker reason", RevocationDetails{Reason: RevocationReasonKeyCompromise}, RevocationDetails{Reason: RevocationReasonSuperseded}, RevocationDetails{Reason: RevocationReasonKeyCompromise}},
		{"keyCompromise upgrades an earlier reason", RevocationDetails{Reason: RevocationReasonSuperseded}, RevocationDetails{Reason: RevocationReasonKeyCompromise}, RevocationDetails{Reason: RevocationReasonKeyCompromise}},
		{"a reason is never withdrawn", RevocationDetails{Reason: RevocationReasonSuperseded}, RevocationDetails{}, RevocationDetails{Reason: RevocationReasonSuperseded}},
		{"the earliest invalidity date wins", RevocationDetails{InvalidityDate: late}, RevocationDetails{InvalidityDate: early}, RevocationDetails{InvalidityDate: early}},
		{"a date is never withdrawn", RevocationDetails{InvalidityDate: early}, RevocationDetails{InvalidityDate: late}, RevocationDetails{InvalidityDate: early}},
		{"a date is added", RevocationDetails{}, RevocationDetails{InvalidityDate: late}, RevocationDetails{InvalidityDate: late}},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, tc.old.Merge(tc.newer), tc.name)
	}
	compromised := RevocationDetails{Reason: RevocationReasonKeyCompromise, InvalidityDate: early}
	require.False(t, compromised.Exposes(early.Add(-time.Second)))
	require.True(t, compromised.Exposes(*early))
	require.True(t, compromised.Exposes(late.Add(time.Hour)))
	require.True(t, RevocationDetails{Reason: RevocationReasonKeyCompromise}.Exposes(time.Unix(0, 0)), "no date: any time")
	require.False(t, RevocationDetails{Reason: RevocationReasonSuperseded}.Exposes(*late))
	require.False(t, RevocationDetails{}.Exposes(*late))
}

func TestParseRevocationList(t *testing.T) {
	issuer := "https://gov.example.com"
	base := func(extra string) string {
		return `{"version":1,"issuer":"https://gov.example.com","updated":"2026-04-18T14:00:00Z","next_update":"2026-04-18T14:15:00Z","revoked_kids":["k1","k2"]` + extra + `}`
	}
	l, err := ParseRevocationList([]byte(base(`,"revocation_details":{"k1":{"reason":"keyCompromise","invalidity_date":"2026-04-17T09:00:00Z"},"k2":{"reason":"superseded"}}`)), issuer)
	require.NoError(t, err)
	require.True(t, l.IsRevoked("k1"))
	require.False(t, l.IsRevoked("k3"))
	require.Equal(t, RevocationReasonKeyCompromise, l.Details["k1"].Reason)
	require.Equal(t, *ts("2026-04-17T09:00:00Z"), *l.Details["k1"].InvalidityDate)
	require.Nil(t, l.Details["k2"].InvalidityDate)

	// The issuer compares by canonical origin.
	_, err = ParseRevocationList([]byte(strings.Replace(base(""), `"https://gov.example.com"`, `"HTTPS://Gov.Example.com:443/"`, 1)), issuer)
	require.NoError(t, err)

	for name, doc := range map[string]string{
		"detail for an unrevoked kid":  base(`,"revocation_details":{"k9":{"reason":"superseded"}}`),
		"unknown reason":               base(`,"revocation_details":{"k1":{"reason":"oops"}}`),
		"date without a timezone":      base(`,"revocation_details":{"k1":{"invalidity_date":"2026-04-17T09:00:00"}}`),
		"detail is not an object":      base(`,"revocation_details":{"k1":"keyCompromise"}`),
		"other issuer":                 strings.Replace(base(""), "gov.example.com", "evil.example.com", 1),
		"issuer with userinfo":         strings.Replace(base(""), "https://gov", "https://u@gov", 1),
		"cadence below the 60 s floor": strings.Replace(base(""), "14:15:00Z", "14:00:30Z", 1),
		"missing version":              strings.Replace(base(""), `"version":1,`, ``, 1),
		"zero version":                 strings.Replace(base(""), `"version":1`, `"version":0`, 1),
		"kids not strings":             strings.Replace(base(""), `["k1","k2"]`, `[1]`, 1),
		"duplicate JSON key":           strings.Replace(base(""), `"version":1`, `"version":1,"version":2`, 1),
		"bad timestamp":                strings.Replace(base(""), "2026-04-18T14:00:00Z", "yesterday", 1),
	} {
		_, err := ParseRevocationList([]byte(doc), issuer)
		require.Error(t, err, name)
	}
}

// TestRevocationListRetainNeverUnrevokes: revocations are monotonic.
func TestRevocationListRetainNeverUnrevokes(t *testing.T) {
	issuer := "https://gov.example.com"
	old, err := ParseRevocationList([]byte(`{"version":1,"issuer":"https://gov.example.com","updated":"2026-04-18T14:00:00Z","next_update":"2026-04-18T14:15:00Z","revoked_kids":["k1"],"revoked_jtis":["j1"],"revocation_details":{"k1":{"reason":"keyCompromise","invalidity_date":"2026-04-17T09:00:00Z"}}}`), issuer)
	require.NoError(t, err)
	newer, err := ParseRevocationList([]byte(`{"version":1,"issuer":"https://gov.example.com","updated":"2026-04-18T14:15:00Z","next_update":"2026-04-18T14:30:00Z","revoked_kids":["k2"],"revocation_details":{}}`), issuer)
	require.NoError(t, err)
	require.NoError(t, newer.Retain(old))
	require.True(t, newer.IsRevoked("k1"), "a revocation is never withdrawn")
	require.True(t, newer.IsRevoked("k2"))
	require.Contains(t, newer.RevokedJTIs, "j1")
	require.Equal(t, RevocationReasonKeyCompromise, newer.Details["k1"].Reason)
	other := &RevocationList{Issuer: "https://other.example.com"}
	require.Error(t, newer.Retain(other))
}

func TestVerifyRevocationJWSSerializations(t *testing.T) {
	key := newEd25519(t)
	jwk, _ := PublicDirectoryKey(key)
	resolve := func(kid string) (*JWK, error) {
		if kid == jwk.Kid {
			k := jwk
			return &k, nil
		}
		return nil, nil
	}
	payload := []byte(`{"version":1}`)
	header := map[string]any{"alg": "EdDSA", "typ": RevocationListTyp, "kid": jwk.Kid}
	prot, pay, sig := signJWS(t, key, header, payload)
	general, _ := json.Marshal(map[string]any{"payload": pay, "signatures": []map[string]string{{"protected": prot, "signature": sig}}})
	flattened, _ := json.Marshal(map[string]any{"payload": pay, "protected": prot, "signature": sig})
	for name, body := range map[string][]byte{"compact": []byte(prot + "." + pay + "." + sig), "general": general, "flattened": flattened} {
		got, err := verifyRevocationJWS(body, resolve)
		require.NoError(t, err, name)
		require.Equal(t, payload, got, name)
	}
	mk := func(h map[string]any) []byte {
		p, pl, s := signJWS(t, key, h, payload)
		return []byte(p + "." + pl + "." + s)
	}
	ambiguous, _ := json.Marshal(map[string]any{"payload": pay, "protected": prot, "signature": sig, "signatures": []map[string]string{{"protected": prot, "signature": sig}}})
	twoSigs, _ := json.Marshal(map[string]any{"payload": pay, "signatures": []map[string]string{{"protected": prot, "signature": sig}, {"protected": prot, "signature": sig}}})
	tampered := []byte(prot + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"version":2}`)) + "." + sig)
	for name, body := range map[string][]byte{
		"wrong typ":      mk(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": jwk.Kid}),
		"alg none":       mk(map[string]any{"alg": "none", "typ": RevocationListTyp, "kid": jwk.Kid}),
		"alg mismatch":   mk(map[string]any{"alg": "ES256", "typ": RevocationListTyp, "kid": jwk.Kid}),
		"crit":           mk(map[string]any{"alg": "EdDSA", "typ": RevocationListTyp, "kid": jwk.Kid, "crit": []string{"b64"}}),
		"no kid":         mk(map[string]any{"alg": "EdDSA", "typ": RevocationListTyp}),
		"unknown kid":    mk(map[string]any{"alg": "EdDSA", "typ": RevocationListTyp, "kid": "someone-else"}),
		"tampered":       tampered,
		"ambiguous JSON": ambiguous,
		"two signatures": twoSigs,
		"not a JWS":      []byte("hello"),
		"empty segment":  []byte(prot + ".." + sig),
	} {
		_, err := verifyRevocationJWS(body, resolve)
		require.Error(t, err, name)
	}
}

func TestOriginRevocationCheckerLifecycle(t *testing.T) {
	now := wbaTestNow
	clock := func() time.Time { return now }
	rig := newWBARig(t)
	rig.resolver = NewDirectoryResolver(DirectoryResolverOptions{Fetch: rig.dirs.fetch, Clock: clock})
	checker, err := NewOriginRevocationChecker(OriginRevocationCheckerOptions{Keys: rig.resolver, Fetch: rig.revs.fetch, Clock: clock})
	require.NoError(t, err)
	ctx := context.Background()
	jwk, _ := PublicDirectoryKey(rig.key)
	updated := now.Add(-time.Minute)
	rig.revs.set(t, revocationPayload{Updated: rfc3339(updated), NextUpdate: rfc3339(updated.Add(5 * time.Minute)), RevokedKids: []string{"old-kid"},
		Details: map[string]map[string]string{"old-kid": {"reason": "keyCompromise", "invalidity_date": "2026-01-01T00:00:00Z"}}})

	revoked, err := checker.RevokedWBAKey(ctx, rig.origin, jwk.Kid)
	require.NoError(t, err)
	require.False(t, revoked)
	revoked, err = checker.RevokedWBAKey(ctx, rig.origin, "old-kid")
	require.NoError(t, err)
	require.True(t, revoked)
	require.Equal(t, 1, rig.revs.fetches, "served from cache before next_update")
	d, ok := checker.Details(rig.origin, "old-kid")
	require.True(t, ok)
	require.True(t, d.Exposes(now))

	// After next_update the checker refreshes. The new list drops old-kid
	// and weakens its reason; neither sticks.
	now = now.Add(5 * time.Minute)
	updated = now.Add(-10 * time.Second)
	rig.revs.set(t, revocationPayload{Updated: rfc3339(updated), NextUpdate: rfc3339(updated.Add(5 * time.Minute)), RevokedKids: []string{jwk.Kid},
		Details: map[string]map[string]string{jwk.Kid: {"reason": "superseded"}}})
	revoked, err = checker.RevokedWBAKey(ctx, rig.origin, "old-kid")
	require.NoError(t, err)
	require.True(t, revoked, "an origin cannot un-revoke a key")
	revoked, _ = checker.RevokedWBAKey(ctx, rig.origin, jwk.Kid)
	require.True(t, revoked)
	d, _ = checker.Details(rig.origin, "old-kid")
	require.Equal(t, RevocationReasonKeyCompromise, d.Reason)
	require.ElementsMatch(t, []string{"old-kid", jwk.Kid}, checker.RevokedKids(rig.origin))
	require.True(t, slices.IsSorted(checker.RevokedKids(rig.origin)))

	// A list older than the cached one is refused (no rollback); within
	// grace the cached list still serves, past grace checks fail closed.
	now = now.Add(5 * time.Minute)
	rig.revs.set(t, revocationPayload{Updated: rfc3339(updated.Add(-time.Hour)), NextUpdate: rfc3339(now.Add(time.Hour))})
	revoked, err = checker.RevokedWBAKey(ctx, rig.origin, jwk.Kid)
	require.NoError(t, err)
	require.True(t, revoked)
	now = now.Add(11 * time.Minute) // past next_update + 2 x 5 min
	_, err = checker.RevokedWBAKey(ctx, rig.origin, jwk.Kid)
	requireWBAStatus(t, err, http.StatusForbidden)
	require.Equal(t, `"v1"`, rig.revs.lastINM, "refreshes are conditional")
}

func TestOriginRevocationCheckerNotModifiedDoesNotExtend(t *testing.T) {
	now := wbaTestNow
	clock := func() time.Time { return now }
	rig := newWBARig(t)
	rig.resolver = NewDirectoryResolver(DirectoryResolverOptions{Fetch: rig.dirs.fetch, Clock: clock})
	checker, _ := NewOriginRevocationChecker(OriginRevocationCheckerOptions{Keys: rig.resolver, Fetch: rig.revs.fetch, Clock: clock})
	updated := now.Add(-time.Minute)
	rig.revs.set(t, revocationPayload{Updated: rfc3339(updated), NextUpdate: rfc3339(updated.Add(2 * time.Minute))})
	_, err := checker.RevokedWBAKey(context.Background(), rig.origin, "k")
	require.NoError(t, err)
	rig.revs.mu.Lock()
	rig.revs.status = http.StatusNotModified
	rig.revs.mu.Unlock()
	for range 6 { // 304 every minute; never extends signed freshness
		now = now.Add(time.Minute + time.Second)
		_, err = checker.RevokedWBAKey(context.Background(), rig.origin, "k")
	}
	requireWBAStatus(t, err, http.StatusForbidden)
}

func TestOriginRevocationCheckerAdmission(t *testing.T) {
	now := wbaTestNow
	clock := func() time.Time { return now }
	dirs := newFakeDirectories()
	resolver := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: clock})
	servers := map[string]*revocationServer{}
	fetch := func(ctx context.Context, url, inm, ims string) (*RevocationFetchResult, error) {
		origin := strings.TrimSuffix(url, RevocationListPath)
		s := servers[origin]
		if s == nil {
			return &RevocationFetchResult{Status: http.StatusNotFound}, nil
		}
		return s.fetch(ctx, url, inm, ims)
	}
	publish := func(origin string) {
		key := newEd25519(t)
		dirs.publish(t, origin, now.Add(-time.Minute), time.Hour, key)
		s := newRevocationServer(t, origin, key)
		s.set(t, revocationPayload{Updated: rfc3339(now.Add(-time.Minute)), NextUpdate: rfc3339(now.Add(30 * time.Minute))})
		servers[origin] = s
	}
	checker, _ := NewOriginRevocationChecker(OriginRevocationCheckerOptions{Keys: resolver, Fetch: fetch, Clock: clock, MaxOrigins: 3, MaxOriginsPerOperator: 2})
	ctx := context.Background()

	// A failed first discovery (no list published) costs a cooldown, not an
	// admission slot.
	for range 5 {
		_, err := checker.RevokedWBAKey(ctx, "https://missing.example.net", "k")
		requireWBAStatus(t, err, http.StatusForbidden)
	}
	publish("https://a.example.com")
	publish("https://b.example.com")
	publish("https://c.example.com")
	publish("https://d.example.org")
	publish("https://e.example.org")
	for _, o := range []string{"https://a.example.com", "https://b.example.com"} {
		_, err := checker.RevokedWBAKey(ctx, o, "k")
		require.NoError(t, err)
	}
	// One operator cannot take more than its quota.
	_, err := checker.RevokedWBAKey(ctx, "https://c.example.com", "k")
	requireWBAStatus(t, err, http.StatusTooManyRequests)
	// Other operators still get room, up to the global cap.
	_, err = checker.RevokedWBAKey(ctx, "https://d.example.org", "k")
	require.NoError(t, err)
	_, err = checker.RevokedWBAKey(ctx, "https://e.example.org", "k")
	requireWBAStatus(t, err, http.StatusTooManyRequests)

	// The cooldown expires, and a now-published list is admitted... once
	// capacity allows.
	publish("https://missing.example.net")
	now = now.Add(61 * time.Second)
	_, err = checker.RevokedWBAKey(ctx, "https://missing.example.net", "k")
	requireWBAStatus(t, err, http.StatusTooManyRequests)

	// A list signed by a key outside the origin's directory is refused.
	dirs2 := newFakeDirectories()
	key := newEd25519(t)
	dirs2.publish(t, "https://x.example.com", now.Add(-time.Minute), time.Hour, key)
	s := newRevocationServer(t, "https://x.example.com", newEd25519(t))
	s.set(t, revocationPayload{Updated: rfc3339(now.Add(-time.Minute)), NextUpdate: rfc3339(now.Add(30 * time.Minute))})
	c2, _ := NewOriginRevocationChecker(OriginRevocationCheckerOptions{Keys: NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs2.fetch, Clock: clock}), Fetch: s.fetch, Clock: clock})
	_, err = c2.RevokedWBAKey(ctx, "https://x.example.com", "k")
	requireWBAStatus(t, err, http.StatusForbidden)

	_, err = NewOriginRevocationChecker(OriginRevocationCheckerOptions{})
	require.Error(t, err)
}
