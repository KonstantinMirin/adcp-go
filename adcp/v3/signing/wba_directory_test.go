package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSignKeyDirectoryRoundTrip(t *testing.T) {
	keys := []any{newEd25519(t), newP256(t)}
	resp, err := SignKeyDirectory("https://buyer.example.com/agent", keys, wbaTestNow, time.Hour)
	require.NoError(t, err)
	require.Equal(t, DirectoryMediaType, resp.Header.Get("Content-Type"))
	require.Equal(t, "max-age=300", resp.Header.Get("Cache-Control"))
	require.NotContains(t, string(resp.Body), `"d"`)
	got, err := VerifyDirectoryResponse("https://buyer.example.com", resp, wbaTestNow)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, k := range keys {
		jwk, _ := PublicDirectoryKey(k)
		require.Contains(t, got, jwk.Kid)
	}
	in, _ := parseSFDictionary(resp.Header.Get("Signature-Input"))
	require.Equal(t, []string{"key1", "key2"}, in.keys())

	_, err = SignKeyDirectory("https://buyer.example.com", nil, wbaTestNow, time.Hour)
	require.Error(t, err)
	k := newEd25519(t)
	_, err = SignKeyDirectory("https://buyer.example.com", []any{k, k}, wbaTestNow, time.Hour)
	require.Error(t, err, "duplicate keys")
	_, err = SignKeyDirectory("http://buyer.example.com", []any{k}, wbaTestNow, time.Hour)
	require.Error(t, err)
}

func TestVerifyDirectoryResponseRejectsTampering(t *testing.T) {
	origin := "https://buyer.example.com"
	keyA, keyB := newEd25519(t), newEd25519(t)
	fresh := func() *DirectoryResponse {
		resp, err := SignKeyDirectory(origin, []any{keyA, keyB}, wbaTestNow.Add(-time.Minute), time.Hour)
		require.NoError(t, err)
		return resp
	}
	resign := func(resp *DirectoryResponse, body []byte) {
		resp.Body = body
		resp.Header.Set("Content-Digest", computeSHA256DigestHeaderForEncoding(body, BinaryEncodingRFC8941))
	}
	cases := []struct {
		name   string
		mutate func(*DirectoryResponse)
		origin string
		now    time.Time
	}{
		{"body changed", func(r *DirectoryResponse) { r.Body = []byte(strings.Replace(string(r.Body), `"sig"`, `"enc"`, 1)) }, origin, wbaTestNow},
		{"body and digest changed", func(r *DirectoryResponse) {
			var doc struct{ Keys []JWK }
			_ = json.Unmarshal(r.Body, &doc)
			doc.Keys = doc.Keys[:1]
			b, _ := json.Marshal(doc)
			resign(r, b)
		}, origin, wbaTestNow},
		{"one key unsigned", func(r *DirectoryResponse) {
			r.Header.Set("Signature-Input", strings.SplitN(r.Header.Get("Signature-Input"), ", key2=", 2)[0])
			r.Header.Set("Signature", strings.SplitN(r.Header.Get("Signature"), ", key2=", 2)[0])
		}, origin, wbaTestNow},
		{"signature labels differ", func(r *DirectoryResponse) {
			r.Header.Set("Signature", strings.Replace(r.Header.Get("Signature"), "key2=", "key9=", 1))
		}, origin, wbaTestNow},
		{"wrong media type", func(r *DirectoryResponse) { r.Header.Set("Content-Type", "application/json") }, origin, wbaTestNow},
		{"not 200", func(r *DirectoryResponse) { r.Status = http.StatusNotModified }, origin, wbaTestNow},
		{"oversized", func(r *DirectoryResponse) { r.Body = make([]byte, directoryMaxBytes+1) }, origin, wbaTestNow},
		{"served for another origin", func(*DirectoryResponse) {}, "https://evil.example.com", wbaTestNow},
		{"signatures expired", func(*DirectoryResponse) {}, origin, wbaTestNow.Add(2 * time.Hour)},
		{"signatures created in the future (no skew)", func(*DirectoryResponse) {}, origin, wbaTestNow.Add(-2 * time.Minute)},
		{"wrong tag", func(r *DirectoryResponse) {
			r.Header.Set("Signature-Input", strings.ReplaceAll(r.Header.Get("Signature-Input"), DirectoryTag, ProfileTagWebBotAuth))
		}, origin, wbaTestNow},
		{"authority not covered", func(r *DirectoryResponse) {
			r.Header.Set("Signature-Input", strings.ReplaceAll(r.Header.Get("Signature-Input"), `"@authority";req `, ``))
		}, origin, wbaTestNow},
		{"private key member", func(r *DirectoryResponse) {
			resign(r, []byte(strings.Replace(string(r.Body), `"use":"sig"`, `"use":"sig","d":"AAAA"`, 1)))
		}, origin, wbaTestNow},
		{"kid is not the thumbprint", func(r *DirectoryResponse) {
			var doc struct{ Keys []JWK }
			_ = json.Unmarshal(r.Body, &doc)
			doc.Keys[0].Kid = "operator-chosen"
			b, _ := json.Marshal(doc)
			resign(r, b)
		}, origin, wbaTestNow},
		{"duplicate JSON key", func(r *DirectoryResponse) {
			resign(r, []byte(`{"keys":[],"keys":[]}`))
		}, origin, wbaTestNow},
		{"no keys", func(r *DirectoryResponse) { resign(r, []byte(`{"keys":[]}`)) }, origin, wbaTestNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := fresh()
			tc.mutate(resp)
			_, err := VerifyDirectoryResponse(tc.origin, resp, tc.now)
			require.Error(t, err)
		})
	}
	_, err := VerifyDirectoryResponse(origin, fresh(), wbaTestNow)
	require.NoError(t, err)
}

func TestDirectoryPublisherResigns(t *testing.T) {
	now := wbaTestNow
	clock := func() time.Time { return now }
	key := newEd25519(t)
	p, err := NewDirectoryPublisher(DirectoryPublisherOptions{AgentOrigin: "https://buyer.example.com", PrivateKeys: []any{key}, Lifetime: time.Hour, Clock: clock})
	require.NoError(t, err)
	first, _ := p.Current()
	now = now.Add(20 * time.Minute)
	same, _ := p.Current()
	require.Same(t, first, same)
	now = now.Add(15 * time.Minute) // past half the lifetime
	next, _ := p.Current()
	require.NotSame(t, first, next)
	_, err = VerifyDirectoryResponse("https://buyer.example.com", next, now)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://buyer.example.com"+DirectoryPath, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, DirectoryMediaType, rec.Header().Get("Content-Type"))
	served := &DirectoryResponse{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
	_, err = VerifyDirectoryResponse("https://buyer.example.com", served, now)
	require.NoError(t, err)

	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "https://buyer.example.com"+DirectoryPath, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Zero(t, rec.Body.Len())
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://buyer.example.com"+DirectoryPath, nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	_, err = NewDirectoryPublisher(DirectoryPublisherOptions{AgentOrigin: "https://buyer.example.com"})
	require.Error(t, err)
}

func TestDirectoryResolverCaching(t *testing.T) {
	now := wbaTestNow
	clock := func() time.Time { return now }
	dirs := newFakeDirectories()
	origin := "https://buyer.example.com"
	key := newEd25519(t)
	jwk, _ := PublicDirectoryKey(key)
	dirs.publish(t, origin, now.Add(-time.Minute), 2*time.Minute, key) // expires in 1 minute
	d := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: clock})
	ctx := context.Background()

	got, err := d.ResolveWBAKey(ctx, origin, jwk.Kid)
	require.NoError(t, err)
	require.Equal(t, jwk.X, got.X)
	// A miss in a fresh directory is absent, with no refetch.
	got, err = d.ResolveWBAKey(ctx, origin, "unknown-kid")
	require.NoError(t, err)
	require.Nil(t, got)
	// The same origin spelled differently shares the cache.
	_, err = d.ResolveWBAKey(ctx, "https://BUYER.example.com:443/x", jwk.Kid)
	require.NoError(t, err)
	require.Equal(t, 1, dirs.count(origin))
	require.NotNil(t, d.Evidence(origin))

	// The cache never outlives the directory signatures (1 minute here,
	// under the 5-minute cap).
	now = now.Add(61 * time.Second)
	dirs.publish(t, origin, now.Add(-time.Minute), time.Hour, key)
	_, err = d.ResolveWBAKey(ctx, origin, jwk.Kid)
	require.NoError(t, err)
	require.Equal(t, 2, dirs.count(origin))
	// Then at most five minutes.
	now = now.Add(4 * time.Minute)
	_, _ = d.ResolveWBAKey(ctx, origin, jwk.Kid)
	require.Equal(t, 2, dirs.count(origin))
	now = now.Add(time.Minute + time.Second)
	_, _ = d.ResolveWBAKey(ctx, origin, jwk.Kid)
	require.Equal(t, 3, dirs.count(origin))
}

func TestDirectoryResolverOutageCoolsDown(t *testing.T) {
	now := wbaTestNow
	clock := func() time.Time { return now }
	dirs := newFakeDirectories()
	origin := "https://buyer.example.com"
	key := newEd25519(t)
	jwk, _ := PublicDirectoryKey(key)
	dirs.publish(t, origin, now.Add(-time.Minute), 2*time.Minute, key)
	d := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: clock})
	ctx := context.Background()
	_, err := d.ResolveWBAKey(ctx, origin, jwk.Kid)
	require.NoError(t, err)

	// The directory expires and the origin goes down: a failure is not
	// evidence of removal, but expired keys never authenticate.
	now = now.Add(2 * time.Minute)
	dirs.fail(origin, errors.New("connection reset"))
	_, err = d.ResolveWBAKey(ctx, origin, jwk.Kid)
	requireWBAStatus(t, err, http.StatusServiceUnavailable)
	require.True(t, IsIdentityUnavailable(err))
	require.NotNil(t, d.Evidence(origin), "the previous signed snapshot is kept as evidence")
	// Cooldown: no refetch within 60 s, and the cooldown keeps the kind.
	_, err = d.ResolveWBAKey(ctx, origin, jwk.Kid)
	requireWBAStatus(t, err, http.StatusServiceUnavailable)
	require.Equal(t, 2, dirs.count(origin))
	now = now.Add(61 * time.Second)
	dirs.publish(t, origin, now.Add(-time.Minute), time.Hour, key)
	_, err = d.ResolveWBAKey(ctx, origin, jwk.Kid)
	require.NoError(t, err)
	require.Equal(t, 3, dirs.count(origin))
}

func TestDirectoryResolverCoalescesPerOrigin(t *testing.T) {
	dirs := newFakeDirectories()
	slow, fast := "https://slow.example.com", "https://fast.example.com"
	slowKey, fastKey := newEd25519(t), newEd25519(t)
	dirs.publish(t, slow, wbaTestNow.Add(-time.Minute), time.Hour, slowKey)
	dirs.publish(t, fast, wbaTestNow.Add(-time.Minute), time.Hour, fastKey)
	release := make(chan struct{})
	dirs.block[slow] = release
	d := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: wbaClock})
	slowJWK, _ := PublicDirectoryKey(slowKey)
	fastJWK, _ := PublicDirectoryKey(fastKey)

	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := d.ResolveWBAKey(context.Background(), slow, slowJWK.Kid)
			if err == nil && k == nil {
				err = errors.New("missing key")
			}
			errs <- err
		}()
	}
	// A waiter that gives up does not cancel discovery for the others.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.ResolveWBAKey(ctx, slow, slowJWK.Kid)
	require.ErrorIs(t, err, context.Canceled)
	// A slow origin does not block another origin.
	k, err := d.ResolveWBAKey(context.Background(), fast, fastJWK.Kid)
	require.NoError(t, err)
	require.NotNil(t, k)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, dirs.count(slow), "concurrent lookups share one fetch")
}

func TestDirectoryResolverBounds(t *testing.T) {
	dirs := newFakeDirectories()
	keys := map[string]any{}
	for _, o := range []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"} {
		keys[o] = newEd25519(t)
		dirs.publish(t, o, wbaTestNow.Add(-time.Minute), time.Hour, keys[o])
	}
	d := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: wbaClock, MaxOrigins: 2})
	for _, o := range []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"} {
		jwk, _ := PublicDirectoryKey(keys[o])
		_, err := d.ResolveWBAKey(context.Background(), o, jwk.Kid)
		require.NoError(t, err)
	}
	require.Nil(t, d.Evidence("https://a.example.com"), "least recently used origin evicted")
	require.NotNil(t, d.Evidence("https://c.example.com"))

	// Concurrent discoveries beyond MaxOrigins are refused with 429.
	release := make(chan struct{})
	dirs.block["https://a.example.com"] = release
	dirs.block["https://b.example.com"] = release
	d2 := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: wbaClock, MaxOrigins: 2})
	var wg sync.WaitGroup
	for _, o := range []string{"https://a.example.com", "https://b.example.com"} {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = d2.ResolveWBAKey(context.Background(), o, "k") }()
	}
	require.Eventually(t, func() bool {
		return dirs.count("https://a.example.com") >= 2 && dirs.count("https://b.example.com") >= 2
	}, time.Second, time.Millisecond)
	_, err := d2.ResolveWBAKey(context.Background(), "https://c.example.com", "k")
	requireWBAStatus(t, err, http.StatusTooManyRequests)
	close(release)
	wg.Wait()

	_, err = d.ResolveWBAKey(context.Background(), "http://a.example.com", "k")
	requireWBAStatus(t, err, http.StatusForbidden)
}

// TestDirectoryResolverOperatorIsolation: one operator cannot hold every
// discovery slot, and failed discoveries never evict verified directories.
func TestDirectoryResolverOperatorIsolation(t *testing.T) {
	dirs := newFakeDirectories()
	release := make(chan struct{})
	good := newEd25519(t)
	dirs.publish(t, "https://good.example.org", wbaTestNow.Add(-time.Minute), time.Hour, good)
	d := NewDirectoryResolver(DirectoryResolverOptions{Fetch: dirs.fetch, Clock: wbaClock, MaxOrigins: 4, MaxPendingPerOperator: 2})
	goodJWK, _ := PublicDirectoryKey(good)
	_, err := d.ResolveWBAKey(context.Background(), "https://good.example.org", goodJWK.Kid)
	require.NoError(t, err)

	var wg sync.WaitGroup
	attackers := []string{"https://a1.attacker.example.com", "https://a2.attacker.example.com"}
	dirs.mu.Lock()
	for _, o := range attackers {
		dirs.block[o] = release
	}
	dirs.mu.Unlock()
	for _, o := range attackers {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = d.ResolveWBAKey(context.Background(), o, "k") }()
	}
	require.Eventually(t, func() bool {
		return dirs.count("https://a1.attacker.example.com") == 1 && dirs.count("https://a2.attacker.example.com") == 1
	}, time.Second, time.Millisecond)
	_, err = d.ResolveWBAKey(context.Background(), "https://a3.attacker.example.com", "k")
	requireWBAStatus(t, err, http.StatusTooManyRequests)
	close(release)
	wg.Wait()

	// Many failed discoveries do not push the verified directory out.
	for i := range 10 {
		_, _ = d.ResolveWBAKey(context.Background(), fmt.Sprintf("https://f%d.example.net", i), "k")
	}
	require.NotNil(t, d.Evidence("https://good.example.org"))
	got, err := d.ResolveWBAKey(context.Background(), "https://good.example.org", goodJWK.Kid)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, 1, dirs.count("https://good.example.org"))
}
