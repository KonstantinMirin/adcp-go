package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type trustServer struct {
	mu      sync.Mutex
	docs    map[string]*TrustResponse
	errs    map[string]error
	block   map[string]chan struct{}
	fetches map[string]int
}

func newTrustServer() *trustServer {
	return &trustServer{docs: map[string]*TrustResponse{}, errs: map[string]error{}, block: map[string]chan struct{}{}, fetches: map[string]int{}}
}

func (s *trustServer) set(url string, status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[url] = &TrustResponse{Status: status, Body: []byte(body)}
	delete(s.errs, url)
}

func (s *trustServer) fail(url string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs[url] = err
}

func (s *trustServer) count(url string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches[url]
}

func (s *trustServer) fetch(ctx context.Context, url string) (*TrustResponse, error) {
	s.mu.Lock()
	s.fetches[url]++
	block, err, doc := s.block[url], s.errs[url], s.docs[url]
	s.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return &TrustResponse{Status: http.StatusNotFound}, nil
	}
	return doc, nil
}

func trustURL(domain string) string { return "https://" + domain + "/.well-known/trust.json" }

type evalRig struct {
	now    time.Time
	server *trustServer
	eval   *TrustRecordEvaluator
}

func newEvalRig(t *testing.T) *evalRig {
	t.Helper()
	r := &evalRig{now: testNow, server: newTrustServer()}
	var err error
	r.eval, err = NewTrustRecordEvaluator(TrustRecordEvaluatorOptions{Fetch: r.server.fetch, Clock: func() time.Time { return r.now }, PollingInterval: time.Minute})
	require.NoError(t, err)
	return r
}

const buyerRecord = `{"agents":[{"url":"https://buyer.example.com/mcp","roles":["adcp:buying"]}]}`

func TestTrustRecordURL(t *testing.T) {
	u, err := TrustRecordURL("https://agent.buyer.example.co.uk:8443/mcp")
	require.NoError(t, err)
	require.Equal(t, "https://example.co.uk/.well-known/trust.json", u)
	for _, bad := range []string{"https://192.0.2.1", "https://co.uk", "https://buyer.example", "https://localhost"} {
		_, err := TrustRecordURL(bad)
		require.Error(t, err, bad)
	}
	_, err = NewTrustRecordEvaluator(TrustRecordEvaluatorOptions{PollingInterval: time.Hour})
	require.Error(t, err, "the cache bound may not exceed the 30 min polling ceiling")
}

func TestEvaluateRequiresExactlyOneAgentWithRole(t *testing.T) {
	r := newEvalRig(t)
	ctx := context.Background()
	r.server.set(trustURL("example.com"), 200, buyerRecord)
	rec, err := r.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.NoError(t, err)
	require.Equal(t, "example.com", rec.OperatorDomain)
	_, err = r.eval.Evaluate(ctx, "https://buyer.example.com", RoleSales)
	require.Error(t, err)
	_, err = r.eval.Evaluate(ctx, "https://other.example.com", RoleBuying)
	require.Error(t, err)
	require.Equal(t, 1, r.server.count(trustURL("example.com")), "one fetch serves every origin of the operator")

	// The returned record is a copy: mutating it cannot change authority.
	rec.Record.Agents[0].Roles = []string{RoleSales}
	_, err = r.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.NoError(t, err)
}

func TestEvaluateAuthoritativeLocation(t *testing.T) {
	r := newEvalRig(t)
	ctx := context.Background()
	hosted := "https://records.host.example.net/brand/trust.json"
	r.server.set(trustURL("example.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
	r.server.set(hosted, 200, buyerRecord)
	rec, err := r.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.NoError(t, err)
	require.Equal(t, "example.com", rec.OperatorDomain, "the operator is never the hop target's host")
	require.Equal(t, hosted, rec.SourceURL)

	// A hosted record cannot make another domain's agents this operator's.
	r2 := newEvalRig(t)
	r2.server.set(trustURL("example.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
	r2.server.set(hosted, 200, `{"agents":[{"url":"https://agent.host.example.net/mcp","roles":["adcp:buying"]}]}`)
	_, err = r2.eval.Evaluate(ctx, "https://buyer.example.com", "")
	require.Error(t, err)

	cases := map[string]func(s *trustServer){
		"second hop": func(s *trustServer) {
			s.set(trustURL("example.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
			s.set(hosted, 200, `{"authoritative_location":"https://third.example.org/trust.json"}`)
		},
		"HTTP redirect is not followed": func(s *trustServer) {
			s.set(trustURL("example.com"), http.StatusFound, ``)
		},
		"pointer to a private address": func(s *trustServer) {
			s.set(trustURL("example.com"), 200, `{"authoritative_location":"https://10.0.0.5/trust.json"}`)
		},
		"pointer with userinfo": func(s *trustServer) {
			s.set(trustURL("example.com"), 200, `{"authoritative_location":"https://user@hosted.example.net/trust.json"}`)
		},
		"hop target is 404 (not absence)": func(s *trustServer) {
			s.set(trustURL("example.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
		},
		"strict JSON": func(s *trustServer) {
			s.set(trustURL("example.com"), 200, `{"agents":[],"agents":[]}`)
		},
		"oversized": func(s *trustServer) {
			s.set(trustURL("example.com"), 200, `{"grants":[],"ext":{"v":{"p":"`+strings.Repeat("x", TrustRecordMaxBytes)+`"}}}`)
		},
		"server error": func(s *trustServer) { s.set(trustURL("example.com"), 503, ``) },
		"transport error": func(s *trustServer) {
			s.fail(trustURL("example.com"), errors.New("connection refused"))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newEvalRig(t)
			setup(r.server)
			_, err := r.eval.Evaluate(ctx, "https://buyer.example.com", "")
			require.Error(t, err)
			require.False(t, IsTrustRecordAbsent(err), "a failure is never absence")
		})
	}
}

func TestEvaluateAbsenceAndNoDowngrade(t *testing.T) {
	r := newEvalRig(t)
	ctx := context.Background()
	_, err := r.eval.Evaluate(ctx, "brand.com", "")
	require.True(t, IsTrustRecordAbsent(err), "404 before any 200 is absence")
	r.server.set(trustURL("brand.com"), http.StatusGone, "")
	r.now = r.now.Add(61 * time.Second)
	_, err = r.eval.Evaluate(ctx, "brand.com", "")
	require.True(t, IsTrustRecordAbsent(err), "410 too")

	r.server.set(trustURL("brand.com"), 200, `{"grants":[]}`)
	r.now = r.now.Add(61 * time.Second)
	_, err = r.eval.Evaluate(ctx, "brand.com", "")
	require.NoError(t, err)
	// After a 200 the record disappears: that is a failure, not absence, so
	// no fallback to brand.json is possible.
	r.server.set(trustURL("brand.com"), http.StatusNotFound, "")
	r.now = r.now.Add(2 * time.Minute)
	_, err = r.eval.Evaluate(ctx, "brand.com", "")
	require.Error(t, err)
	require.False(t, IsTrustRecordAbsent(err))
}

func TestEvaluateFreshnessAndNegativeCache(t *testing.T) {
	r := newEvalRig(t)
	ctx := context.Background()
	u := trustURL("example.com")
	r.server.set(u, 200, buyerRecord)
	rec, err := r.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.NoError(t, err)
	require.Equal(t, r.now.Add(time.Minute), rec.ExpiresAt, "cached no longer than the polling interval")
	r.now = r.now.Add(30 * time.Second)
	_, _ = r.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.Equal(t, 1, r.server.count(u))

	// Delisting ends authority within one cache lifetime.
	r.server.set(u, 200, `{"agents":[{"url":"https://other.example.com","roles":["adcp:buying"]}]}`)
	r.now = r.now.Add(31 * time.Second)
	_, err = r.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.Error(t, err)

	// A failure is negatively cached for at most 60 s.
	r2 := newEvalRig(t)
	r2.server.fail(u, errors.New("down"))
	_, err = r2.eval.Evaluate(ctx, "https://buyer.example.com", "")
	require.Error(t, err)
	_, err = r2.eval.Evaluate(ctx, "https://buyer.example.com", "")
	require.Error(t, err)
	require.Equal(t, 1, r2.server.count(u))
	r2.server.set(u, 200, buyerRecord)
	r2.now = r2.now.Add(61 * time.Second)
	_, err = r2.eval.Evaluate(ctx, "https://buyer.example.com", RoleBuying)
	require.NoError(t, err)
}

func TestEvaluateRecordExpiringDuringFetchGrantsNothing(t *testing.T) {
	r := newEvalRig(t)
	u := trustURL("example.com")
	r.server.set(u, 200, buyerRecord)
	release := make(chan struct{})
	r.server.block[u] = release
	done := make(chan error)
	go func() {
		_, err := r.eval.Evaluate(context.Background(), "https://buyer.example.com", RoleBuying)
		done <- err
	}()
	require.Eventually(t, func() bool { return r.server.count(u) == 1 }, time.Second, time.Millisecond)
	r.eval.mu.Lock()
	r.now = r.now.Add(2 * time.Minute) // the fetch outlives the record's lifetime
	r.eval.mu.Unlock()
	close(release)
	require.Error(t, <-done)
}

func TestEvaluateSingleFlightAndIsolation(t *testing.T) {
	r := newEvalRig(t)
	slow, fast := trustURL("slow.com"), trustURL("fast.com")
	r.server.set(slow, 200, `{"agents":[{"url":"https://a.slow.com","roles":["adcp:buying"]}]}`)
	r.server.set(fast, 200, `{"agents":[{"url":"https://a.fast.com","roles":["adcp:buying"]}]}`)
	_, err := r.eval.Evaluate(context.Background(), "https://a.fast.com", RoleBuying)
	require.NoError(t, err)
	release := make(chan struct{})
	r.server.block[slow] = release
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.eval.Evaluate(context.Background(), "https://a.slow.com", RoleBuying)
			require.NoError(t, err)
		}()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.eval.Evaluate(ctx, "https://a.slow.com", RoleBuying)
	require.ErrorIs(t, err, context.Canceled, "a waiter that gives up does not cancel the shared fetch")
	// One slow operator does not block another operator's cached record.
	_, err = r.eval.Evaluate(context.Background(), "https://a.fast.com", RoleBuying)
	require.NoError(t, err)
	close(release)
	wg.Wait()
	require.Equal(t, 1, r.server.count(slow))
}

func TestEvaluateSharedHopCannotExtendFreshness(t *testing.T) {
	r := newEvalRig(t)
	hosted := "https://records.host.example.net/shared/trust.json"
	r.server.set(trustURL("one.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
	r.server.set(trustURL("two.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
	r.server.set(hosted, 200, `{"grants":[]}`)
	a, err := r.eval.Evaluate(context.Background(), "one.com", "")
	require.NoError(t, err)
	r.now = r.now.Add(40 * time.Second)
	b, err := r.eval.Evaluate(context.Background(), "two.com", "")
	require.NoError(t, err)
	require.Equal(t, 1, r.server.count(hosted), "hop bytes are shared")
	require.Equal(t, "two.com", b.OperatorDomain, "authority is not shared")
	require.Equal(t, a.ExpiresAt, b.ExpiresAt, "a cached hop response bounds the later record's freshness")
}

func TestEvaluateHostFailureCooldownIsNotAbsence(t *testing.T) {
	r := newEvalRig(t)
	hosted := "https://records.host.example.net/a/trust.json"
	r.server.set(trustURL("one.com"), 200, `{"authoritative_location":"`+hosted+`"}`)
	r.server.set(hosted, 503, ``)
	_, err := r.eval.Evaluate(context.Background(), "one.com", "")
	require.Error(t, err)
	// Another operator hosted on the same host, whose own derived URL 404s
	// on the first try, still gets "absent" only from its own URL.
	_, err = r.eval.Evaluate(context.Background(), "two.com", "")
	require.True(t, IsTrustRecordAbsent(err))
	// But a different path on the cooling host fails without being absence.
	r.server.set(trustURL("three.com"), 200, `{"authoritative_location":"https://records.host.example.net/b/trust.json"}`)
	_, err = r.eval.Evaluate(context.Background(), "three.com", "")
	require.Error(t, err)
	require.False(t, IsTrustRecordAbsent(err))
	require.Zero(t, r.server.count("https://records.host.example.net/b/trust.json"), "the host is cooling down")
}

func TestEvaluateBoundsPending(t *testing.T) {
	server := newTrustServer()
	release := make(chan struct{})
	for _, d := range []string{"a.com", "b.com"} {
		server.set(trustURL(d), 200, `{"grants":[]}`)
		server.block[trustURL(d)] = release
	}
	eval, _ := NewTrustRecordEvaluator(TrustRecordEvaluatorOptions{Fetch: server.fetch, MaxRecords: 2, Clock: func() time.Time { return testNow }})
	var wg sync.WaitGroup
	for _, d := range []string{"a.com", "b.com"} {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = eval.Evaluate(context.Background(), d, "") }()
	}
	require.Eventually(t, func() bool { return server.count(trustURL("a.com")) == 1 && server.count(trustURL("b.com")) == 1 }, time.Second, time.Millisecond)
	_, err := eval.Evaluate(context.Background(), "c.com", "")
	require.Error(t, err)
	close(release)
	wg.Wait()
}

func TestBindingsAndGate(t *testing.T) {
	ctx := context.Background()
	b := NewOriginBindings()
	require.NoError(t, b.Bind(ctx, "https://buyer.example.com/mcp", "p1", BindOptions{}))
	require.NoError(t, b.Bind(ctx, "https://BUYER.example.com:443", "p1", BindOptions{}), "rebinding to the same principal is idempotent")
	require.ErrorIs(t, b.Bind(ctx, "https://buyer.example.com", "p2", BindOptions{}), ErrRebind)
	require.NoError(t, b.Bind(ctx, "https://second.example.com", "p1", BindOptions{}), "a principal may own several origins")
	require.ErrorIs(t, b.Bind(ctx, "https://legacy.example.com", "p9", BindOptions{ExistingRFC9421Principal: true}), ErrMigrationNotApproved)
	require.NoError(t, b.Bind(ctx, "https://legacy.example.com", "p9", BindOptions{ExistingRFC9421Principal: true, MigrationApproved: true}))
	require.Error(t, b.Bind(ctx, "http://plain.example.com", "p3", BindOptions{}))
	require.Error(t, b.Bind(ctx, "https://x.example.com", "", BindOptions{}))
	p, ok, _ := b.PrincipalForOrigin(ctx, "https://buyer.example.com/other")
	require.True(t, ok)
	require.Equal(t, "p1", p)

	r := newEvalRig(t)
	r.server.set(trustURL("example.com"), 200, buyerRecord)
	gate := &BindingGate{Bindings: b, Records: r.eval}
	signer := &signing.VerifiedSigner{AgentURL: "https://buyer.example.com", Profile: signing.ProfileTagWebBotAuth}
	got, err := gate.AuthorizeWBA(ctx, signer, "create_media_buy")
	require.NoError(t, err)
	require.Equal(t, "p1", got)
	unbound := &signing.VerifiedSigner{AgentURL: "https://new.example.com", Profile: signing.ProfileTagWebBotAuth}
	got, err = gate.AuthorizeWBA(ctx, unbound, "get_principal")
	require.NoError(t, err)
	require.Empty(t, got, "an unbound origin is identity-established")

	// Delisting removes authority on refresh but keeps the binding, which
	// still blocks an RFC 9421 downgrade.
	r.server.set(trustURL("example.com"), 200, `{"agents":[{"url":"https://other.example.com","roles":["adcp:buying"]}]}`)
	r.now = r.now.Add(2 * time.Minute)
	_, err = gate.AuthorizeWBA(ctx, signer, "create_media_buy")
	require.Error(t, err)
	_, still, _ := b.PrincipalForOrigin(ctx, "https://buyer.example.com")
	require.True(t, still)

	// Binding is explicit and needs the trust record listing.
	r.server.set(trustURL("example.com"), 200, `{"agents":[{"url":"https://new.example.com","roles":["adcp:buying"]},{"url":"https://sales.example.com","roles":["adcp:sales"]}]}`)
	r.now = r.now.Add(2 * time.Minute)
	_, err = r.eval.Bind(ctx, unbound, "p5", b, BindOptions{})
	require.NoError(t, err)
	p, _, _ = b.PrincipalForOrigin(ctx, unbound.AgentURL)
	require.Equal(t, "p5", p)
	_, err = r.eval.Bind(ctx, &signing.VerifiedSigner{AgentURL: "https://sales.example.com", Profile: signing.ProfileTagWebBotAuth}, "p6", b, BindOptions{})
	require.Error(t, err, "the required role is adcp:buying")
	_, err = r.eval.Bind(ctx, &signing.VerifiedSigner{AgentURL: "https://sales.example.com", Profile: signing.ProfileTagWebBotAuth}, "p6", b, BindOptions{Role: RoleSales})
	require.NoError(t, err)
	_, err = r.eval.Bind(ctx, &signing.VerifiedSigner{AgentURL: "https://new.example.com", Profile: signing.ProfileTagRequestSigning}, "p7", b, BindOptions{})
	require.Error(t, err, "binding requires a Web Bot Auth identity")
	_, err = r.eval.Bind(ctx, nil, "p7", b, BindOptions{})
	require.Error(t, err)
}
