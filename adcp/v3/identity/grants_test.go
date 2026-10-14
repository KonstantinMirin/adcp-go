package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// The grant fixtures model DR-0025's parties:
//   - brand-7k3q.com, the brand, which publishes grants;
//   - agency-7k3q.com, an agency named as account.operator;
//   - platform-7k3q.com, a platform hosting the agency's buying agent;
//   - buyer agents at https://buy.agency-7k3q.com and https://agent.platform-7k3q.com.
const (
	agencyAgent   = "https://buy.agency-7k3q.com"
	platformAgent = "https://agent.platform-7k3q.com"
)

func grantRig(t *testing.T, records map[string]string) *evalRig {
	t.Helper()
	r := newEvalRig(t)
	for domain, doc := range records {
		r.server.set(trustURL(domain), 200, doc)
	}
	return r
}

var baseRecords = map[string]string{
	"agency-7k3q.com":   `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}]}`,
	"platform-7k3q.com": `{"agents":[{"url":"https://agent.platform-7k3q.com/mcp","roles":["adcp:buying"]}]}`,
}

func with(records map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range records {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func TestGrantEvaluation(t *testing.T) {
	brandGrantsAgency := `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"],"countries":["US","CA"],"profiles":{"adcp":{"brands":["nova"]}},"valid_until":"2027-06-30T00:00:00Z"}]}`
	cases := []struct {
		name    string
		records map[string]string
		req     GrantRequest
		want    bool
		reason  string
	}{
		{
			name:    "implicit when operator, brand, and signer share a registrable domain",
			records: map[string]string{"agency-7k3q.com": baseRecords["agency-7k3q.com"]},
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "house.agency-7k3q.com", AccountOperator: "agency-7k3q.com"},
			want:    true,
		},
		{
			name:    "direct grant to the signer's operator, which is account.operator",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova", Countries: []string{"US"}},
			want:    true,
		},
		{
			name:    "a grant does not cover a brand it does not list",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "other", Countries: []string{"US"}},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a country-limited grant covers no claim outside it",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova", Countries: []string{"US", "MX"}},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a country-limited grant covers no claim without countries",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova"},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "the scope must be covered",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova", Countries: []string{"US"}, Scope: ScopeCreativeGeneration},
			reason:  GrantReasonAbsent,
		},
		{
			name: "adcp:all covers adcp scopes and * covers everything",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:all"]}]}`,
				"other-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["*"]}]}`}),
			req:  GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", Scope: ScopeCreativeGeneration},
			want: true,
		},
		{
			name:    "account.operator must be on the chain",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "someone-else-7k3q.com", BrandID: "nova", Countries: []string{"US"}},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a self-operated brand (brand is account.operator) grants the hosting platform directly",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"],"agents":[{"url":"https://agent.platform-7k3q.com/mcp"}]}]}`}),
			req:     GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "brand-7k3q.com"},
			want:    true,
		},
		{
			name:    "a self-operated brand's grant to someone else does not cover the platform",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"]}]}`}),
			req:     GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "brand-7k3q.com"},
			reason:  GrantReasonAbsent,
		},
		{
			name: "chain through account.operator to the hosting platform",
			records: with(baseRecords, map[string]string{
				"brand-7k3q.com":  brandGrantsAgency,
				"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"],"agents":[{"url":"https://agent.platform-7k3q.com/mcp"}]}]}`,
			}),
			req:  GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova", Countries: []string{"CA"}},
			want: true,
		},
		{
			name: "intersection: the second link must cover the claim's countries too",
			records: with(baseRecords, map[string]string{
				"brand-7k3q.com":  brandGrantsAgency,
				"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"],"countries":["US"]}]}`,
			}),
			req:    GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova", Countries: []string{"CA"}},
			reason: GrantReasonAbsent,
		},
		{
			name: "agents[] narrowing is matched by canonical origin",
			records: with(baseRecords, map[string]string{
				"brand-7k3q.com":  brandGrantsAgency,
				"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"],"agents":[{"url":"https://other.platform-7k3q.com/mcp"}]}]}`,
			}),
			req:    GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", BrandID: "nova", Countries: []string{"CA"}},
			reason: GrantReasonAbsent,
		},
		{
			name: "no third link: a grant to account.operator's grantee's grantee is not followed",
			records: with(baseRecords, map[string]string{
				"brand-7k3q.com":    `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"]}]}`,
				"agency-7k3q.com":   `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"middle-7k3q.com","scopes":["adcp:media_buying"]}]}`,
				"middle-7k3q.com":   `{"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"]}]}`,
				"platform-7k3q.com": baseRecords["platform-7k3q.com"],
			}),
			req:    GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason: GrantReasonAbsent,
		},
		{
			name: "the buyer operator's record never authorizes a brand outside its domain",
			records: with(baseRecords, map[string]string{
				"brand-7k3q.com":  `{"grants":[]}`,
				"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"agency-7k3q.com","scopes":["*"]}]}`,
			}),
			req:    GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason: GrantReasonAbsent,
		},
		{
			name:    "an expired grant",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T11:00:00Z"}]}`}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a grant not yet valid",
			records: with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"],"valid_from":"2026-10-14T00:00:00Z"}]}`}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "Web Bot Auth: the signer's operator must list the origin with adcp:buying",
			records: map[string]string{"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:sales"]}]}`},
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "agency-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason:  GrantReasonSignerUnlisted,
		},
		{
			name:    "a brand trust record that cannot be fetched is not absence",
			records: baseRecords,
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "down-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason:  GrantReasonTrustRecordUnavailable,
		},
		{
			name:    "a brand that publishes no trust record and no legacy hook",
			records: baseRecords,
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"},
			reason:  GrantReasonTrustRecordAbsent,
		},
		{
			name:    "no registrable domain",
			records: baseRecords,
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.example", AccountOperator: "agency-7k3q.com"},
			reason:  GrantReasonAbsent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := grantRig(t, tc.records)
			r.server.fail(trustURL("down-7k3q.com"), errors.New("timeout"))
			g := &GrantEvaluator{Records: r.eval}
			res, err := g.Check(context.Background(), tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.want, res.Authorized, res.Reason)
			if !tc.want {
				require.Equal(t, tc.reason, res.Reason)
				require.Error(t, res.Err())
			} else {
				require.NoError(t, res.Err())
				require.False(t, res.ExpiresAt.IsZero())
			}
		})
	}
}

func TestGrantExpiryIsTheEarliestOnTheChain(t *testing.T) {
	r := grantRig(t, with(baseRecords, map[string]string{
		"brand-7k3q.com":  `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:50Z"}]}`,
		"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:30Z"},{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:40Z"}]}`,
	}))
	g := &GrantEvaluator{Records: r.eval}
	res, err := g.Check(context.Background(), GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"})
	require.NoError(t, err)
	require.True(t, res.Authorized)
	require.Equal(t, time.Date(2026, 10, 13, 12, 0, 40, 0, time.UTC), res.ExpiresAt, "min over links of each link's latest valid_until")
}

func TestGrantExpiringDuringIntermediaryFetchIsNotAuthorized(t *testing.T) {
	r := grantRig(t, with(baseRecords, map[string]string{
		"brand-7k3q.com":  `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:05Z"}]}`,
		"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"]}]}`,
	}))
	// Evaluate brand and signer first so only the intermediary fetch runs
	// during Check, and advance the clock as it happens.
	_, _ = r.eval.Evaluate(context.Background(), "brand-7k3q.com", "")
	_, _ = r.eval.Evaluate(context.Background(), platformAgent, RoleBuying)
	fetch := r.server.fetch
	eval, _ := NewTrustRecordEvaluator(TrustRecordEvaluatorOptions{
		Clock: func() time.Time { return r.now }, PollingInterval: time.Minute,
		Fetch: func(ctx context.Context, url string) (*TrustResponse, error) {
			if url == trustURL("agency-7k3q.com") {
				r.now = r.now.Add(10 * time.Second)
			}
			return fetch(ctx, url)
		},
	})
	_, _ = eval.Evaluate(context.Background(), "brand-7k3q.com", "")
	_, _ = eval.Evaluate(context.Background(), platformAgent, RoleBuying)
	g := &GrantEvaluator{Records: eval}
	res, err := g.Check(context.Background(), GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"})
	require.NoError(t, err)
	require.False(t, res.Authorized)
}

func TestGrantExclusiveAndHooks(t *testing.T) {
	yes := func(context.Context, GrantRequest) (bool, error) { return true, nil }
	fail := func(context.Context, GrantRequest) (bool, error) { return false, errors.New("db down") }
	req := GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"}
	ctx := context.Background()

	// Without exclusive_grants, an uncovered claim is at the seller's
	// discretion.
	r := grantRig(t, with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"x-7k3q.com","scopes":["adcp:media_buying"]}]}`}))
	res, _ := (&GrantEvaluator{Records: r.eval, SellerAuthorization: yes}).Check(ctx, req)
	require.True(t, res.Authorized)
	res, _ = (&GrantEvaluator{Records: r.eval, SellerAuthorization: fail}).Check(ctx, req)
	require.False(t, res.Authorized, "a hook error fails closed")

	// exclusive_grants makes grants[] exhaustive for the scopes it names...
	r = grantRig(t, with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"x-7k3q.com","scopes":["adcp:media_buying"]}],"exclusive_grants":true}`}))
	res, _ = (&GrantEvaluator{Records: r.eval, SellerAuthorization: yes}).Check(ctx, req)
	require.False(t, res.Authorized)
	require.Equal(t, GrantReasonAbsent, res.Reason)
	// ...and only those.
	creative := req
	creative.Scope = ScopeCreativeGeneration
	res, _ = (&GrantEvaluator{Records: r.eval, SellerAuthorization: yes}).Check(ctx, creative)
	require.True(t, res.Authorized)

	// A 200 from the brand's trust.json disables the legacy brand.json hook.
	legacyCalled := false
	legacy := func(context.Context, GrantRequest) (bool, error) { legacyCalled = true; return true, nil }
	r = grantRig(t, with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[]}`}))
	res, _ = (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, req)
	require.False(t, res.Authorized)
	require.False(t, legacyCalled)

	// Absent (404 before any 200): the legacy hook decides.
	r = grantRig(t, baseRecords)
	res, _ = (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, req)
	require.True(t, res.Authorized)
	require.True(t, res.LegacyFallbackAllowed)
	require.True(t, legacyCalled)

	// A fetch failure invokes neither hook.
	legacyCalled = false
	sellerCalled := false
	r = grantRig(t, baseRecords)
	r.server.fail(trustURL("brand-7k3q.com"), errors.New("timeout"))
	res, _ = (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy, SellerAuthorization: func(context.Context, GrantRequest) (bool, error) {
		sellerCalled = true
		return true, nil
	}}).Check(ctx, req)
	require.False(t, res.Authorized)
	require.False(t, legacyCalled)
	require.False(t, sellerCalled)
}

// TestGrantRFC9421Signer: an RFC 9421 signer keeps its established path
// while the brand has never published a trust record; once the brand
// serves 200, the signer's operator must list it too.
func TestGrantRFC9421Signer(t *testing.T) {
	ctx := context.Background()
	legacy := func(context.Context, GrantRequest) (bool, error) { return true, nil }
	req := GrantRequest{AgentOrigin: "https://legacy.agency-7k3q.com/mcp", BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", SigningProfile: signing.ProfileTagRequestSigning}

	r := grantRig(t, nil) // the agency publishes no trust record either
	res, _ := (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, req)
	require.True(t, res.Authorized, "no new operator record is needed before the brand publishes")

	r = grantRig(t, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"]}]}`})
	res, _ = (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, req)
	require.False(t, res.Authorized)
	require.Equal(t, GrantReasonSignerUnlisted, res.Reason, "the agency publishes no record, so it lists no agent")

	// A Web Bot Auth signer never reaches the legacy path without its own
	// operator record.
	wba := req
	wba.SigningProfile = signing.ProfileTagWebBotAuth
	r = grantRig(t, nil)
	res, _ = (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, wba)
	require.False(t, res.Authorized)

	_, err := (&GrantEvaluator{Records: r.eval}).Check(ctx, GrantRequest{AgentOrigin: agencyAgent, SigningProfile: "bearer"})
	require.Error(t, err)
}

// permissionDetails renders err the way a seller does, by returning it
// from SyncAccountsAuthorizer through a registered MCP server, and returns
// the wire code and details.
func permissionDetails(t *testing.T, err error) (string, map[string]any) {
	t.Helper()
	require.Error(t, err)
	handlerCalled := false
	result := callSyncAccounts(t, adcp.Config{
		IdempotencyReplayTTL: 24 * time.Hour,
		SyncAccounts: func(context.Context, *adcp.SyncAccountsRequest) ([]adcp.AccountResult, error) {
			handlerCalled = true
			return nil, nil
		},
		SyncAccountsAuthorizer: func(context.Context, *mcp.CallToolRequest, []adcp.AccountInput) error { return err },
	})
	require.True(t, result.IsError)
	require.False(t, handlerCalled, "no account is created when the gate denies")
	b, _ := json.Marshal(result.StructuredContent)
	var p struct {
		ADCPError struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
		} `json:"adcp_error"`
	}
	require.NoError(t, json.Unmarshal(b, &p))
	return p.ADCPError.Code, p.ADCPError.Details
}

func callSyncAccounts(t *testing.T, cfg adcp.Config) *mcp.CallToolResult {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "identity-test", Version: "v0"}, nil)
	adcp.Register(server, cfg)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, st, nil)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "v0"}, nil).Connect(ctx, ct, nil)
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "sync_accounts", Arguments: map[string]any{
		"idempotency_key": "4f6c1a0e-8d2b-4b7e-9c3a-2e5d7f1b0a96",
		"accounts":        []map[string]any{{"brand": map[string]any{"domain": "brand-7k3q.com"}, "operator": "agency-7k3q.com", "billing": "operator"}},
	}})
	require.NoError(t, err)
	return res
}

type stubKeys map[string]signing.JWK

func (s stubKeys) ResolveWBAKey(_ context.Context, origin, kid string) (*signing.JWK, error) {
	if k, ok := s[origin]; ok && k.Kid == kid {
		return &k, nil
	}
	return nil, nil
}

type noRevocations struct{}

func (noRevocations) RevokedWBAKey(context.Context, string, string) (bool, error) { return false, nil }

type stubAuthorizer map[string]string

func (s stubAuthorizer) AuthorizeWBA(_ context.Context, signer *signing.VerifiedSigner, _ string) (string, error) {
	return s[signer.AgentURL], nil
}

// wbaAgent is a Web Bot Auth signer for tests: an origin and its key.
type wbaAgent struct {
	origin string
	key    ed25519.PrivateKey
	jwk    signing.JWK
}

func newWBAAgent(t *testing.T, origin string) wbaAgent {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk, err := signing.PublicDirectoryKey(key)
	require.NoError(t, err)
	return wbaAgent{origin: origin, key: key, jwk: jwk}
}

// signingTransport WBA-signs every outbound request as the current agent.
type signingTransport struct {
	mu      sync.Mutex
	current wbaAgent
}

func (s *signingTransport) use(a wbaAgent) { s.mu.Lock(); s.current = a; s.mu.Unlock() }

func (s *signingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	a := s.current
	s.mu.Unlock()
	clone := r.Clone(r.Context())
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		clone.Body = io.NopCloser(bytes.NewReader(b))
	}
	if err := signing.SignWebBotAuthRequest(clone, a.key, signing.WBASignOptions{AgentOrigin: a.origin}); err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(clone)
}

// TestSyncAccountsGateUsesThePerRequestSigner drives a stateful MCP
// session over HTTP: initialize is signed by one agent and tools/call by
// another. The gate must evaluate the agent that signed the call, never the
// session's initialize request.
func TestSyncAccountsGateUsesThePerRequestSigner(t *testing.T) {
	agentA := newWBAAgent(t, "https://buy.agency-7k3q.com")
	agentB := newWBAAgent(t, "https://agent.platform-7k3q.com")
	var seen []*signing.VerifiedSigner
	var ctxSigners []*signing.VerifiedSigner
	server := mcp.NewServer(&mcp.Implementation{Name: "seller", Version: "v0"}, nil)
	adcp.Register(server, adcp.Config{
		IdempotencyReplayTTL: 24 * time.Hour,
		SyncAccounts: func(context.Context, *adcp.SyncAccountsRequest) ([]adcp.AccountResult, error) {
			return []adcp.AccountResult{{AccountID: "acc_1", Status: "active"}}, nil
		},
		SyncAccountsAuthorizer: func(ctx context.Context, req *mcp.CallToolRequest, _ []adcp.AccountInput) error {
			seen = append(seen, signing.VerifiedSignerFromToolRequest(req))
			ctxSigners = append(ctxSigners, signing.VerifiedSignerFromContext(ctx))
			return nil
		},
	})
	handler := signing.Middleware(signing.MiddlewareOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		WebBotAuth: &signing.WebBotAuthOptions{
			Keys:       stubKeys{agentA.origin: agentA.jwk, agentB.origin: agentB.jwk},
			Revocation: noRevocations{},
			Authorizer: stubAuthorizer{agentA.origin: "principal_a", agentB.origin: "principal_b"},
		},
	})(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	rt := &signingTransport{current: agentA}
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "buyer", Version: "v0"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: rt}}, nil)
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	call := func() {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "sync_accounts", Arguments: map[string]any{
			"idempotency_key": "4f6c1a0e-8d2b-4b7e-9c3a-2e5d7f1b0a9" + strconv.Itoa(len(seen)),
			"accounts":        []map[string]any{{"brand": map[string]any{"domain": "brand-7k3q.com"}, "operator": "agency-7k3q.com", "billing": "operator"}},
		}})
		require.NoError(t, err)
		require.False(t, res.IsError)
	}
	rt.use(agentB)
	call()
	rt.use(agentA)
	call()
	require.Len(t, seen, 2)
	require.Equal(t, agentB.origin, seen[0].AgentURL)
	require.Equal(t, "principal_b", seen[0].PrincipalID)
	require.Equal(t, agentA.origin, seen[1].AgentURL)
	require.Equal(t, "principal_a", seen[1].PrincipalID)
	// The handler's ctx is the session's initialize request's (signed by A),
	// so a ctx-based lookup would have evaluated the wrong agent for B.
	require.NotNil(t, ctxSigners[0])
	require.Equal(t, agentA.origin, ctxSigners[0].AgentURL, "the trap this API avoids")
}

// toolRequestWithSigner builds the CallToolRequest a tool handler receives
// after Middleware verified signer.
func toolRequestWithSigner(signer *signing.VerifiedSigner) *mcp.CallToolRequest {
	if signer == nil {
		return &mcp.CallToolRequest{}
	}
	return &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{Extra: map[string]any{signing.TokenInfoSignerKey: signer}}}}
}

func TestGrantGate(t *testing.T) {
	ctx := context.Background()
	r := grantRig(t, with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"]}]}`}))
	gate := &GrantGate{
		Evaluator: &GrantEvaluator{Records: r.eval},
		ExistingAccountClaim: func(_ context.Context, id string) (GrantClaim, error) {
			if id == "acc_brand" {
				return GrantClaim{BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"}, nil
			}
			return GrantClaim{}, errors.New("unknown account")
		},
	}
	signer := &signing.VerifiedSigner{AgentURL: agencyAgent, Profile: signing.ProfileTagWebBotAuth, PrincipalID: "p_agency"}
	stranger := &signing.VerifiedSigner{AgentURL: platformAgent, Profile: signing.ProfileTagWebBotAuth, PrincipalID: "p_platform"}
	unbound := &signing.VerifiedSigner{AgentURL: agencyAgent, Profile: signing.ProfileTagWebBotAuth}
	decl := adcp.AccountInput{Brand: &adcp.BrandReference{Domain: "brand-7k3q.com"}, Operator: "agency-7k3q.com"}

	require.NoError(t, gate.RequireDeclaration(ctx, decl, signer))
	require.NoError(t, gate.RequireDeclaration(ctx, adcp.AccountInput{AccountID: "acc_brand"}, signer))

	code, details := permissionDetails(t, gate.RequireDeclaration(ctx, decl, stranger))
	require.Equal(t, "PERMISSION_DENIED", code)
	require.Equal(t, map[string]any{"scope": "agent", "reason": "grant_absent"}, details)
	_, details = permissionDetails(t, gate.RequireDeclaration(ctx, adcp.AccountInput{AccountID: "acc_unknown"}, signer))
	require.Equal(t, "grant_absent", details["reason"])
	_, details = permissionDetails(t, gate.RequireDeclaration(ctx, adcp.AccountInput{Operator: "agency-7k3q.com"}, signer))
	require.Equal(t, "grant_absent", details["reason"], "an entry with no brand has no grant authority")

	// An identity-established (unbound) Web Bot Auth signer never
	// provisions accounts, even when a grant would cover it.
	code, details = permissionDetails(t, gate.RequireDeclaration(ctx, decl, unbound))
	require.Equal(t, "PERMISSION_DENIED", code)
	require.Nil(t, details)

	// No established identity: PERMISSION_DENIED without details (the
	// cross-tenant oracle clamp).
	code, details = permissionDetails(t, gate.RequireDeclaration(ctx, decl, nil))
	require.Equal(t, "PERMISSION_DENIED", code)
	require.Nil(t, details)

	// Operation scope: a media-buying grant covers media-buying operations
	// only, unless the seller names the operation's scope.
	require.NoError(t, gate.RequireAccountForOperation(ctx, "acc_brand", "create_media_buy", signer))
	_, details = permissionDetails(t, gate.RequireAccountForOperation(ctx, "acc_brand", "build_creative", signer))
	require.Equal(t, "grant_absent", details["reason"])
	gate.OperationClaim = func(_ context.Context, id, op string) (GrantClaim, error) {
		return GrantClaim{BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com", Scope: ScopeCreativeGeneration}, nil
	}
	_, details = permissionDetails(t, gate.RequireAccountForOperation(ctx, "acc_brand", "build_creative", signer))
	require.Equal(t, "grant_absent", details["reason"], "the grant does not cover creative generation")

	gate.OperationClaim = nil
	callReq := toolRequestWithSigner(signer)
	callReq.Params = &mcp.CallToolParamsRaw{Name: "create_media_buy"}
	require.NoError(t, gate.RequireAccountForToolRequest(ctx, callReq, "acc_brand"))
	callReq.Params.Name = "build_creative"
	require.Error(t, gate.RequireAccountForToolRequest(ctx, callReq, "acc_brand"))
	require.Error(t, gate.RequireAccountForToolRequest(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "create_media_buy"}}, "acc_brand"))

	// The seller hook reads the per-request signer and rejects the whole
	// request before any upsert.
	authorize := gate.SyncAccountsAuthorizer()
	require.NoError(t, authorize(ctx, toolRequestWithSigner(signer), []adcp.AccountInput{decl}))
	require.Error(t, authorize(ctx, toolRequestWithSigner(signer), []adcp.AccountInput{
		decl, {Brand: &adcp.BrandReference{Domain: "elsewhere-7k3q.com"}, Operator: "agency-7k3q.com"},
	}))
	require.Error(t, authorize(ctx, toolRequestWithSigner(nil), []adcp.AccountInput{decl}))
	require.Error(t, authorize(ctx, nil, []adcp.AccountInput{decl}))

	_, err := (&GrantEvaluator{}).Check(ctx, GrantRequest{})
	require.Error(t, err, "a GrantEvaluator without Records")
}

// TestGrantOutageVersusRemoval: a grantor record that cannot be fetched is
// SERVICE_UNAVAILABLE, never grant_absent; a record removed after it was
// read is a removal: its link is gone (grant_absent) and the brand.json
// fallback does not come back.
func TestGrantOutageVersusRemoval(t *testing.T) {
	ctx := context.Background()
	req := GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"}
	legacyCalled := false
	legacy := func(context.Context, GrantRequest) (bool, error) { legacyCalled = true; return true, nil }

	r := grantRig(t, with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"]}]}`}))
	g := &GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}
	res, _ := g.Check(ctx, req)
	require.True(t, res.Authorized)

	// Brand record outage.
	r.server.fail(trustURL("brand-7k3q.com"), errors.New("connection refused"))
	r.now = r.now.Add(2 * time.Minute)
	res, _ = g.Check(ctx, req)
	require.False(t, res.Authorized)
	require.True(t, res.Unavailable)
	code, _ := permissionDetails(t, res.Err())
	require.Equal(t, "SERVICE_UNAVAILABLE", code)

	// Brand record removed after it was read.
	r.server.set(trustURL("brand-7k3q.com"), http.StatusGone, "")
	r.now = r.now.Add(2 * time.Minute)
	res, _ = g.Check(ctx, req)
	require.False(t, res.Authorized)
	require.False(t, res.Unavailable)
	require.Equal(t, GrantReasonAbsent, res.Reason)
	require.False(t, legacyCalled, "authorized_operators does not come back after a removal")
	_, details := permissionDetails(t, res.Err())
	require.Equal(t, "grant_absent", details["reason"])

	// Intermediary outage on a two-link chain.
	r2 := grantRig(t, with(baseRecords, map[string]string{
		"brand-7k3q.com":  `{"grants":[{"grantee":"agency-7k3q.com","scopes":["adcp:media_buying"]}]}`,
		"agency-7k3q.com": `{"agents":[{"url":"https://buy.agency-7k3q.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform-7k3q.com","scopes":["adcp:media_buying"]}]}`,
	}))
	g2 := &GrantEvaluator{Records: r2.eval}
	chain := GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand-7k3q.com", AccountOperator: "agency-7k3q.com"}
	res, _ = g2.Check(ctx, chain)
	require.True(t, res.Authorized)
	r2.server.fail(trustURL("agency-7k3q.com"), errors.New("timeout"))
	r2.now = r2.now.Add(2 * time.Minute)
	res, _ = g2.Check(ctx, chain)
	require.True(t, res.Unavailable)
	// The intermediary removes its record: the second link is gone.
	r2.server.set(trustURL("agency-7k3q.com"), http.StatusNotFound, "")
	r2.now = r2.now.Add(2 * time.Minute)
	res, _ = g2.Check(ctx, chain)
	require.False(t, res.Authorized)
	require.False(t, res.Unavailable)
	require.Equal(t, GrantReasonAbsent, res.Reason)

	// The signer's own operator record is unreachable: an outage.
	r3 := grantRig(t, with(baseRecords, map[string]string{"brand-7k3q.com": `{"grants":[]}`}))
	r3.server.fail(trustURL("agency-7k3q.com"), errors.New("timeout"))
	res, _ = (&GrantEvaluator{Records: r3.eval}).Check(ctx, req)
	require.True(t, res.Unavailable)
}
