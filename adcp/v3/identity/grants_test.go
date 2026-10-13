package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// The grant fixtures model DR-0025's parties:
//   - brand.com, the brand, which publishes grants;
//   - agency.com, an agency named as account.operator;
//   - platform.com, a platform hosting the agency's buying agent;
//   - buyer agents at https://buy.agency.com and https://agent.platform.com.
const (
	agencyAgent   = "https://buy.agency.com"
	platformAgent = "https://agent.platform.com"
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
	"agency.com":   `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}]}`,
	"platform.com": `{"agents":[{"url":"https://agent.platform.com/mcp","roles":["adcp:buying"]}]}`,
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
	brandGrantsAgency := `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"],"countries":["US","CA"],"profiles":{"adcp":{"brands":["nova"]}},"valid_until":"2027-06-30T00:00:00Z"}]}`
	cases := []struct {
		name    string
		records map[string]string
		req     GrantRequest
		want    bool
		reason  string
	}{
		{
			name:    "implicit when operator, brand, and signer share a registrable domain",
			records: map[string]string{"agency.com": baseRecords["agency.com"]},
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "house.agency.com", AccountOperator: "agency.com"},
			want:    true,
		},
		{
			name:    "direct grant to the signer's operator, which is account.operator",
			records: with(baseRecords, map[string]string{"brand.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova", Countries: []string{"US"}},
			want:    true,
		},
		{
			name:    "a grant does not cover a brand it does not list",
			records: with(baseRecords, map[string]string{"brand.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "other", Countries: []string{"US"}},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a country-limited grant covers no claim outside it",
			records: with(baseRecords, map[string]string{"brand.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova", Countries: []string{"US", "MX"}},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a country-limited grant covers no claim without countries",
			records: with(baseRecords, map[string]string{"brand.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova"},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "the scope must be covered",
			records: with(baseRecords, map[string]string{"brand.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova", Countries: []string{"US"}, Scope: ScopeCreativeGeneration},
			reason:  GrantReasonAbsent,
		},
		{
			name: "adcp:all covers adcp scopes and * covers everything",
			records: with(baseRecords, map[string]string{"brand.com": `{"grants":[{"grantee":"agency.com","scopes":["adcp:all"]}]}`,
				"other.com": `{"grants":[{"grantee":"agency.com","scopes":["*"]}]}`}),
			req:  GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", Scope: ScopeCreativeGeneration},
			want: true,
		},
		{
			name:    "account.operator must be on the chain",
			records: with(baseRecords, map[string]string{"brand.com": brandGrantsAgency}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "someone-else.com", BrandID: "nova", Countries: []string{"US"}},
			reason:  GrantReasonAbsent,
		},
		{
			name: "chain through account.operator to the hosting platform",
			records: with(baseRecords, map[string]string{
				"brand.com":  brandGrantsAgency,
				"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform.com","scopes":["adcp:media_buying"],"agents":[{"url":"https://agent.platform.com/mcp"}]}]}`,
			}),
			req:  GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova", Countries: []string{"CA"}},
			want: true,
		},
		{
			name: "intersection: the second link must cover the claim's countries too",
			records: with(baseRecords, map[string]string{
				"brand.com":  brandGrantsAgency,
				"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform.com","scopes":["adcp:media_buying"],"countries":["US"]}]}`,
			}),
			req:    GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova", Countries: []string{"CA"}},
			reason: GrantReasonAbsent,
		},
		{
			name: "agents[] narrowing is matched by canonical origin",
			records: with(baseRecords, map[string]string{
				"brand.com":  brandGrantsAgency,
				"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform.com","scopes":["adcp:media_buying"],"agents":[{"url":"https://other.platform.com/mcp"}]}]}`,
			}),
			req:    GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand.com", AccountOperator: "agency.com", BrandID: "nova", Countries: []string{"CA"}},
			reason: GrantReasonAbsent,
		},
		{
			name: "no third link: a grant to account.operator's grantee's grantee is not followed",
			records: with(baseRecords, map[string]string{
				"brand.com":    `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"]}]}`,
				"agency.com":   `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"middle.com","scopes":["adcp:media_buying"]}]}`,
				"middle.com":   `{"grants":[{"grantee":"platform.com","scopes":["adcp:media_buying"]}]}`,
				"platform.com": baseRecords["platform.com"],
			}),
			req:    GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"},
			reason: GrantReasonAbsent,
		},
		{
			name: "the buyer operator's record never authorizes a brand outside its domain",
			records: with(baseRecords, map[string]string{
				"brand.com":  `{"grants":[]}`,
				"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"agency.com","scopes":["*"]}]}`,
			}),
			req:    GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"},
			reason: GrantReasonAbsent,
		},
		{
			name:    "an expired grant",
			records: with(baseRecords, map[string]string{"brand.com": `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T11:00:00Z"}]}`}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "a grant not yet valid",
			records: with(baseRecords, map[string]string{"brand.com": `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"],"valid_from":"2026-10-14T00:00:00Z"}]}`}),
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"},
			reason:  GrantReasonAbsent,
		},
		{
			name:    "Web Bot Auth: the signer's operator must list the origin with adcp:buying",
			records: map[string]string{"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:sales"]}]}`},
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "agency.com", AccountOperator: "agency.com"},
			reason:  GrantReasonSignerRecordUnavailable,
		},
		{
			name:    "a brand trust record that cannot be fetched is not absence",
			records: baseRecords,
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "down.com", AccountOperator: "agency.com"},
			reason:  GrantReasonTrustRecordUnavailable,
		},
		{
			name:    "a brand that publishes no trust record and no legacy hook",
			records: baseRecords,
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"},
			reason:  GrantReasonTrustRecordAbsent,
		},
		{
			name:    "no registrable domain",
			records: baseRecords,
			req:     GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.example", AccountOperator: "agency.com"},
			reason:  GrantReasonAbsent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := grantRig(t, tc.records)
			r.server.fail(trustURL("down.com"), errors.New("timeout"))
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
		"brand.com":  `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:50Z"}]}`,
		"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:30Z"},{"grantee":"platform.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:40Z"}]}`,
	}))
	g := &GrantEvaluator{Records: r.eval}
	res, err := g.Check(context.Background(), GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"})
	require.NoError(t, err)
	require.True(t, res.Authorized)
	require.Equal(t, time.Date(2026, 10, 13, 12, 0, 40, 0, time.UTC), res.ExpiresAt, "min over links of each link's latest valid_until")
}

func TestGrantExpiringDuringIntermediaryFetchIsNotAuthorized(t *testing.T) {
	r := grantRig(t, with(baseRecords, map[string]string{
		"brand.com":  `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"],"valid_until":"2026-10-13T12:00:05Z"}]}`,
		"agency.com": `{"agents":[{"url":"https://buy.agency.com/mcp","roles":["adcp:buying"]}],"grants":[{"grantee":"platform.com","scopes":["adcp:media_buying"]}]}`,
	}))
	// Evaluate brand and signer first so only the intermediary fetch runs
	// during Check, and advance the clock as it happens.
	_, _ = r.eval.Evaluate(context.Background(), "brand.com", "")
	_, _ = r.eval.Evaluate(context.Background(), platformAgent, RoleBuying)
	fetch := r.server.fetch
	eval, _ := NewTrustRecordEvaluator(TrustRecordEvaluatorOptions{
		Clock: func() time.Time { return r.now }, PollingInterval: time.Minute,
		Fetch: func(ctx context.Context, url string) (*TrustResponse, error) {
			if url == trustURL("agency.com") {
				r.now = r.now.Add(10 * time.Second)
			}
			return fetch(ctx, url)
		},
	})
	_, _ = eval.Evaluate(context.Background(), "brand.com", "")
	_, _ = eval.Evaluate(context.Background(), platformAgent, RoleBuying)
	g := &GrantEvaluator{Records: eval}
	res, err := g.Check(context.Background(), GrantRequest{AgentOrigin: platformAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"})
	require.NoError(t, err)
	require.False(t, res.Authorized)
}

func TestGrantExclusiveAndHooks(t *testing.T) {
	yes := func(context.Context, GrantRequest) (bool, error) { return true, nil }
	fail := func(context.Context, GrantRequest) (bool, error) { return false, errors.New("db down") }
	req := GrantRequest{AgentOrigin: agencyAgent, BrandDomain: "brand.com", AccountOperator: "agency.com"}
	ctx := context.Background()

	// Without exclusive_grants, an uncovered claim is at the seller's
	// discretion.
	r := grantRig(t, with(baseRecords, map[string]string{"brand.com": `{"grants":[{"grantee":"x.com","scopes":["adcp:media_buying"]}]}`}))
	res, _ := (&GrantEvaluator{Records: r.eval, SellerAuthorization: yes}).Check(ctx, req)
	require.True(t, res.Authorized)
	res, _ = (&GrantEvaluator{Records: r.eval, SellerAuthorization: fail}).Check(ctx, req)
	require.False(t, res.Authorized, "a hook error fails closed")

	// exclusive_grants makes grants[] exhaustive for the scopes it names...
	r = grantRig(t, with(baseRecords, map[string]string{"brand.com": `{"grants":[{"grantee":"x.com","scopes":["adcp:media_buying"]}],"exclusive_grants":true}`}))
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
	r = grantRig(t, with(baseRecords, map[string]string{"brand.com": `{"grants":[]}`}))
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
	r.server.fail(trustURL("brand.com"), errors.New("timeout"))
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
	req := GrantRequest{AgentOrigin: "https://legacy.agency.com/mcp", BrandDomain: "brand.com", AccountOperator: "agency.com", SigningProfile: signing.ProfileTagRequestSigning}

	r := grantRig(t, nil) // the agency publishes no trust record either
	res, _ := (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, req)
	require.True(t, res.Authorized, "no new operator record is needed before the brand publishes")

	r = grantRig(t, map[string]string{"brand.com": `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"]}]}`})
	res, _ = (&GrantEvaluator{Records: r.eval, LegacyAuthorization: legacy}).Check(ctx, req)
	require.False(t, res.Authorized)
	require.Equal(t, GrantReasonSignerRecordUnavailable, res.Reason)

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
		SyncAccountsAuthorizer: func(context.Context, []adcp.AccountInput) error { return err },
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
		"accounts":        []map[string]any{{"brand": map[string]any{"domain": "brand.com"}, "operator": "agency.com", "billing": "operator"}},
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

// contextWithSigner returns the request context the signing middleware
// produces for a Web Bot Auth request verified from origin.
func contextWithSigner(t *testing.T, origin string) context.Context {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk, err := signing.PublicDirectoryKey(key)
	require.NoError(t, err)
	var got context.Context
	h := signing.Middleware(signing.MiddlewareOptions{
		OperationResolver: signing.DefaultOperationResolver,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		WebBotAuth: &signing.WebBotAuthOptions{
			Keys:       stubKeys{origin: jwk},
			Revocation: noRevocations{},
			UnboundFor: []string{"sync_accounts"},
		},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() }))
	r := httptest.NewRequest(http.MethodPost, "https://seller.example.com/adcp/sync_accounts", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	require.NoError(t, signing.SignWebBotAuthRequest(r, key, signing.WBASignOptions{AgentOrigin: origin}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	require.NotNil(t, got)
	s := signing.VerifiedSignerFromContext(got)
	require.NotNil(t, s)
	require.Equal(t, origin, s.AgentURL)
	return got
}

func TestGrantGate(t *testing.T) {
	ctx := context.Background()
	r := grantRig(t, with(baseRecords, map[string]string{"brand.com": `{"grants":[{"grantee":"agency.com","scopes":["adcp:media_buying"]}]}`}))
	gate := &GrantGate{
		Evaluator: &GrantEvaluator{Records: r.eval},
		ExistingAccountClaim: func(_ context.Context, id string) (GrantClaim, error) {
			if id == "acc_brand" {
				return GrantClaim{BrandDomain: "brand.com", AccountOperator: "agency.com"}, nil
			}
			return GrantClaim{}, errors.New("unknown account")
		},
	}
	signer := &signing.VerifiedSigner{AgentURL: agencyAgent, Profile: signing.ProfileTagWebBotAuth}
	stranger := &signing.VerifiedSigner{AgentURL: platformAgent, Profile: signing.ProfileTagWebBotAuth}

	require.NoError(t, gate.RequireDeclaration(ctx, adcp.AccountInput{Brand: &adcp.BrandReference{Domain: "brand.com"}, Operator: "agency.com"}, signer))
	require.NoError(t, gate.RequireDeclaration(ctx, adcp.AccountInput{AccountID: "acc_brand"}, signer))

	code, details := permissionDetails(t, gate.RequireDeclaration(ctx, adcp.AccountInput{Brand: &adcp.BrandReference{Domain: "brand.com"}, Operator: "agency.com"}, stranger))
	require.Equal(t, "PERMISSION_DENIED", code)
	require.Equal(t, map[string]any{"scope": "agent", "reason": "grant_absent"}, details)
	_, details = permissionDetails(t, gate.RequireDeclaration(ctx, adcp.AccountInput{AccountID: "acc_unknown"}, signer))
	require.Equal(t, "grant_absent", details["reason"])
	_, details = permissionDetails(t, gate.RequireDeclaration(ctx, adcp.AccountInput{Operator: "agency.com"}, signer))
	require.Equal(t, "grant_absent", details["reason"], "an entry with no brand has no grant authority")

	// No established identity: PERMISSION_DENIED without details (the
	// cross-tenant oracle clamp).
	code, details = permissionDetails(t, gate.RequireDeclaration(ctx, adcp.AccountInput{Brand: &adcp.BrandReference{Domain: "brand.com"}, Operator: "agency.com"}, nil))
	require.Equal(t, "PERMISSION_DENIED", code)
	require.Nil(t, details)

	// The seller hook rejects the whole request before any upsert.
	authorize := gate.SyncAccountsAuthorizer()
	ctxSigned := contextWithSigner(t, agencyAgent)
	require.NoError(t, authorize(ctxSigned, []adcp.AccountInput{{Brand: &adcp.BrandReference{Domain: "brand.com"}, Operator: "agency.com"}}))
	require.Error(t, authorize(ctxSigned, []adcp.AccountInput{
		{Brand: &adcp.BrandReference{Domain: "brand.com"}, Operator: "agency.com"},
		{Brand: &adcp.BrandReference{Domain: "elsewhere.com"}, Operator: "agency.com"},
	}))
	require.Error(t, authorize(ctx, []adcp.AccountInput{{Brand: &adcp.BrandReference{Domain: "brand.com"}, Operator: "agency.com"}}))
}
