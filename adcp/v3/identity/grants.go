package identity

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/adcontextprotocol/adcp-go/adcp/v3"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/internal/psl"
	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GrantRequest is an acts-for claim to evaluate (DR-0025): the signer at
// AgentOrigin acts for the brand at BrandDomain, under the account operator
// AccountOperator, for Scope.
type GrantRequest struct {
	AgentOrigin     string
	BrandDomain     string
	AccountOperator string
	// Scope defaults to adcp:media_buying.
	Scope   string
	BrandID string
	// Countries the claim covers; a grant limited to countries must cover
	// every one, and covers no claim without countries.
	Countries []string
	// SigningProfile is the profile the signer verified under:
	// signing.ProfileTagWebBotAuth (the default) or
	// signing.ProfileTagRequestSigning.
	SigningProfile string
}

// Grant evaluation outcomes. Every denial surfaces externally as
// PERMISSION_DENIED with reason grant_absent; Reason is for logs.
const (
	GrantReasonAbsent                   = "grant_absent"
	GrantReasonSignerRecordUnavailable  = "signer_trust_record_unavailable"
	GrantReasonTrustRecordAbsent        = "trust_record_absent"
	GrantReasonTrustRecordUnavailable   = "trust_record_unavailable"
	GrantReasonAuthorizationHookFailure = "authorization_hook_failed"
)

// GrantAuthorization is the outcome of GrantEvaluator.Check.
type GrantAuthorization struct {
	Authorized bool
	// Reason explains a denial, for logs only.
	Reason string
	// LegacyFallbackAllowed reports that the brand has never published a
	// trust record (404/410 before any 200), the only case in which
	// brand.json authorized_operators may still decide.
	LegacyFallbackAllowed bool
	// ExpiresAt bounds how long an authorization may be reused: the
	// earliest of the records' cache lifetimes and each link's valid_until.
	// It is set on every authorization, including a SellerAuthorization or
	// LegacyAuthorization approval (bounded by one polling interval), and
	// zero only on a denial.
	ExpiresAt time.Time
}

// Err returns nil when authorized, and otherwise PERMISSION_DENIED with
// details {scope: "agent", reason: "grant_absent"} and recovery
// correctable. Call it only after the signer's identity is established:
// before that, PERMISSION_DENIED must omit details (see RequireClaim).
func (a GrantAuthorization) Err() error {
	if a.Authorized {
		return nil
	}
	return grantAbsentError()
}

func grantAbsentError() error {
	d := GrantAbsentDetails()
	return adcp.NewError("PERMISSION_DENIED", adcp.ErrorOptions{
		Message:  "Agent has no authority for this brand",
		Recovery: "correctable",
		Details:  map[string]any{"scope": d.Scope, "reason": d.Reason},
	})
}

// unestablishedDenial is PERMISSION_DENIED for a caller whose identity is
// not established: no details, so the response is no onboarding oracle.
func unestablishedDenial() error {
	return adcp.NewError("PERMISSION_DENIED", adcp.ErrorOptions{
		Message:  "Buyer agent is not authorized",
		Recovery: "correctable",
	})
}

// GrantHook is a seller-owned authorization decision consulted by
// GrantEvaluator. An error fails closed.
type GrantHook func(ctx context.Context, req GrantRequest) (bool, error)

// GrantEvaluator evaluates demand-side grants from the brand's trust record
// (DR-0025, specs/agent-identity-3-3.md R6):
//   - the brand's own record authorizes, never the buyer operator's;
//   - authority is implicit when the account operator, the brand, and the
//     signer's operator share a registrable domain;
//   - otherwise a chain must reach the signer's operator with the account
//     operator on it: the brand grants the signer's operator directly (when
//     it is the account operator), or the brand grants the account
//     operator, whose own record grants the signer's operator. There is no
//     third link;
//   - every link must cover the claim's scope, brand, countries, agent
//     narrowing, and validity window, which is the intersection rule;
//   - exclusive_grants makes grants[] exhaustive for the scopes it names,
//     disabling SellerAuthorization for them;
//   - a 200 from the brand's trust.json makes it the only source of grants,
//     so LegacyAuthorization (brand.json authorized_operators) runs only
//     when the brand has never published one. A fetch failure is never
//     absence and invokes neither hook.
//
// Under Web Bot Auth, the signer's operator must also currently list the
// signer's origin with adcp:buying.
type GrantEvaluator struct {
	Records *TrustRecordEvaluator
	// SellerAuthorization is the seller's discretion for an uncovered claim
	// when grants are not exclusive: its own onboarding records, never the
	// brand's brand.json.
	SellerAuthorization GrantHook
	// LegacyAuthorization is the brand.json authorized_operators check,
	// consulted only when the brand publishes no trust record.
	LegacyAuthorization GrantHook
	// Clock defaults to the evaluator's clock.
	Clock func() time.Time
}

func (g *GrantEvaluator) now() time.Time {
	if g.Clock != nil {
		return g.Clock()
	}
	return g.Records.clock()
}

// Check evaluates req. The error is non-nil only for a malformed request.
func (g *GrantEvaluator) Check(ctx context.Context, req GrantRequest) (GrantAuthorization, error) {
	if g.Records == nil {
		return GrantAuthorization{}, errNoRecords
	}
	if req.Scope == "" {
		req.Scope = ScopeMediaBuying
	}
	if req.SigningProfile == "" {
		req.SigningProfile = signing.ProfileTagWebBotAuth
	}
	if req.SigningProfile != signing.ProfileTagWebBotAuth && req.SigningProfile != signing.ProfileTagRequestSigning {
		return GrantAuthorization{}, errUnsupportedProfile
	}
	origin, err := signing.CanonicalOrigin(req.AgentOrigin)
	if err != nil {
		return denied(GrantReasonAbsent, false)
	}
	req.AgentOrigin = origin
	signerOp, ok1 := psl.RegistrableDomain(origin)
	brandOp, ok2 := psl.RegistrableDomain(req.BrandDomain)
	accountOp, ok3 := psl.RegistrableDomain(req.AccountOperator)
	if !ok1 || !ok2 || !ok3 {
		return denied(GrantReasonAbsent, false)
	}

	var signerRec *EvaluatedTrustRecord
	if req.SigningProfile == signing.ProfileTagWebBotAuth {
		// Web Bot Auth authority always needs a current operator role entry.
		if signerRec, err = g.Records.Evaluate(ctx, origin, RoleBuying); err != nil {
			return denied(GrantReasonSignerRecordUnavailable, false)
		}
		if signerOp == brandOp && brandOp == accountOp {
			return GrantAuthorization{Authorized: true, ExpiresAt: signerRec.ExpiresAt}, nil
		}
	}
	brandRec, err := g.Records.Evaluate(ctx, req.BrandDomain, "")
	if err != nil {
		if IsTrustRecordAbsent(err) {
			if g.LegacyAuthorization != nil {
				ok, herr := g.LegacyAuthorization(ctx, req)
				if herr != nil {
					return denied(GrantReasonAuthorizationHookFailure, true)
				}
				if !ok {
					return denied(GrantReasonAbsent, true)
				}
				// Bound like any trust-record result: re-check after one
				// polling interval.
				return GrantAuthorization{Authorized: true, LegacyFallbackAllowed: true, ExpiresAt: g.now().Add(g.Records.PollingInterval())}, nil
			}
			return denied(GrantReasonTrustRecordAbsent, true)
		}
		return denied(GrantReasonTrustRecordUnavailable, false)
	}
	if signerRec == nil {
		// An RFC 9421 signer keeps its established onboarding path while the
		// brand has no trust record. Once the brand serves 200, grants have
		// one source and need the signer's operator role entry.
		if signerRec, err = g.Records.Evaluate(ctx, origin, RoleBuying); err != nil {
			return denied(GrantReasonSignerRecordUnavailable, false)
		}
		if signerOp == brandOp && brandOp == accountOp {
			return GrantAuthorization{Authorized: true, ExpiresAt: signerRec.ExpiresAt}, nil
		}
	}

	countries := map[string]struct{}{}
	for _, c := range req.Countries {
		countries[c] = struct{}{}
	}
	match := func(grants []TrustGrant, grantee string, at time.Time) []TrustGrant {
		var out []TrustGrant
		for _, gr := range grants {
			if grantMatches(gr, grantee, req, countries, at) {
				out = append(out, gr)
			}
		}
		return out
	}
	used := []*EvaluatedTrustRecord{signerRec, brandRec}
	first := match(brandRec.Record.Grants, accountOp, g.now())
	var links [][]TrustGrant
	switch {
	case accountOp == signerOp:
		links = [][]TrustGrant{first}
	case len(first) > 0:
		intermediary, err := g.Records.Evaluate(ctx, accountOp, "")
		if err != nil {
			return denied(GrantReasonTrustRecordUnavailable, false)
		}
		used = append(used, intermediary)
		// Fetching the intermediary may outlive an earlier grant: evaluate
		// both links at decision time.
		at := g.now()
		first = match(first, accountOp, at)
		second := match(intermediary.Record.Grants, signerOp, at)
		links = [][]TrustGrant{first, second}
	}
	now := g.now()
	for _, r := range used {
		if !now.Before(r.ExpiresAt) {
			return denied(GrantReasonTrustRecordUnavailable, false)
		}
	}
	covered := len(links) > 0
	for _, l := range links {
		if len(l) == 0 {
			covered = false
		}
	}
	if !covered {
		exhaustive := false
		if brandRec.Record.ExclusiveGrants != nil && *brandRec.Record.ExclusiveGrants {
			for _, gr := range brandRec.Record.Grants {
				if scopeCovers(gr.Scopes, req.Scope) {
					exhaustive = true
					break
				}
			}
		}
		if !exhaustive && g.SellerAuthorization != nil {
			ok, err := g.SellerAuthorization(ctx, req)
			if err != nil {
				return denied(GrantReasonAuthorizationHookFailure, false)
			}
			if ok {
				return GrantAuthorization{Authorized: true, ExpiresAt: brandRec.ExpiresAt}, nil
			}
		}
		return denied(GrantReasonAbsent, false)
	}
	// Every surviving grant covers the same requested dimensions, so the
	// best path expires at the minimum over links of each link's latest
	// valid_until, bounded by the records' lifetimes.
	expiry := time.Unix(math.MaxInt32, 0)
	for _, r := range used {
		if r.ExpiresAt.Before(expiry) {
			expiry = r.ExpiresAt
		}
	}
	for _, l := range links {
		var best time.Time
		unbounded := false
		for _, gr := range l {
			if gr.ValidUntil == "" {
				unbounded = true
				break
			}
			if t, err := time.Parse(time.RFC3339Nano, gr.ValidUntil); err == nil && t.After(best) {
				best = t
			}
		}
		if !unbounded && best.Before(expiry) {
			expiry = best
		}
	}
	if !now.Before(expiry) {
		return denied(GrantReasonAbsent, false)
	}
	return GrantAuthorization{Authorized: true, ExpiresAt: expiry}, nil
}

// denied is a denial outcome. A failed fetch or hook is an authorization
// outcome, not an error of Check: it denies, with the cause in Reason.
func denied(reason string, legacyFallbackAllowed bool) (GrantAuthorization, error) {
	return GrantAuthorization{Reason: reason, LegacyFallbackAllowed: legacyFallbackAllowed}, nil
}

type grantError string

func (e grantError) Error() string { return string(e) }

const (
	errUnsupportedProfile = grantError("identity: unsupported authenticated signing profile")
	errNoRecords          = grantError("identity: GrantEvaluator requires Records")
)

func scopeCovers(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope || s == ScopeAny || (s == ScopeAll && strings.HasPrefix(scope, "adcp:")) {
			return true
		}
	}
	return false
}

func grantMatches(g TrustGrant, grantee string, req GrantRequest, countries map[string]struct{}, now time.Time) bool {
	if g.Grantee != grantee || !scopeCovers(g.Scopes, req.Scope) {
		return false
	}
	if g.Agents != nil {
		ok := false
		for _, a := range g.Agents {
			if o, err := signing.CanonicalOrigin(a.URL); err == nil && o == req.AgentOrigin {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if g.Countries != nil {
		if len(countries) == 0 {
			return false
		}
		allowed := map[string]struct{}{}
		for _, c := range g.Countries {
			allowed[c] = struct{}{}
		}
		for c := range countries {
			if _, ok := allowed[c]; !ok {
				return false
			}
		}
	}
	brands := []string{"*"}
	if g.Profiles != nil && g.Profiles.Adcp != nil && g.Profiles.Adcp.Brands != nil {
		brands = g.Profiles.Adcp.Brands
	}
	if !containsStr(brands, "*") && (req.BrandID == "" || !containsStr(brands, req.BrandID)) {
		return false
	}
	if g.ValidFrom != "" {
		t, err := time.Parse(time.RFC3339Nano, g.ValidFrom)
		if err != nil || now.Before(t) {
			return false
		}
	}
	if g.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339Nano, g.ValidUntil)
		if err != nil || !now.Before(t) {
			return false
		}
	}
	return true
}

// GrantClaim is the acts-for claim a request makes: the brand, the account
// operator, and the scope the operation needs.
type GrantClaim struct {
	BrandDomain     string
	AccountOperator string
	BrandID         string
	Countries       []string
	// Scope defaults to adcp:media_buying.
	Scope string
}

// GrantGate applies grant evaluation before account side effects: at
// sync_accounts for every natural-key declaration, and for an existing
// account (including before a spend-committing call) through the seller's
// ExistingAccountClaim, so a caller cannot omit the brand to skip the check.
// A missing grant is a request-level PERMISSION_DENIED: no account is
// created and no account changes status.
type GrantGate struct {
	Evaluator *GrantEvaluator
	// ExistingAccountClaim resolves the claim for an account_id from
	// seller-owned state. Nil denies account_id-only references.
	ExistingAccountClaim func(ctx context.Context, accountID string) (GrantClaim, error)
	// OperationClaim, when set, resolves the claim for an account and an
	// operation, choosing the scope the operation needs.
	OperationClaim func(ctx context.Context, accountID, operation string) (GrantClaim, error)
}

// RequireClaim authorizes claim for signer. A nil signer (no established
// identity) is denied without details, under the cross-tenant oracle clamp.
// A Web Bot Auth signer must also be bound to a principal: an
// identity-established signer gets no account authority (it may not
// provision accounts), so it is denied before any grant is read.
func (g *GrantGate) RequireClaim(ctx context.Context, claim GrantClaim, signer *signing.VerifiedSigner) error {
	if signer == nil || signer.AgentURL == "" {
		return unestablishedDenial()
	}
	profile := signing.ProfileTagRequestSigning
	if signer.Profile == signing.ProfileTagWebBotAuth {
		profile = signing.ProfileTagWebBotAuth
		if signer.PrincipalID == "" {
			return unboundDenial()
		}
	}
	res, err := g.Evaluator.Check(ctx, GrantRequest{
		AgentOrigin:     signer.AgentURL,
		BrandDomain:     claim.BrandDomain,
		AccountOperator: claim.AccountOperator,
		Scope:           claim.Scope,
		BrandID:         claim.BrandID,
		Countries:       claim.Countries,
		SigningProfile:  profile,
	})
	if err != nil {
		return grantAbsentError()
	}
	return res.Err()
}

// unboundDenial is PERMISSION_DENIED for an identity-established signer.
// Its identity is known, but grant_absent would misstate the cause.
func unboundDenial() error {
	return adcp.NewError("PERMISSION_DENIED", adcp.ErrorOptions{
		Message:  "Agent identity is not approved by this seller",
		Recovery: "correctable",
	})
}

// mediaBuyingOperations may use the default adcp:media_buying scope: buys,
// their account provisioning, and the reads and creative work around them
// (the same set as the Python SDK). Other operations need an explicit
// scope from the seller, so a media-buying grant never authorizes, say,
// creative generation merely because both calls name an account.
var mediaBuyingOperations = map[string]struct{}{
	"sync_accounts": {}, "get_products": {}, "list_products": {}, "request_proposals": {},
	"refine_proposals": {}, "decline_proposals": {}, "buy_products": {}, "accept_proposal": {},
	"create_media_buy": {}, "update_media_buy": {}, "control_media_buy": {}, "get_media_buys": {},
	"get_media_buy_delivery": {}, "get_reporting_status": {}, "sync_reporting_receipts": {},
	"provide_performance_feedback": {}, "sync_creatives": {}, "list_creatives": {}, "list_creative_formats": {},
}

// RequireAccount authorizes an existing account for signer, under the
// default adcp:media_buying scope. Use RequireAccountForOperation when the
// operation is known.
func (g *GrantGate) RequireAccount(ctx context.Context, accountID string, signer *signing.VerifiedSigner) error {
	return g.RequireAccountForOperation(ctx, accountID, "", signer)
}

// RequireAccountForOperation authorizes an existing account for signer and
// operation. The claim comes from OperationClaim when set, otherwise from
// ExistingAccountClaim. An operation outside the media-buying set whose
// claim keeps the default adcp:media_buying scope is denied: the seller
// must choose its scope explicitly. Call it before every spend-committing
// call; the evaluator's cache keeps the check fresh.
func (g *GrantGate) RequireAccountForOperation(ctx context.Context, accountID, operation string, signer *signing.VerifiedSigner) error {
	if signer == nil || signer.AgentURL == "" {
		return unestablishedDenial()
	}
	var claim GrantClaim
	var err error
	switch {
	case g.OperationClaim != nil && operation != "":
		claim, err = g.OperationClaim(ctx, accountID, operation)
	case g.ExistingAccountClaim != nil:
		claim, err = g.ExistingAccountClaim(ctx, accountID)
	default:
		return grantAbsentError()
	}
	if err != nil {
		return grantAbsentError()
	}
	if operation != "" && (claim.Scope == "" || claim.Scope == ScopeMediaBuying) {
		if _, ok := mediaBuyingOperations[operation]; !ok {
			return grantAbsentError()
		}
	}
	return g.RequireClaim(ctx, claim, signer)
}

// RequireDeclaration authorizes one sync_accounts entry for signer: a
// natural-key declaration (brand and operator) is checked directly; an
// account_id reference goes through ExistingAccountClaim. An entry with
// neither has no grant authority.
func (g *GrantGate) RequireDeclaration(ctx context.Context, account adcp.AccountInput, signer *signing.VerifiedSigner) error {
	if signer == nil || signer.AgentURL == "" {
		return unestablishedDenial()
	}
	if account.Brand != nil && account.Brand.Domain != "" && account.Operator != "" {
		return g.RequireClaim(ctx, GrantClaim{
			BrandDomain:     account.Brand.Domain,
			AccountOperator: account.Operator,
			BrandID:         account.Brand.BrandID,
		}, signer)
	}
	if account.AccountID != "" {
		return g.RequireAccountForOperation(ctx, account.AccountID, "sync_accounts", signer)
	}
	return grantAbsentError()
}

// SyncAccountsAuthorizer returns a hook for adcp.Config.SyncAccountsAuthorizer:
// every entry must be authorized, for the signer the signing middleware
// verified on this tool call's HTTP request, before any upsert. It reads
// the signer from the tool request (signing.VerifiedSignerFromToolRequest),
// never from ctx, which in a stateful MCP session belongs to the session's
// initialize request. This requires signing.MiddlewareOptions.WebBotAuth.
func (g *GrantGate) SyncAccountsAuthorizer() func(ctx context.Context, req *mcp.CallToolRequest, accounts []adcp.AccountInput) error {
	return func(ctx context.Context, req *mcp.CallToolRequest, accounts []adcp.AccountInput) error {
		signer := signing.VerifiedSignerFromToolRequest(req)
		for _, a := range accounts {
			if err := g.RequireDeclaration(ctx, a, signer); err != nil {
				return err
			}
		}
		return nil
	}
}
