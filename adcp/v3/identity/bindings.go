package identity

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
)

// BindOptions qualifies a binding.
type BindOptions struct {
	// ExistingRFC9421Principal marks principalID as a principal that already
	// authenticates with the RFC 9421 profile. Binding onto it needs
	// MigrationApproved: controlling the agent's host was not enough to
	// obtain its RFC 9421 keys, so origin control alone must not inherit
	// that principal.
	ExistingRFC9421Principal bool
	// MigrationApproved records the seller's explicit, out-of-band approval
	// to bind onto an existing RFC 9421 principal. Never set automatically.
	MigrationApproved bool
	// Role is the trust-record role the origin must carry. Defaults to
	// adcp:buying.
	Role string
}

// BindingStore records origin-to-principal bindings: the seller's explicit,
// audited decisions. An origin maps to at most one principal; a principal
// may own several origins. Implementations are application-owned and
// durable in production. Discovery and verification never write bindings.
type BindingStore interface {
	signing.OriginBindingLookup
	Bind(ctx context.Context, origin, principalID string, opts BindOptions) error
}

// ErrRebind is returned when an origin is already bound to a different
// principal.
var ErrRebind = errors.New("identity: an origin cannot be rebound to another principal")

// ErrMigrationNotApproved is returned when binding onto an existing RFC 9421
// principal without explicit approval.
var ErrMigrationNotApproved = errors.New("identity: binding an existing RFC 9421 principal requires explicit approval")

// OriginBindings is an in-memory BindingStore for one process, for tests and
// examples. Production deployments supply a durable store. Bindings persist
// when the operator later delists an origin: the BindingGate then denies
// authority, but the historical binding still refuses an RFC 9421
// downgrade.
type OriginBindings struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewOriginBindings returns an empty OriginBindings.
func NewOriginBindings() *OriginBindings {
	return &OriginBindings{m: map[string]string{}}
}

// Bind implements BindingStore.
func (b *OriginBindings) Bind(_ context.Context, origin, principalID string, opts BindOptions) error {
	canonical, err := signing.CanonicalOrigin(origin)
	if err != nil || !strings.HasPrefix(canonical, "https://") || principalID == "" {
		return errors.New("identity: binding requires an HTTPS origin and a principal ID")
	}
	if opts.ExistingRFC9421Principal && !opts.MigrationApproved {
		return ErrMigrationNotApproved
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.m[canonical]; ok && existing != principalID {
		return ErrRebind
	}
	b.m[canonical] = principalID
	return nil
}

// PrincipalForOrigin implements signing.OriginBindingLookup.
func (b *OriginBindings) PrincipalForOrigin(_ context.Context, origin string) (string, bool, error) {
	canonical, err := signing.CanonicalOrigin(origin)
	if err != nil {
		return "", false, nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	p, ok := b.m[canonical]
	return p, ok, nil
}

// BindingGate is the signing.WBAAuthorizer that turns a verified origin
// into a principal. An unbound origin is identity-established (it returns
// ""; the middleware then allows only its UnboundFor operations). A bound
// origin is re-evaluated against its operator's trust record on every
// request, through the evaluator's cache, which is bounded by the
// revocation polling interval: when the operator delists the origin, or the
// record cannot be fetched, authority ends within one cache lifetime and
// the request is denied. The binding itself is kept, so the origin still
// cannot fall back to the RFC 9421 profile.
type BindingGate struct {
	Bindings signing.OriginBindingLookup
	Records  *TrustRecordEvaluator
	// Role defaults to adcp:buying. Configure the role your receiving
	// surface needs.
	Role string
}

// AuthorizeWBA implements signing.WBAAuthorizer.
func (g *BindingGate) AuthorizeWBA(ctx context.Context, signer *signing.VerifiedSigner, _ string) (string, error) {
	if g.Bindings == nil {
		return "", nil
	}
	principal, bound, err := g.Bindings.PrincipalForOrigin(ctx, signer.AgentURL)
	if err != nil {
		return "", err
	}
	if !bound {
		return "", nil
	}
	if g.Records == nil {
		return "", errors.New("identity: binding evaluation unavailable")
	}
	role := g.Role
	if role == "" {
		role = RoleBuying
	}
	if _, err := g.Records.Evaluate(ctx, signer.AgentURL, role); err != nil {
		return "", err
	}
	return principal, nil
}
