// Package identity is the EXPERIMENTAL AdCP 3.3 agent-identity layer above
// request verification: trust.json evaluation, origin-to-principal binding,
// demand-side grants (DR-0025), and Go types for the identity schemas that
// are not yet in a released schema bundle (onboarding posture, principal
// relationship, grant_absent, trust.json v1 without keys).
//
// The design is specs/agent-identity-3-3.md and DR-0023/DR-0025 in
// adcontextprotocol/adcp. The schemas are pinned to draft commits recorded
// in testdata/schemas/UPSTREAM.json and may change before 3.3 ships. The
// SDK's wire pin is unchanged; nothing here is used unless configured.
//
// # Where the trust record is read
//
// signing verifies a Web Bot Auth signature and yields a verified origin. It
// never reads a trust record, and this package is not imported by signing,
// so the signature path cannot consult one. A trust record is evaluated only
// when something is gated on it: binding a principal (BindingGate,
// TrustRecordEvaluator.Bind), evaluating a grant (GrantEvaluator), and open
// onboarding (TrustRecordEvaluator.Evaluate with the required role).
//
// # Authority
//
// A verified origin with no binding is identity-established: it gets what an
// anonymous caller gets. A binding is an explicit seller decision, made only
// after the operator's trust record lists the origin with the required role,
// re-evaluated at least as often as the revocation polling interval, and it
// maps an origin to one principal. Binding onto a principal that already
// uses the RFC 9421 profile needs explicit approval, and a bound origin is
// refused the RFC 9421 profile (signing.MiddlewareOptions.BoundOrigins).
package identity
