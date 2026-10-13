# Agent identity in AdCP 3.3: adcp-go migration note

This note covers the experimental AdCP 3.3 agent-identity support in `github.com/adcontextprotocol/adcp-go/adcp/v3` (issue [#556](https://github.com/adcontextprotocol/adcp-go/issues/556)). It is the adcp-go entry for the SDK table in the spec's migration guide, [Migrating agent identity in AdCP 3.3](https://adcontextprotocol.org/docs/reference/migration/agent-identity-3-3).

Everything here is **opt-in and experimental**.
- **Wire pin.** It is unchanged: `adcp/v3/schemas/VERSION` stays at 3.2.x, and nothing advertises 3.3.
- **Pinned drafts.** The Web Bot Auth wire rules and vectors are pinned to adcontextprotocol/adcp#7894 at `656bd080`. The identity schemas are pinned to the draft commits in [`adcp/v3/identity/testdata/schemas/UPSTREAM.json`](../adcp/v3/identity/testdata/schemas/UPSTREAM.json).
- **Change.** Both may still change before 3.3 ships.
- **Default behavior.** Existing APIs behave exactly as before unless you set the new options.

## What is where

| Need | API |
|---|---|
| Sign as a Web Bot Auth agent | `signing.SignerOptions.AgentOrigin` (or `SignWebBotAuthRequest`), `SignedHTTPClientOptions.AgentOrigin` |
| Publish the key directory | `signing.NewDirectoryPublisher` (an `http.Handler`), `signing.SignKeyDirectory`, `cmd/adcp-wba-directory` |
| Verify Web Bot Auth | `signing.MiddlewareOptions.WebBotAuth`, or `signing.VerifyWebBotAuthRequest` |
| Resolve many signers by `Signature-Agent` | `signing.NewDirectoryResolver` (keyed by origin and RFC 7638 thumbprint) |
| Origin revocation lists | `signing.NewOriginRevocationChecker`, `signing.RevocationDetails` |
| Canonical origin | `signing.CanonicalOrigin` |
| trust.json authoring and validation | `identity.ValidateTrustRecord`, `identity.MarshalTrustRecord` |
| Trust-record evaluation | `identity.NewTrustRecordEvaluator`, `identity.TrustRecordURL` |
| Bind an origin to a principal | `identity.TrustRecordEvaluator.Bind`, `identity.OriginBindings` (in memory), `identity.BindingGate` |
| Grants at `sync_accounts` (DR-0025) | `identity.GrantEvaluator`, `identity.GrantGate`, `adcp.Config.SyncAccountsAuthorizer` |
| New schema types | `identity.AgentOnboarding` and its tiers, requirements, and enums; `identity.BuyerOnboardingPosture`; `identity.PrincipalRelationship`; `identity.PrincipalChanged*` reasons; `identity.GrantAbsentDetails`; `identity.TrustRecord`; `identity.RequestSigningCapabilities` (`profiles`) |

## Buyer signer

1. Give the agent its own HTTPS origin, one agent per origin.
2. Sign with the Web Bot Auth profile:

   ```go
   priv, _, _ := signing.LoadPrivateKey(pemBytes) // Ed25519 or P-256
   client, _ := signing.NewSignedHTTPClient(signing.SignedHTTPClientOptions{
       PrivateKey:         priv,
       AgentOrigin:        "https://buyer.example.com",
       CapabilityProvider: capsFor,     // the seller's request_signing block
       ProfilesProvider:   profilesFor, // the seller's request_signing.profiles
   })
   ```

   `AgentOrigin` sets and covers `Signature-Agent`. The signature carries `tag="web-bot-auth"`, a 256-bit nonce, the key's thumbprint as `keyid`, and an algorithm derived from the key. The digest is always covered on a body. With a `CapabilityProvider`, the client sends only when the seller lists `web-bot-auth`. Otherwise it returns `ErrWebBotAuthNotAdvertised` and never downgrades on its own. `identity.AdvertisedRequestSigningProfiles` reads the list from a capabilities response.

3. Serve the signed key directory on that origin:

   ```go
   pub, _ := signing.NewDirectoryPublisher(signing.DirectoryPublisherOptions{
       AgentOrigin: "https://buyer.example.com", PrivateKeys: []any{priv, nextKey},
   })
   mux.Handle(signing.DirectoryPath, pub) // re-signs before the signatures expire
   ```

   For static hosting, run `adcp-wba-directory --origin ... --key ... --out-body ... --out-headers ...` again before `--lifetime` elapses. Publish a key before signing with it, because verifiers cache a directory for up to five minutes.

4. Serve a signed revocation list at `/.well-known/governance-revocations.json` on the same origin (`adcp-gov-revocation+jws`, signed by a directory key). **Sellers using this SDK fail closed when they cannot read it**, as the Python SDK does.
5. List the origin in `https://{your registrable domain}/.well-known/trust.json` with `adcp:buying`. `identity.MarshalTrustRecord(rec, "your-domain.com")` validates it before you publish.

Keep your RFC 9421 setup (`KeyID`, brand.json `jwks_uri`) for sellers that have not moved. The default `Signer` never emits or covers `Signature-Agent`.

## Seller verifier

```go
keys := signing.NewDirectoryResolver(signing.DirectoryResolverOptions{})
revocations, _ := signing.NewOriginRevocationChecker(signing.OriginRevocationCheckerOptions{Keys: keys})
records, _ := identity.NewTrustRecordEvaluator(identity.TrustRecordEvaluatorOptions{PollingInterval: time.Minute})
bindings := identity.NewOriginBindings() // supply a durable identity.BindingStore in production

mw := signing.Middleware(signing.MiddlewareOptions{
    Resolver: rfc9421Resolver,                 // RFC 9421 keeps working through 3.x
    Replay:   sharedReplayStore,               // shared by both profiles
    WebBotAuth: &signing.WebBotAuthOptions{
        Keys:        keys,
        Revocation:  revocations,
        Authorizer:  &identity.BindingGate{Bindings: bindings, Records: records},
        Authorities: []string{"seller.example.com"}, // the host names this endpoint serves
    },
    BoundOrigins: bindings,                    // refuse RFC 9421 for a bound origin
})
// Install mw inside (after) any bearer-token middleware.
```

- **Profile selection.** A request with `Signature-Agent` or a `web-bot-auth` tag is verified under Web Bot Auth only, including under `ObserveOnly`. An uncovered `Signature-Agent` member is never attributed.
- **Body.** A non-empty signed body must be strict JSON: no duplicate keys, including keys that differ only in case. Anything else is `400`.
- **Authorities.** Set `Authorities` so that a signature captured at another seller cannot be replayed to this endpoint under that seller's `Host`.
- **Errors.** Failures are `400`, `403` with `Accept-Signature`, or `429`. A revoked key or an origin without authority gets a generic `PERMISSION_DENIED` and no `Accept-Signature`. `request_signature_*` codes remain for the RFC 9421 profile.
- **Identity-established.** A verified origin with no binding may call only `UnboundFor` (default `get_adcp_capabilities` and `get_principal`). Set it to your anonymous permissions plus `get_principal`.
  - The MCP session methods (`initialize`, `notifications/initialized`, `ping`, `tools/list`) and bodyless streamable-HTTP `GET`/`DELETE` are always allowed in addition, so the signer can open and close a session.
  - A2A deployments resolve skills with `OperationResolver`.
  - `get_principal` should return `unconfigured`, with `relationship` (an `identity.PrincipalRelationship`) when an application is in progress.
  - Add `sync_principal` only when its handler implements an explicit `open` policy.
- **Binding.** This is an explicit seller decision: `records.Bind(ctx, signer, principalID, bindings, identity.BindOptions{})`. The operator's trust record must list exactly one agent at the origin with `adcp:buying`.
  - An origin maps to one principal. Binding onto a principal that already uses RFC 9421 needs `ExistingRFC9421Principal: true, MigrationApproved: true`. Set those from your own records: the zero value treats the principal as new, as in the Python SDK.
  - `BindingGate` re-evaluates the trust record on every request, through the evaluator's cache, which is bounded by the polling interval. When the operator delists the origin, or its record cannot be fetched, the bound origin is denied every operation, including the `UnboundFor` ones. This matches the Python SDK and is raised upstream. The binding stays, so the origin still cannot downgrade to RFC 9421.
- **The trust record is never read on the signature path.** The `signing` package cannot import `identity`, because `identity` imports `signing`.
- **MCP tool handlers.** Read the signer with `signing.VerifiedSignerFromToolRequest(req)`. A stateful go-sdk session binds handlers to the context of its `initialize` request, so `VerifiedSignerFromContext` can return another request's signer there. The middleware places every verified signer, under either profile, in the per-request `auth.TokenInfo`. It sets only `TokenInfo.Extra`, never `UserID`, and the MCP SDK copies it into `req.Extra`. `GrantGate.RequireAccountForToolRequest` uses it.
- **Grants.** Set `adcp.Config.SyncAccountsAuthorizer = gate.SyncAccountsAuthorizer()`, with `gate := &identity.GrantGate{Evaluator: &identity.GrantEvaluator{Records: records}, ExistingAccountClaim: ...}`.
  - The hook reads the per-request signer (Web Bot Auth or RFC 9421) and checks every entry before the handler runs.
  - An identity-established Web Bot Auth signer (no `PrincipalID`) never provisions accounts.
  - A missing grant is `PERMISSION_DENIED` with `{scope: "agent", reason: "grant_absent"}`, or with no details when no identity is established.
  - Before spend-committing calls, call `gate.RequireAccountForToolRequest(ctx, req, accountID)`. An operation outside media buying needs an explicit scope (`OperationClaim`).
  - `GrantEvaluator.LegacyAuthorization` (brand.json `authorized_operators`) runs only while the brand has never served a trust.json. `SellerAuthorization` is your discretion for uncovered claims and is disabled by `exclusive_grants`.
- **Revocation.** `OriginRevocationChecker` retains every thumbprint-shaped revoked kid, at most 1024 per origin. It keeps `keyCompromise` and the earliest `invalidity_date`, and refuses older lists. After an origin is evicted, that holds only while the origin stays in the history. The default in-memory history is bounded, with per-operator quotas, and an attacker with many registrable domains can flush it. **Public deployments should supply a durable `RevocationHistory`.** At capacity it evicts the least recently used origin rather than refusing new ones. `RevocationDetails.Exposes(receivedAt)` tells you which accepted buys came from suspect requests; never unwind them automatically.
- **Advertising.** Advertise the profile with `identity.RequestSigningCapabilities{Profiles: []string{signing.ProfileTagRequestSigning, signing.ProfileTagWebBotAuth}}`, and advertise onboarding with `identity.AccountCapabilities.AgentOnboarding` (list `account.agent_onboarding` in `experimental_features`).

## Deprecation

AdCP 3.3 deprecates the RFC 9421 profile. It stays fully functional through 3.x and is removed in 4.0. `signing.Middleware` logs this once per process when `WebBotAuth` is not set. The RFC 9421 APIs are not marked `Deprecated:` in Go, so `staticcheck` builds keep passing while 3.x still requires them. JWS document signing (governance context, response signing, rights attestations) stays on the RFC 9421 chain until 3.4.

## Rollback

- **Signers:** clear `AgentOrigin` and set `KeyID` to your brand.json kid to sign with RFC 9421 again. A seller that has bound your origin refuses that until it unbinds.
- **Sellers:** remove `WebBotAuth`. Bindings remain in your store and still block RFC 9421 for those origins through `BoundOrigins`, so unbind them first.

## Not covered yet

- **Legacy module.** These features ship in `adcp/v3` only. The legacy `adcp` module is frozen at v2 (see MIGRATING.md) and received only the covered-header tolerance.
- **Webhooks.** Web Bot Auth webhooks are ordinary signed requests and verify with the same middleware. The `adcp/v3/webhook` publisher does not sign them yet, and the `signing_profile` registration field is not modeled.
- **Durable state.** These are in memory: bindings, revocation history (beyond a bounded LRU), replay state, and the record of which operators have served a trust.json (which keeps a later 404 from re-enabling the brand.json fallback). Persistent stores are the application's, behind `BindingStore`, `RevocationHistory`, and `ReplayStore`.
- **Released inputs.** The final 3.3 schema bundle and the P7 trust-record and grant-chain vectors are upstream release dependencies. Re-pin and rerun conformance when they land.
