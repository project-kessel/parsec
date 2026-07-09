# RHCLOUD-47315: Reject impersonated tokens and enforce IdP claim presence in JWT validation

**JIRA**: https://redhat.atlassian.net/browse/RHCLOUD-47315
**Status**: In Progress
**Author**: AI Assistant
**Date**: 2026-07-08

## Context

Two security checks that insights-3scale enforces are absent from parsec:

1. **Impersonated tokens pass through unchecked.** When an SSO admin
   impersonates a user, Keycloak mints a JWT with `impersonated: true`.
   insights-3scale returns 401; parsec accepts the token and issues.

2. **No IdP enforcement.** When `APICAST_ENFORCE_IDP_AUTH=true`,
   insights-3scale requires tokens to carry an `idp` claim. Parsec has no
   equivalent.

### Acceptance Criteria

- [ ] AC1: Tokens with `impersonated: true` are rejected before issuance when configured
- [ ] AC2: Tokens missing `idp` claim are rejected before issuance when configured
- [ ] AC3: Error messages are clear and descriptive
- [ ] AC4: Both checks are observable via OpenTelemetry (histogram result attributes)
- [ ] AC5: Config is documented with examples showing 3scale parity
- [ ] AC6: Existing tests pass; new tests cover both positive and negative cases
- [ ] AC7: Policy applies to both ext_authz and exchange flows

### External References

- Parent: [RHCLOUD-46385](https://redhat.atlassian.net/browse/RHCLOUD-46385) — Investigate matching OIDC to x-rh-identity parity with 3scale

## Design

### Server Code vs. Configuration

> **Answer these questions FIRST before proceeding with any design.**

| Question | Answer |
|----------|--------|
| Does this modify server Go code or use configuration/policy? | Both: adds a new generic issuance policy abstraction + configuration |
| If server code: is the change generic (any IdP/vendor/deployment) or specific? | **Generic.** The server code evaluates claim assertions by name from configuration — it never mentions `impersonated`, `idp`, Keycloak, or any specific IdP. |
| Does any proposed server code hardcode claim names, issuer URLs, vendor behaviors, or deployment-specific logic? | **No.** Claim names are purely in YAML configuration, not in Go code. |
| Which existing parsec policy/config layer fits? | **None exactly.** Existing layers: validators (trust establishment), AuthzCheckPolicy (ext_authz-only gating), claim mappers (transformation). See analysis below. |
| If none: does this need a new abstraction layer? | **Yes — issuance policy.** Split into abstraction PR + config follow-up. |

### Architectural Layer Analysis

_Feedback from Alec (project lead) identified a fundamental layer misplacement
in the v1 draft of this plan, which proposed adding these checks to the
`jwt_validator` (trust layer)._

**Why NOT the validator layer:**
Validators establish *trust* — is this token valid? Who issued it? Are the
claims authentic? The `aud` check belongs there because a token not addressed
to us shouldn't be parsed at all. But impersonation and IdP checks are *policy
over trusted claims* — the token IS valid, but we have a policy about whether
those claims are acceptable for issuance. An impersonated token is
cryptographically valid; we choose not to act on it. That's policy, not trust.

**Why NOT AuthzCheckPolicy:**
`AuthzCheckPolicy` sits between validation and issuance in the **ext_authz
flow only**. The exchange flow goes directly from `trust.Store.Validate()` to
`TokenService.IssueTokens()` with no policy checkpoint. Impersonation rejection
must apply to **both** entry points — an impersonated token should be rejected
regardless of whether it arrives via ext_authz or token exchange.

**Why NOT claim mappers:**
Mappers transform claims — they build the token's claim structure. Mixing
rejection logic into mappers violates single responsibility and makes error
handling awkward (mappers returning errors to signal policy denial).

**The right layer — issuance policy on TokenService:**
A new `IssuancePolicy` interface on `TokenService`, evaluated before any
token issuance begins. This is:
- **Universal**: both ext_authz and exchange flow through `TokenService`
- **Correct separation**: trust establishes identity, policy gates issuance
- **Composable**: multiple policies can be chained
- **Generic**: claim names come from config, not code

### Approach

Introduce a new **issuance policy** abstraction as a pre-issuance hook on
`TokenService`. The first implementation is `ClaimAssertionPolicy` — a generic,
config-driven policy that evaluates claim presence/absence and value rejection.

```
Credential Validation (trust layer)
    │
    ▼
trust.Result (authenticated claims)
    │
    ├──► ext_authz: AuthzCheckPolicy.Decide() → issue / allow / deny
    │                                               │
    │                                               ▼ (if issue)
    └──► TokenService.IssueTokens()
              │
              ▼
         IssuancePolicy.Evaluate(subject) ◄── NEW: gates issuance
              │
              ▼ (if allowed)
         Issuer.Issue() → Token
```

**`IssuancePolicy` interface** (in `internal/service/`):

```go
type IssuancePolicy interface {
    Evaluate(ctx context.Context, subject *trust.Result) error
}
```

**`ClaimAssertionPolicy` implementation** (in `internal/service/`):

Evaluates two kinds of claim assertions from configuration:
1. **`required_claims: []string`** — claim names that must be present.
   Covers `require_idp_claim`: `required_claims: ["idp"]`.
2. **`rejected_claims: map[string]any`** — claim name → value pairs.
   Covers `reject_impersonated`: `rejected_claims: {impersonated: true}`.

Both default to empty (no enforcement), preserving backward compatibility.

**Value comparison**: `rejected_claims` compares values using
`reflect.DeepEqual`. This handles booleans (the primary use case) and strings
correctly. JSON-parsed numbers (`float64`) vs YAML-parsed numbers (`int`) may
not match; acceptable since numeric rejection is an edge case.

**Injection**: `TokenService` gains a `WithIssuancePolicy(IssuancePolicy)`
functional option. When set, `IssueTokens` evaluates the policy before
entering the issuance loop. When nil (default), no policy check — backward
compatible.

### Alternatives Considered

| Alternative | Pros | Cons | Why not |
|-------------|------|------|---------|
| Per-validator config (`required_claims` / `rejected_claims` on `jwt_validator`) | Simple, follows `audiences` pattern | Wrong layer: validators establish trust, not policy; must be configured redundantly per validator | Conceptual mismatch (v1 of this plan) |
| Extend `AuthzCheckPolicy` | Existing abstraction, no new interface | ext_authz only — exchange flow not covered | Incomplete coverage |
| Claim mapper rejection | Uses existing layer | Mappers transform, not gate; error semantics are wrong | SRP violation |
| CEL-based issuance policy | Maximum flexibility | Over-engineering for claim presence/value checks; CEL can be added later as another `IssuancePolicy` impl | Future enhancement, not first impl |

### Interface Changes

**New `IssuancePolicy` interface** (in `internal/service/`):

```go
// IssuancePolicy evaluates whether token issuance should proceed based on
// the authenticated subject's validated claims. This sits between credential
// validation (trust layer) and token issuance (service layer).
//
// Validators establish trust — they verify a credential is authentic and
// extract identity claims. IssuancePolicy decides whether those trusted
// claims are acceptable for token issuance.
type IssuancePolicy interface {
    Evaluate(ctx context.Context, subject *trust.Result) error
}
```

**New `ClaimAssertionPolicy` struct** (in `internal/service/`):

```go
type ClaimAssertionPolicy struct {
    requiredClaims []string
    rejectedClaims map[string]any
}
```

**`TokenService`** — new optional field + constructor option:

```go
type TokenService struct {
    // ...existing fields...
    issuancePolicy IssuancePolicy
}

func WithIssuancePolicy(p IssuancePolicy) TokenServiceOption { ... }
```

**`TokenIssuanceProbe`** — one new method:

```go
type TokenIssuanceProbe interface {
    // ...existing methods...
    IssuancePolicyDenied(err error)
}
```

### Package Impact

| Package | Change Type | Description |
|---------|------------|-------------|
| `internal/service` | Modified | New `IssuancePolicy` interface; `ClaimAssertionPolicy` impl; `TokenService` option + pre-issuance hook; `TokenIssuanceProbe` new method; NoOps updated |
| `internal/config` | Modified | New `IssuancePolicyConfig` struct; wire to `TokenService` via option |
| `internal/probe/otel` | Modified | New result attribute for `tokenIssuanceProbe`; implement `IssuancePolicyDenied` |
| `internal/probe/zlog` | Modified | Implement `IssuancePolicyDenied` with log message |

## Implementation Steps

### PR 1: Issuance policy abstraction with claim assertions

This PR introduces the `IssuancePolicy` interface and its first
implementation (`ClaimAssertionPolicy`), wires it into `TokenService`,
adds observability, and provides config support. The abstraction is generic
and stands on its own — no vendor-specific claim names in code.

_Follows the **abstraction-first PR pattern**: the abstraction is designed
generically, tested, observable, and documented. The specific 3scale-parity
configuration is a downstream config update (no code change)._

#### Step 1: Define IssuancePolicy interface and ClaimAssertionPolicy

**Package**: `internal/service`
**Files**: `issuance_policy.go` (new)
**Status**: Done

1. Define `IssuancePolicy` interface with `Evaluate(ctx, *trust.Result) error`.
2. Define `ErrIssuanceDenied` sentinel error.
3. Implement `ClaimAssertionPolicy` with `requiredClaims` and `rejectedClaims`.
4. Implement `NoOpIssuancePolicy` (always allows).
5. Constructor: `NewClaimAssertionPolicy(requiredClaims []string, rejectedClaims map[string]any)`.

**Key types/functions**:
- `IssuancePolicy` — interface for pre-issuance policy evaluation
- `ErrIssuanceDenied` — sentinel wrapping error for policy denials
- `ClaimAssertionPolicy` — evaluates claim presence and value assertions
- `NoOpIssuancePolicy` — allows all issuance (default)

#### Step 2: Add probe method to TokenIssuanceProbe

**Package**: `internal/service`
**Files**: `observer.go`
**Status**: Done

Add `IssuancePolicyDenied(err error)` to `TokenIssuanceProbe` and its NoOp:

**Key types/functions**:
- `TokenIssuanceProbe.IssuancePolicyDenied(err error)` — called when policy denies issuance
- `NoOpTokenIssuanceProbe.IssuancePolicyDenied(error)` — no-op

#### Step 3: Wire IssuancePolicy into TokenService

**Package**: `internal/service`
**Files**: `service.go`
**Status**: Done

1. Add `issuancePolicy IssuancePolicy` field to `TokenService`.
2. Add `TokenServiceOption` type and `WithIssuancePolicy` option function.
3. Update `NewTokenService` to accept variadic options (backward compatible:
   existing call sites pass no options).
4. In `IssueTokens`, evaluate policy before the issuance loop. On denial,
   call `p.IssuancePolicyDenied(err)` and return `ErrIssuanceDenied`-wrapped error.

**Key types/functions**:
- `TokenServiceOption` — functional option type
- `WithIssuancePolicy(IssuancePolicy)` — sets the issuance policy
- Modified `IssueTokens` — evaluates policy before issuing

#### Step 4: Implement OTel probe method

**Package**: `internal/probe/otel`
**Files**: update the service observer file (likely `service.go` or similar)
**Status**: Done

Add result attribute constant and implement the probe method on the OTel
token issuance probe:

**Key types/functions**:
- `resultIssuancePolicyDenied` — `attribute.String("result", "issuance_policy_denied")`
- OTel probe `IssuancePolicyDenied(err)` — sets error status + result

#### Step 5: Implement logging probe method

**Package**: `internal/probe/zlog`
**Files**: update the service logging observer file
**Status**: Done

Implement `IssuancePolicyDenied(err error)` on the logging probe:

**Key types/functions**:
- Logging probe `IssuancePolicyDenied(err)` — logs at Warn level with error detail

#### Step 6: Config wiring

**Package**: `internal/config`
**Files**: `config.go`, `provider.go` (or new `issuance_policy.go`)
**Status**: Done

1. Add `IssuancePolicyConfig` struct with `Type`, `RequiredClaims`, `RejectedClaims`.
2. Add `IssuancePolicy *IssuancePolicyConfig` field to root `Config`.
3. Build `ClaimAssertionPolicy` from config and pass to `TokenService` via
   `WithIssuancePolicy`.

Config YAML structure:

```yaml
issuance_policy:
  type: claim_assertions
  required_claims:
    - idp
  rejected_claims:
    impersonated: true
```

**Key types/functions**:
- `IssuancePolicyConfig` — `koanf:"issuance_policy"`
- `newIssuancePolicy(cfg)` — builds policy from config

#### Step 7: Unit tests for ClaimAssertionPolicy

**Package**: `internal/service`
**Files**: `issuance_policy_test.go` (new)
**Status**: Done

Test the policy in isolation (no TokenService needed):

1. `required_claims` tests:
   - Claim present → allowed (nil error)
   - Claim missing → denied with `ErrIssuanceDenied`
   - Multiple required, all present → allowed
   - Multiple required, one missing → denied
   - Empty required → no enforcement

2. `rejected_claims` tests:
   - Claim matches rejected value → denied
   - Claim present but different value → allowed
   - Claim absent → allowed
   - Multiple rejected → denied on first match
   - Empty rejected → no enforcement

3. Combined: both active simultaneously

#### Step 8: Integration test — TokenService with IssuancePolicy

**Package**: `internal/service`
**Files**: `service_test.go` (extend)
**Status**: Done

Test that `TokenService.IssueTokens` respects the policy:

1. Policy allows → tokens issued (existing behavior)
2. Policy denies → error returned, no tokens issued, probe called
3. No policy configured → tokens issued (backward compat)

#### Step 9: Config integration tests

**Package**: `internal/config`
**Files**: new test file
**Status**: Done

1. Test YAML loading of `issuance_policy` config.
2. Test end-to-end: config → policy → TokenService rejects/allows.
3. Test backward compatibility: config without `issuance_policy` works.

#### Step 10: Update example config

**Package**: root
**Files**: `configs/parsec.yaml`
**Status**: Done

Add commented example of the new `issuance_policy` section.

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| Interface | `IssuancePolicy` | Describes what it does: policy over issuance |
| Sentinel error | `ErrIssuanceDenied` | Follows `ErrInvalidToken` / `ErrExpiredToken` pattern |
| Implementation | `ClaimAssertionPolicy` | Describes mechanism: asserts claim presence/values |
| Config struct | `IssuancePolicyConfig` | Follows `ObservabilityConfig`, `TrustStoreConfig` pattern |
| YAML key | `issuance_policy` | Top-level config, koanf snake_case |
| YAML subkeys | `required_claims`, `rejected_claims` | Clear, generic |
| Probe method | `IssuancePolicyDenied` | Descriptive: what happened |
| OTel result | `issuance_policy_denied` | Follows existing snake_case result values |
| Option func | `WithIssuancePolicy` | Follows `With…` option convention |

## Test Plan

Per `docs/testing.md`: hermetic, no I/O, no mocks, prefer real instances and fakes.

### Unit Tests

| Test | Package | What it verifies |
|------|---------|-----------------|
| `TestClaimAssertionPolicy_requiredClaims/accepts_when_present` | `internal/service` | Claim present → nil |
| `TestClaimAssertionPolicy_requiredClaims/denies_when_missing` | `internal/service` | Claim absent → ErrIssuanceDenied |
| `TestClaimAssertionPolicy_requiredClaims/accepts_all_present` | `internal/service` | Multiple, all present |
| `TestClaimAssertionPolicy_requiredClaims/denies_any_missing` | `internal/service` | Multiple, one missing |
| `TestClaimAssertionPolicy_requiredClaims/skips_when_empty` | `internal/service` | No enforcement |
| `TestClaimAssertionPolicy_rejectedClaims/denies_matching_value` | `internal/service` | Value match → denied |
| `TestClaimAssertionPolicy_rejectedClaims/accepts_different_value` | `internal/service` | Different value → allowed |
| `TestClaimAssertionPolicy_rejectedClaims/accepts_absent_claim` | `internal/service` | Absent → allowed |
| `TestClaimAssertionPolicy_rejectedClaims/skips_when_empty` | `internal/service` | No enforcement |
| `TestClaimAssertionPolicy_combined` | `internal/service` | Both active |
| `TestTokenService_IssuancePolicy/policy_denies` | `internal/service` | IssueTokens returns error, no tokens, probe called |
| `TestTokenService_IssuancePolicy/policy_allows` | `internal/service` | IssueTokens proceeds normally |
| `TestTokenService_IssuancePolicy/no_policy` | `internal/service` | Backward compat — issuance proceeds |
| `TestLoadIssuancePolicyFromYAML` | `internal/config` | YAML → config parsing |
| `TestIssuancePolicyBackwardCompat` | `internal/config` | No policy in config → no enforcement |

### Benchmarks

No new benchmarks. The claim checks are O(n) over small config-bounded lists
with no allocations on the allow path.

## Observability

Per `docs/observer-pattern.md`.

### Observer Hierarchy

One method added to existing `TokenIssuanceProbe`:

```text
ServiceObserver                      (package aggregate — unchanged)
├── TokenServiceObserver             (unchanged)
│   └── TokenIssuanceProbe           (probe — 1 new method: IssuancePolicyDenied)
```

### New Probe Method

| Method | Metric Impact | Log Impact | Key Attributes |
|--------|--------------|------------|----------------|
| `IssuancePolicyDenied(err)` | Sets `result="issuance_policy_denied"`, `status="error"` | Warn: "issuance denied by policy" with error detail | error message (log only) |

### Injection

`TokenService` already injects its observer. No new observer types — the
policy denial is a lifecycle event within `IssueTokens`, reported via the
existing `TokenIssuanceProbe`.

## Security

- [x] Input validation: `required_claims` and `rejected_claims` are typed at
  config load time. Claim names are compared by exact string match.
- [x] Error handling: error messages include the claim name (from config, not
  token) but do not leak token contents or internal details.
- [x] Credential handling per `docs/CREDENTIAL_DESIGN.md`: no change.
- [x] TLS/mTLS considerations: N/A.

## Maintainability

- [x] Constructor pattern: `TokenService` gains functional options (`With…`)
  for optional parameters. Required params remain positional.
- [x] Forward compatibility: `NoOpTokenIssuanceProbe` gains the new method.
- [x] Config vs. domain separation: claim names are configuration; the policy
  logic is domain-generic.
- [x] Interface-driven: `IssuancePolicy` allows future implementations
  (CEL, composite, etc.) without changing `TokenService`.
- [x] Downstream app-interface impact: yes — see Configuration Impact.

## Configuration Impact

> **Fail-safe rule**: See [config-constraints.md](config-constraints.md).
> All config changes must be backward compatible.

### Backward Compatibility

| New Field | Type | Default / Zero Value | Behavior When Absent |
|-----------|------|---------------------|----------------------|
| `issuance_policy` | `*IssuancePolicyConfig` | `nil` | No policy — all issuance proceeds as before |
| `issuance_policy.required_claims` | `[]string` | `nil` (empty) | No claim presence enforcement |
| `issuance_policy.rejected_claims` | `map[string]any` | `nil` (empty) | No claim value rejection |

- [x] Every new field has a safe default that preserves prior behavior
- [x] No `panic` or `log.Fatal` on missing new config
- [ ] Test verifies behavior with new field absent matches previous version

> **Note on JIRA's "secure by default" stance**: The JIRA proposes
> `reject_impersonated` defaulting to `true`. This would be a **breaking
> change** — deploying new code before updating config would start rejecting
> tokens that were previously accepted. Per the fail-safe constraint, the
> default must preserve previous behavior (no rejection). Impersonation
> rejection activates only when explicitly configured.

### Local Config (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `internal/config/config.go` | New struct + field | `IssuancePolicyConfig` struct; `IssuancePolicy *IssuancePolicyConfig` on root `Config` |
| `internal/config/` (new or existing) | New builder | `newIssuancePolicy()` builds policy from config |
| `internal/config/provider.go` | Modified | Wire policy into `TokenService` via `WithIssuancePolicy` |
| `configs/parsec.yaml` | Updated example | Commented example of `issuance_policy` section |

### Deploy Templates (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| N/A | No changes | Deploy templates don't reference policy config fields |

### Downstream app-interface (follow-up required)

> **Action required after merge**: Update the downstream app-interface secrets
> to add the `issuance_policy` section. Until updated, the new code runs with
> previous behavior (no policy). Once config is applied, enforcement activates.
>
> Refer to `.cursor/rules/deploy-config-sync.mdc` for specific paths and
> validation checks for stage and prod environments.

| Environment | What to update |
|-------------|----------------|
| Stage | Add `issuance_policy` with `required_claims: ["idp"]` and `rejected_claims: {impersonated: true}` |
| Prod | Same as stage, after stage validation |

## Documentation

### New Documentation

| Doc | Path | Purpose |
|-----|------|---------|
| Issuance policy design | `docs/issuance-policy.md` | Explains the layer, why it exists (trust ≠ policy), how to configure, how to extend |

### Documentation Updates

| Doc | Path | What changes |
|-----|------|-------------|
| Architecture | `ARCHITECTURE.md` | Add issuance policy to the token issuance flow diagram and interface list |

### Config Examples

Example YAML showing 3scale-parity configuration:

```yaml
# Issuance policy — evaluated after credential validation, before token
# issuance. Applies to both ext_authz and exchange flows.
#
# This is policy over trusted claims, not trust establishment. Validators
# determine whether a credential is authentic; issuance policy determines
# whether the authenticated claims are acceptable for token issuance.
issuance_policy:
  type: claim_assertions

  # Reject tokens where a claim matches a specific value.
  # Covers 3scale's impersonation check: tokens with "impersonated: true"
  # are rejected before issuance.
  rejected_claims:
    impersonated: true

  # Require specific claims to be present in the token.
  # Covers 3scale's APICAST_ENFORCE_IDP_AUTH: tokens must carry an "idp"
  # claim (indicating they came through a third-party IdP flow).
  required_claims:
    - idp
```

## Completeness Checklist

- [x] **Server code vs. configuration gate passed**: no deployment-specific,
      IdP-specific, or vendor-specific logic in server Go code. Claim names
      are purely configuration.
- [x] New abstraction (`IssuancePolicy`) is a separate concern from the use
      case (deployment config). The abstraction is generic and reusable.
- [x] Every acceptance criterion maps to at least one implementation step
- [x] Every new exported type/function has a proposed name following parsec conventions
- [x] Every new interface method has a NoOp implementation planned
- [x] Every observable component has observer/probe entries
- [x] Test cases cover all new behavior (unit, integration, config)
- [x] Security implications addressed
- [x] Documentation steps included (new doc + ARCHITECTURE.md update + config examples)
- [x] Config impact assessed: local config, deploy templates, and downstream app-interface
- [x] All new config fields are fail-safe
- [x] Test exists verifying behavior with new config field absent (backward compat)
- [x] If config changes exist, explicit follow-up step for app-interface stage + prod updates
- [x] Each step is a reviewable, self-contained unit
- [x] Single PR — abstraction + first implementation + config. Use case is config-only follow-up.
- [x] Plan can be executed top-to-bottom without ambiguity

## Risks & Open Questions

| # | Item | Status | Resolution |
|---|------|--------|------------|
| 1 | v1 placed checks in validator layer. Alec: "validators establish trusted claims, not policy over issuance." | Resolved | Moved to new `IssuancePolicy` on `TokenService` — post-trust, pre-issuance. |
| 2 | Alec mentioned "issuer policy" as a discussed concept with Jozef for other use cases. Does `IssuancePolicy` align with that vision? | Open | Confirm naming and scope. Current design is intentionally minimal — `Evaluate(ctx, subject) error` — extensible to actor, request attrs, etc. later. |
| 3 | `TokenService.NewTokenService` currently has positional params. Adding options changes the signature. | Resolved | Use variadic `...TokenServiceOption` as final param — backward compatible, no call-site changes needed for existing code. |
| 4 | `AuthzCheckPolicy` overlap: ext_authz flow now has TWO policy checkpoints (AuthzCheckPolicy + IssuancePolicy). | Resolved | Different concerns: `AuthzCheckPolicy` decides *whether* to issue (or allow/deny); `IssuancePolicy` gates *what claims are acceptable* for issuance. Layered correctly. |
| 5 | Should `IssuancePolicy.Evaluate` also receive `actor` and `request`? | Open | Current design passes `subject` only — sufficient for impersonation/IdP checks. Can be extended later if needed. Keep minimal for now. |
| 6 | Future: CEL-based `IssuancePolicy` implementation. | Deferred | Natural next step — `IssuancePolicy` interface supports it. Not needed for this JIRA. |
| 7 | `rejected_claims` value comparison uses `reflect.DeepEqual`. YAML `int` vs JSON `float64` may not match. | Resolved | Acceptable: primary use case is boolean. Type-normalizing comparison can be added later. |
| 8 | Error messages differ from 3scale ("Impersonation disallowed" vs "issuance denied: claim 'impersonated' has rejected value"). | Resolved | Parsec is not 3scale. Generic, descriptive messages work for any claim/IdP. |

## Review Log

| Date | Reviewer | Feedback | Changes Made |
|------|----------|----------|--------------|
| 2026-07-08 | — | Initial draft (v1) — placed checks in jwt_validator | — |
| 2026-07-09 | Alec | Layer misplacement: validators are trust, not policy. Suggested pre-issuance policy, claims mapper, or new issuer policy layer. "Any time you see server go code referencing a specific claim for sso.redhat.com it is an immediate red flag." | Complete redesign: moved from trust/validator to new `IssuancePolicy` on `TokenService`. Added architectural analysis of layer options. Updated all sections. |
