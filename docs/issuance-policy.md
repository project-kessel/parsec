# Issuance Policy via CEL Claim Mappers

Parsec enforces issuance policy in **CEL claim mappers**, not in a separate
policy interface. The same script that builds claims can deny issuance with
typed OAuth / token-exchange outcomes.

## Why mappers?

Issuance policy and claim mapping share the same inputs: validated subject,
optional actor, and request attributes (`MapperInput`). A separate
`IssuancePolicy` abstraction duplicated that surface without carrying enough
weight. Policy guards are CEL expressions evaluated before (or instead of)
producing claims.

## Structured result (not error) for OAuth denials

`ClaimMapper.Map` returns a `MappingResult` — claims plus a `MappingDecision`
— shaped like `AuthzCheckDecision`:

| Outcome | How it is expressed |
|---------|---------------------|
| Allow + claims | `Decision.Action == allow`, `error == nil` |
| OAuth denial (Layer A/B) | `Decision.Action == deny` + OAuth fields, `error == nil` |
| Unexpected failure (`fail()`, eval bugs, …) | `error != nil` |

Expected RFC outcomes are **not** stuffed into `error`. Use `error` only when
something is unexpectedly wrong.

Issuers may list multiple ordered mappers. Results are composed with
`MappingResult.Merge`: claims merge on Allow, and the **first non-Allow
decision wins** (further mappers are not called). Deny merges also **clear
prior Allow claims** — no partial claims linger on a deny. Merge logic lives
on the result type, not buried only in `IssueContext.ToClaims`.

### ExchangeResult contract

`Issuer.Issue` returns `(ExchangeResult, error)` — three explicit outcomes:

| Outcome | Return |
|---------|--------|
| Token issued | `ExchangeResult{Token: &Token{…}}`, `error == nil` |
| OAuth denial | `ExchangeResult{Error: &ExchangeError{…}}`, `error == nil` |
| Unexpected failure | zero `ExchangeResult`, `error != nil` |

`IssueTokens` returns per-type results (`map[TokenType]ExchangeResult`).
ext_authz treats **any** per-type `ExchangeError` as a full request denial.

## Deny constructors

Mappers (CEL or future implementations) produce denials via shared
constructors in `service`:

- `DenyOAuth(code OAuthErrorCode, message string)` — Layer A, direct OAuth code
- `DenyReason(reason AbortReason, message string)` — Layer B, reason → OAuth code
  via `OAuthCodeForReason` mapping table

The reason→code mapping table lives once in `service`, so non-CEL mappers
get the same mapping without repeating it.

## Two-layer OAuth abort API

Primary vocabulary is the **token exchange / OAuth** error response
([RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2),
[RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)) —
not HTTP status names.

### Layer A — direct OAuth error codes

| CEL function | Wire `error` | HTTP (ext_authz) |
|--------------|--------------|------------------|
| `invalidRequest(message)` | `invalid_request` | **400** |
| `invalidTarget(message)` | `invalid_target` | **400** |
| `invalidGrant(message)` | `invalid_grant` | **400** |
| `unauthorizedClient(message)` | `unauthorized_client` | **401** |
| `invalidClient(message)` | `invalid_client` | **401** |
| `unsupportedGrantType(message)` | `unsupported_grant_type` | **400** |
| `invalidScope(message)` | `invalid_scope` | **400** |
| `accessDenied(message)` | `access_denied` | **403** |

`accessDenied` is RFC 6749 §4.1.2.1 — "the resource owner or authorization
server denied the request." Use it for policy-level denials (e.g. export
compliance) where the credentials are valid but access is disallowed.
It is the only Layer A function that produces HTTP 403 (all others → 400 or 401).

### Layer B — reason helpers (preferred for guards)

Easier to author correctly; sets a machine `Reason` for observability while
still terminating in a Layer A code:

| CEL function | Wire `error` | Reason |
|--------------|--------------|--------|
| `invalidSubject(message)` | `invalid_request` | `invalid_subject` |
| `invalidActor(message)` | `invalid_request` | `invalid_actor` |
| `invalidAudience(message)` | `invalid_target` | `invalid_audience` |
| `unsupportedTokenType(message)` | `invalid_request` | `unsupported_token_type` |

### `fail(message)`

Reserved for **mapping / system failures**. Returns `*MappingFailure` from
`Map` as `error` (not a Deny decision) → transports treat it as **Internal**
(not an OAuth client error body).

## Decision flow

```
CEL Layer A/B abort helper
  → service.DenyOAuth / DenyReason → MappingDecision
  → abortError{MappingDecision} (distinct from MappingFailure)
  → celhelpers.AbortDecision(err) extracts decision
  → MappingResult{Decision: Deny{OAuthError, Reason, Message}}
  → MappingResult.Merge (first non-Allow wins; clears claims on deny)
  → ToClaims returns (nil, *ExchangeError, nil)
  → Issuer.Issue returns ExchangeResult{Error: &ExchangeError{…}}
  → Exchange: HTTP 400 + { "error", "error_description" } (via gRPC ErrorInfo;
    `invalid_client` / `unauthorized_client` → 401)
  → ext_authz: any type's ExchangeError → full request denial with explicit
    DeniedHttpResponse status (see transport mapping below)
  → logs/metrics: mapping.oauth_error, mapping.abort_reason

CEL fail() / unexpected failure
  → *MappingFailure (not an abortError) → Internal / 500
```

## Transport mapping (exchange + ext_authz)

| Scenario | gRPC code | HTTP (exchange / Envoy DeniedHttpResponse) |
|----------|-----------|--------------------------------------------|
| OAuth `invalid_request` / `invalid_target` / `invalid_grant` / `invalid_scope` / `unsupported_grant_type` | `InvalidArgument` | **400** |
| OAuth `invalid_client` / `unauthorized_client` | `Unauthenticated` | **401** |
| OAuth `access_denied` (`accessDenied()`) | `PermissionDenied` | **403** |
| Credential / subject validation failed | `Unauthenticated` | **401** |
| `AuthzCheckDeny` / trust-store filter failure | `PermissionDenied` | **403** |
| Unexpected `error` / `fail()` / nil token | `Internal` | **500** |

**Envoy pitfall**: if `DeniedHttpResponse.Status` is unset, Envoy defaults the
downstream client status to **403** even when the gRPC code is
`Unauthenticated` or `Internal`. Parsec always sets an explicit HTTP status on
denials so gateway policies see the intended code.

OAuth mapper denials use **400** (not 403): they are protocol / request-validity
outcomes, same class as the exchange path. Authorization policy denies
(`AuthzCheckDeny`) correctly stay **403**.

## Example: 3scale-parity guards

```cel
// Layer B preferred for policy guards.
// Always guard with has(subject.claims) — empty claim maps omit the claims key.
has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !(has(subject.claims) && has(subject.claims.idp))
  ? invalidSubject("claim 'idp' is required")
: {
    "identity": { /* ... */ },
    "entitlements": {}
  }
```

See `configs/scripts/redhat_identity.cel` for a full multi-token-type script
(impersonation globally; IdP required on the console API path).

## Configuration

No new Go config fields. Policy activates only when the CEL script contains
guard expressions. Scripts without guards behave as before.

Downstream (app-interface) CEL scripts must be updated separately to include
guards — until then, stage/prod keep previous behavior.

## Out of scope

Broader claim-policy helpers (`requireClaim`, …), Lua mappers, and a named
global policy registry are intentionally deferred.
