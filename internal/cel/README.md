# CEL Package

This package provides CEL (Common Expression Language) support for the Parsec token exchange service.

## Overview

CEL is a non-Turing complete expression language designed to be fast, portable, and safe to execute. It's ideal for performance-critical applications where user-provided expressions need to be evaluated safely.

## Custom Functions and Variables

This package provides CEL extensions specifically for claim mapping in Parsec:

### Variables

- **`subject`** - Subject identity information (map)
  - `subject.subject` - Subject identifier
  - `subject.issuer` - Issuer URL
  - `subject.trust_domain` - Trust domain
  - `subject.claims` - Additional claims from the credential
  - `subject.audience` - Intended audience
  - `subject.scope` - OAuth2 scope

- **`actor`** - Actor identity information (map, same structure as subject)

- **`request`** - Request attributes (map)
  - `request.method` - HTTP method
  - `request.path` - Request path
  - `request.ip_address` - Client IP address
  - `request.user_agent` - User agent string
  - `request.headers` - HTTP headers
  - `request.additional` - Additional context

### Functions

- **`datasource(name)`** - Fetches data from a named data source
  - Takes a string argument (datasource name)
  - Returns the fetched data (typically a map or list)
  - Returns null if the datasource doesn't exist
  - Results are automatically cached within a single evaluation

- **`fail(message)`** - Unexpected mapping / system failure
  - `ClaimMapper.Map` returns `error` (not a Deny decision)
  - Transports map this to Internal (not an OAuth client error)
  - Prefer Layer A/B helpers for policy denials

#### Layer A — OAuth / token-exchange error codes

Direct helpers for [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) /
[RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2)
wire `error` values. These become a **Deny** `MappingDecision` on
`MappingResult` (`error == nil` from `Map`):

| CEL | Wire `error` |
|-----|--------------|
| `invalidRequest(message)` | `invalid_request` |
| `invalidTarget(message)` | `invalid_target` |
| `invalidGrant(message)` | `invalid_grant` |
| `unauthorizedClient(message)` | `unauthorized_client` |
| `invalidClient(message)` | `invalid_client` |
| `unsupportedGrantType(message)` | `unsupported_grant_type` |
| `invalidScope(message)` | `invalid_scope` |

#### Layer B — reason helpers (preferred for policy guards)

Also Deny decisions (`error == nil` from `Map`):

| CEL | Wire `error` | Reason |
|-----|--------------|--------|
| `invalidSubject(message)` | `invalid_request` | `invalid_subject` |
| `invalidActor(message)` | `invalid_request` | `invalid_actor` |
| `invalidAudience(message)` | `invalid_target` | `invalid_audience` |
| `unsupportedTokenType(message)` | `invalid_request` | `unsupported_token_type` |

### MappingResult vs error

`accessDenied(message, classification)` optionally attaches a policy label for
issuance observers. A core audit reason code (for example `policy_denied`)
becomes the request's `reason_code`; any other label is recorded as the
decision's `classification`. `accessDenied(message, classification, event)`
additionally asks the audit observer to emit the decision as its own event
under that name, after the configured event prefix. Each label must contain
1–128 ASCII letters, digits, dots, underscores, or hyphens. For example,
`accessDenied("tenant is suspended", "tenant_suspended", "tenant_policy_denial")`
preserves the denial response, classifies the decision, and emits
`parsec_tenant_policy_denial`. The labels are internal metadata: they do not
change OAuth fields, gRPC details, or HTTP status. Unlike recording inside a datasource fetch, this decision is
observed even when the datasource result was cached.

| Outcome | `Map` return |
|---------|----------------|
| Claims produced | `Allow` + claims, `err == nil` |
| Layer A/B abort | `Deny` + OAuth fields, `err == nil` |
| `fail()` / unexpected | `err != nil` |

CEL abort helpers call `service.DenyOAuth` / `service.DenyReason` and wrap the
resulting `MappingDecision` in a distinct `abortError`. The CEL mapper extracts
it via `AbortDecision(err)` — no need to check `OAuthError != ""`.
`fail()` returns `*service.MappingFailure` (unexpected; Internal).

Multiple mappers on an issuer are merged with `MappingResult.Merge` (first
non-Allow wins; early termination; deny merges clear claims from prior
allows). See [docs/issuance-policy.md](../../docs/issuance-policy.md).

### Deny constructors

CEL Layer A functions call `service.DenyOAuth(code, message)`.
CEL Layer B functions call `service.DenyReason(reason, message)`, which maps
the reason to the correct OAuth code via a shared table in `service`
(`invalid_audience` → `invalid_target`, etc.).

### ExchangeResult

`Issuer.Issue` returns `(ExchangeResult, error)`. `ExchangeResult` contains
either a `Token` (success) or an `*ExchangeError` (known denial). Unexpected
errors use the top-level `error` return. `IssueTokens` returns per-type
results; ext_authz treats any type's `ExchangeError` as a full request denial.

### Transport mapping

| Decision / error | Exchange (HTTP) | ext_authz (gRPC) |
|------------------|-----------------|------------------|
| `ExchangeError` (`invalid_request` / `invalid_target` / …) | 400 + `{error, error_description}` | `InvalidArgument` (any-type denial = full deny) |
| `MappingFailure` (`fail`) / unexpected `error` | 500 (default gRPC error JSON) | `Internal` |

## Example CEL Expressions

### Simple Claims from Subject

```cel
{
  "user": subject.subject,
  "domain": subject.trust_domain
}
```

### Conditional Logic

```cel
subject.trust_domain == "prod" 
  ? {"env": "production", "level": "high"} 
  : {"env": "dev", "level": "low"}
```

### Policy Guards (Layer B)

```cel
has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !(has(subject.claims) && has(subject.claims.idp))
  ? invalidSubject("claim 'idp' is required")
: { "identity": { /* ... */ }, "entitlements": {} }
```

### Rejecting Unsupported Input

```cel
isSupportedToken(subject.claims)
  ? { "identity": { /* ... */ }, "entitlements": {} }
  : unsupportedTokenType("unsupported_token_type")
```

### Fetching from Data Sources

```cel
{
  "user": subject.subject,
  "roles": datasource("user_roles").roles,
  "region": datasource("geo_lookup").region
}
```

### Deployment Policy via Static Data Sources

Deployment-specific policy (for example Red Hat identity mapping thresholds) belongs in a `static` data source, not top-level parsec config:

```yaml
data_sources:
  - name: identity-policy
    type: static
    data:
      internal_idp_target: "https://sso.redhat.com/auth/realms/internal"
      role_fallback_enabled: true
```

CEL mappers read it like any other datasource:

```cel
subject.claims.idp == datasource("identity-policy").internal_idp_target
```

### Complex Expressions

```cel
{
  "identity": subject.subject + "@" + subject.trust_domain,
  "source_ip": request.ip_address,
  "permissions": datasource("permissions").for_user(subject.subject),
  "is_admin": "admin" in datasource("user_roles").roles
}
```

## Performance Considerations

The CEL mapper compiles and evaluates expressions for each token issuance. While CEL evaluation is very fast (nanoseconds to microseconds), for high-throughput scenarios, consider:

1. Keeping expressions simple and focused
2. Minimizing datasource calls
3. Using caching datasources when appropriate

Datasource results are automatically cached within a single evaluation, so calling the same datasource multiple times in one expression only fetches once.

## References

- [CEL Language Specification](https://github.com/google/cel-spec)
- [CEL-Go Documentation](https://pkg.go.dev/github.com/google/cel-go/cel)
- [CEL-Go Codelab](https://codelabs.developers.google.com/codelabs/cel-go)
- [RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2) — token exchange errors
- [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) — OAuth error response
- [Issuance policy via CEL](../../docs/issuance-policy.md)
