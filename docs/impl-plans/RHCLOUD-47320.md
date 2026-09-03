# RHCLOUD-47320: Cross-account / org-admin access checks

**JIRA**: https://redhat.atlassian.net/browse/RHCLOUD-47320
**Status**: Implemented (awaiting PR)
**Author**: Adam O'Brien
**Date**: 2026-09-03

## Context

3scale lets Red Hat internal employees (TAMs, support) access a customer
account on their behalf: the employee authenticates with their own JWT,
browser cookies name the target account/org, the gateway checks RBAC, then
rewrites `x-rh-identity`. Parsec has no equivalent.

Parent epic: [RHCLOUD-43993](https://redhat.atlassian.net/browse/RHCLOUD-43993)
(CAPS | SSO integration feature parity with 3scale). Depends on Fix-3 (BOP
data source) and Fix-4 (identity branching), both already in tree.

**Throwaway on this branch:** commit `5ec349d` (`impl cross account req`) puts
RBAC and identity mutation on `CredentialContext` in Go. That does not compile,
is unwired, and fails the server-code-vs-configuration gate. Discard those
four files before implementing this plan. Do not iterate on them.

### Acceptance Criteria

- [x] AC1: Internal employee + valid cookies + approved RBAC request → identity with target account/org, `cross_access=true`, `is_org_admin=false`, employee originals preserved
- [x] AC2: Non-internal user + cross-account cookies → 403 `"Cross account access is forbidden."`
- [x] AC3: Internal user + cookies but no approved RBAC request → 403 `"Access denied from RBAC on cross-access check."`
- [x] AC4: No cross-account cookies → normal identity, no employee/cross-account fields
- [x] AC5: RBAC service unavailable → 500
- [x] AC6: Configurable bypass for `is_internal` flag (email suffix check still applies)
- [x] AC7: Configurable toggle between account-number and org-id RBAC queries
- [x] AC8: Audit logging for all cross-account attempts (success and failure)
- [x] AC9: Caching of RBAC results (keyed on employee identity + target cookies)

JWT-auth only — not cert-auth, basic-auth/registry, or service accounts.

Export compliance (RHCLOUD-49359) must keep running on the **original**
employee identity. `redhat_identity.cel` already documents that the compliance
call stays before any cross-account swap.

### External References

- Jira story only (confirmed). 3scale cookie names and error strings come from
  the ticket. Proposed RBAC HTTP shape is called out as an open question.

## Design

### Server Code vs. Configuration

> **Answer these questions FIRST before proceeding with any design.**

| Question | Answer |
|----------|--------|
| Does this modify server Go code or use configuration/policy? | **Almost entirely configuration/policy.** Lua data source + CEL mapper. Two small **generic** Go additions: (1) optional `LuaFetchProbe.Outcome(status string)` so any Lua DS can emit an audit outcome; (2) discard the vendor-specific Go stub. No `cross_access_*` names in `internal/server`. |
| If server code: is the change generic (any IdP/vendor/deployment) or specific? | Generic. Probe `Outcome` takes an opaque status string. Cookie names, email suffix, RBAC URL, query mode, and 3scale error strings stay in Lua/CEL/config. |
| Does any proposed server code hardcode claim names, issuer URLs, vendor behaviors, or deployment-specific logic? | **No.** |
| Which existing parsec policy/config layer fits? | Lua data source (validation + RBAC HTTP) + CEL claim mapper (JWT-only gate, `accessDenied` / eval error → 500, identity mutation). Static `identity-policy` DS for CEL-visible flags. |
| If none: does this need a new abstraction layer? | **No.** `LuaFetchProbe.Outcome` is an additive observer method with NoOp, not a new policy layer. Same PR as the use case is acceptable. |

_Parsec is a generic service. Server code must never contain logic specific to
a particular IdP, vendor, or deployment. Use configuration/policy layers for
deployment-specific behavior._

`CredentialContext` stays transport-only (headers, cookies, TLS). Lua already
sees `request_attributes.headers["cookie"]`. Parsed cookies on
`RequestAttributes` are a nice generic follow-up and **out of scope** for this
ticket.

### Approach

Mirror `export_compliance.lua` + `redhat_identity.cel`, with **fail-closed**
RBAC (unlike compliance, which is fail-open).

```text
User jwt-auth branch (console / rhsm / portal / unsigned-json BOP)
  1. Export compliance on ORIGINAL identity (existing)
  2. datasource("cross_account")
       nil / missing DS → emit normal identity (AC4 + fail-safe rollout)
       status=forbidden  → accessDenied("Cross account access is forbidden.")     (AC2)
       status=denied     → accessDenied("Access denied from RBAC on cross-access check.") (AC3)
       Fetch error       → CEL eval error → MappingFailure → HTTP 500            (AC5)
       status=allowed    → mutate identity (AC1)
  cert / registry / service-account branches never call the DS
```

**Lua (`cross_account.lua`) owns validation:**

1. Parse `Cookie` for `cross_access_account_number` and/or `cross_access_org_id`
   (names configurable, ticket values as defaults). No matching cookies →
   return `nil` (CEL no-op, cache skipped).
2. Require email ending with `internal_email_suffix` (default `@redhat.com`).
   Unless `bypass_is_internal`, also require internal employee using the same
   sources CEL already uses for `user.is_internal`: `claims.idp ==
   internal_idp_target`, else `claims.is_internal`, else role
   `redhat:employees` when `role_fallback_enabled`. Fail → `{status:"forbidden"}`
   and **do not** call RBAC.
3. Build a **pre-swap** `x-rh-identity` envelope (employee account/org) and
   GET RBAC. `query_by` config selects account-number vs org-id (AC7).
4. HTTP 200 with at least one approved request → `{status:"allowed",
   target_account_number, target_org_id, employee_account_number,
   employee_org_id}`. Empty/unapproved → `{status:"denied"}`. Transport error,
   timeout, 5xx, missing `rbac_api`, or undecodable body → Lua `error(...)`
   so `Fetch` returns `error` (not cached; AC5).

**CEL owns mutation and HTTP mapping** (see `docs/issuance-policy.md`):

- `accessDenied(message)` → OAuth `access_denied` → ext_authz **403**
- Lua `error` / `Fetch` error → CEL `types.WrapErr` → `Map` error → **500**
- Allowed: swap `identity.account_number` / `identity.org_id` /
  `identity.internal.org_id` to the Lua targets; set
  `identity.internal.cross_access=true`; force `user.is_org_admin=false`;
  set `identity.employee_account_number` / `identity.employee_org_id` from
  Lua (employee originals). Other user fields stay the employee's.

**Fail-safe rollout:** `datasource()` is already `null` when the name is not
registered. CEL treats null as AC4. New behavior activates only when the DS
is present in config (code can deploy before app-interface).

**Caching (AC9):** `CacheableLuaDataSource` + existing in-memory/distributed
wrappers. `fetch_cache_key` returns `nil` when there are no cross-account
cookies (skip cache on the hot path). Otherwise key = employee subject/email
+ cookie values + `query_by`. Deny and forbidden payloads **are** cached
(they are successful `Fetch` results). Lua `error` is **not** cached
(`InMemoryCachingDataSource` already skips store on `err != nil`).

**Audit (AC8):** Lua always returns a `status` (or errors). Additive
`LuaFetchProbe.Outcome(status string)` logs Info for `allowed` / `forbidden`
/ `denied` and Error for fetch failures (existing `ScriptExecutionFailed`).
CEL `accessDenied` already records `mapping.oauth_error=access_denied` with
the ticket message.

### Alternatives Considered

| Alternative | Pros | Cons | Why not |
|-------------|------|------|---------|
| Go `IdentityMutator` + `RBACService` on `CredentialContext` (current stub) | Feels like a service layer | Vendor-specific server code; identity is not transport; unwired; fails the gate | Rejected |
| Employee check in CEL, Lua only RBAC | Reuses CEL `is_internal` expression | CEL must parse cookies or always call Lua after a redundant RBAC hit for AC2 | Rejected — Lua checks employee first, skips RBAC on forbidden |
| Fail-open on RBAC down (like compliance) | Availability | Violates AC5 | Rejected |
| New `IssuancePolicy` interface | Named policy object | Duplicates mapper inputs; `docs/issuance-policy.md` already chose CEL | Rejected |
| Parsed `Cookies` on `RequestAttributes` | Cleaner Lua | Extra generic plumbing; raw `Cookie` header is enough | Defer |

### Interface Changes

Additive observer method only. Embed `NoOpLuaFetchProbe` so existing
implementations stay valid.

```go
// LuaFetchProbe tracks a single Lua fetch invocation.
type LuaFetchProbe interface {
    // Outcome records a script-defined result (e.g. "allowed", "denied").
    // Call after a successful table return, before End().
    Outcome(status string)

    ScriptLoadFailed(err error)
    ScriptExecutionFailed(err error)
    InvalidReturnType(got string)
    FetchCompleted()
    FetchCompletedNil()
    ResultConversionFailed(err error)
    End()
}
```

`lua_datasource.go`: if the JSON `data` unmarshals to an object with a string
`status` (or `outcome`) field, call `p.Outcome(...)`. Datasources that omit
the field are unchanged. Logging observer: Info with `datasource` + `status`.
OTel: optional `result` attribute on the existing Lua fetch histogram — only
when `Outcome` was called, using the same `result`/`status` correlation
pattern as `docs/observer-pattern.md`. Cardinality: a handful of known
status strings; Lua should not put user IDs in `status`.

No protobuf / gRPC API changes.

### Package Impact

| Package | Change Type | Description |
|---------|------------|-------------|
| `internal/server` | Modified | Revert stub: drop identity fields on `CredentialContext`, delete `identity_mutation.go`, `rbac_mock.go`, `cross_account_test.go` |
| `internal/datasource` | Modified | `LuaFetchProbe.Outcome`; parse optional `status` from Lua JSON |
| `internal/probe/zlog` | Modified | Info log on `Outcome` |
| `internal/probe/otel` | Modified | `result` attribute when `Outcome` was called |
| `internal/observer` | Modified | Composite probe forwards `Outcome` |
| `configs/scripts` | New / Modified | `cross_account.lua`; JWT User branches in `redhat_identity.cel` |
| `configs/` | Modified | Register DS; Lua config; example YAML |
| `deploy/` | Modified | Script mount + DS in ephem/production templates |
| `test/e2e` | New | Hermetic Check() cases for ACs |
| `docs/` | Modified | This plan; `LUA_DATASOURCE.md`; `configs/README.md` |

## Implementation Steps

Atomic enough for **one PR** (Lua unused without CEL; CEL fail-safe without
Lua). Steps below are reviewable units inside that PR. If review load is high,
split after Step 3 (Lua + tests merge independently; CEL PR is then config-only
behavior change).

### PR 1: Cross-account Lua DS + CEL mutation (RHCLOUD-47320)

#### Step 1: Discard the Go stub

**Package**: `internal/server`
**Files**: `credential_context.go`, `identity_mutation.go`, `rbac_mock.go`, `cross_account_test.go`
**Status**: Done (no-op: stub is not on `origin/main` / `rhcloud-47320-impl`)

Restore `CredentialContext` to transport-only. Delete the three new files.
Confirm `go test ./internal/server/` compiles.

**Key types/functions**: none added.

#### Step 2: Generic Lua fetch outcome probe

**Package**: `internal/datasource`, `internal/probe`, `internal/observer`
**Files**: `observer.go`, `lua_datasource.go`, zlog/otel/composite probes, existing NoOps
**Status**: Done

Add `Outcome(status string)`. Call it when returned JSON has `status`.
NoOp embedding. Tests: Lua script returning `{status:"denied"}` hits the
probe; scripts without `status` do not.

**Key types/functions**:
- `LuaFetchProbe.Outcome` — audit/result hook
- `NoOpLuaFetchProbe.Outcome` — no-op

#### Step 3: `cross_account.lua` + hermetic Lua tests

**Package**: `configs/scripts`, `internal/datasource`
**Files**: `configs/scripts/cross_account.lua`, `internal/datasource/cross_account_lua_test.go`
**Status**: Done

Follow `export_compliance.lua` / `export_compliance_lua_test.go`: real script
+ `httpfixture` HTTP, no mocks. Cover:

| Case | Expected |
|------|----------|
| No cookies | `Fetch` nil, no HTTP |
| Non-internal + cookies | `status=forbidden`, no HTTP |
| Internal + bypass off + non-redhat email | `status=forbidden` |
| Bypass on + redhat email + cookies | RBAC called |
| RBAC 200 approved | `status=allowed` + targets + employee originals |
| RBAC 200 empty | `status=denied` |
| RBAC 5xx / timeout / connect error | `Fetch` error |
| `query_by=account` vs `query_by=org_id` | URL query differs |
| `fetch_cache_key` nil without cookies | cache skipped |
| Cache hit on second allowed fetch | one HTTP call |

**Key types/functions**:
- `fetch(input)` / `fetch_cache_key(input)` — Lua
- Cookie parse helper (split `Cookie` header; do not substring-match values)

Lua config keys (all optional except `rbac_api` once the DS is registered):

| Key | Default | Role |
|-----|---------|------|
| `rbac_api` | (empty → `error`, AC5 once DS exists) | Base URL |
| `requests_path` | `/api/rbac/v1/cross-account-requests/` | Path |
| `query_by` | `account` | AC7: `account` or `org_id` |
| `cookie_account` | `cross_access_account_number` | Cookie name |
| `cookie_org` | `cross_access_org_id` | Cookie name |
| `internal_email_suffix` | `@redhat.com` | AC6 email check |
| `bypass_is_internal` | `false` | AC6 |
| `internal_idp_target` | `""` | Align with identity-policy |
| `role_fallback_enabled` | `false` | Align with identity-policy |

Proposed RBAC request (confirm before merge — Open Question 1):

```http
GET {rbac_api}{requests_path}?query_by=user_id&account={cookie_account}&approved_only=true
Accept: application/json
x-rh-identity: {base64(employee envelope)}
```

When `query_by=org_id`, filter with the org cookie (parameter name TBD with
RBAC — likely `org_id` or `query_by=target_org`). Send the **employee**
identity in `x-rh-identity`, never the target. Reuse `base64` + `json` +
`url.encode` services already registered for Lua DS.

Treat HTTP 200 with a non-empty approved list as allowed; 200 empty / 404 as
denied; 5xx and transport errors as `error()`.

#### Step 4: Register the data source (fail-safe)

**Package**: `configs`, `deploy`
**Files**: `configs/parsec.yaml`, `configs/examples/parsec-production.yaml`, `deploy/parsec.yaml`, `deploy/parsec-ephem.yaml`
**Status**: Done — `deploy/parsec.yaml` mounts the script (coordinate with app-interface secret key). Ephem does **not** register the DS or mount the script: the ConfigMap has no `cross_account.lua` key (same as export compliance), and ephemeral has no RBAC.

Add `cross_account` Lua DS with `http` timeout ~5s, in-memory cache in the
dev example, distributed in production example. Mount `cross_account.lua`
next to `bop_user.lua` / `export_compliance.lua`. Named HTTP client only if
RBAC needs extra static headers; prefer Lua-set `x-rh-identity` like
compliance.

Do **not** require a context_extensions kill switch. Absent DS = old
behavior. Once registered, cookies activate the flow.

#### Step 5: CEL identity mutation

**Package**: `configs/scripts`
**Files**: `redhat_identity.cel`, `redhat_identity_test.go`
**Status**: Done

On **User jwt-auth** branches only (unsigned-json BOP, console, rhsm,
customer-portal). After the existing export-compliance guard:

```cel
datasource("cross_account") != null && datasource("cross_account").status == "forbidden"
  ? accessDenied("Cross account access is forbidden.")
: datasource("cross_account") != null && datasource("cross_account").status == "denied"
  ? accessDenied("Access denied from RBAC on cross-access check.")
: datasource("cross_account") != null && datasource("cross_account").status == "allowed"
  ? { /* identity with swapped account/org, cross_access, employee_* */ }
: { /* existing identity; cross_access: false; no employee_* keys */ }
```

`datasource()` is cached per evaluation — multiple reads are one Lua fetch.
Missing DS or no cookies → null → existing map (AC4). Unexpected `status` →
`fail("cross-account check failed")` (fail-closed). Cert / registry / SA
branches unchanged (`cross_access: false`).

Keep error strings **exactly** as in the ACs.

#### Step 6: E2E hermetic authz tests

**Package**: `test/e2e`
**Files**: `hermetic_authz_cross_account_test.go`
**Status**: Done

Per `test/e2e/README.md`: exercise `Check()` only. HTTP fixtures for RBAC.
Cookie header on the Envoy CheckRequest. Assert DeniedHttpResponse 403
messages, 500 on RBAC down, and issued `x-rh-identity` JSON on success
(unsigned issuer). Cover AC1–AC5 plus JWT-only (cert path does not call
RBAC). Pattern: `hermetic_authz_compliance_test.go`.

#### Step 7: Docs + loader test

**Package**: `configs`, `internal/datasource`, `internal/lua`, `internal/config`
**Files**: `configs/README.md`, `internal/datasource/LUA_DATASOURCE.md`, `internal/lua/README.md`, `internal/config/loader_test.go`
**Status**: Done — loader_test YAML is a custom fixture (not `configs/parsec.yaml`); no change needed.

Document DS, cache key, fail-safe, and that compliance stays first.
Extend `loader_test.go` if the embedded example YAML gains the new entry.

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| Data source | `cross_account` | Matches `cross_access` identity field and cookie prefix |
| Script | `cross_account.lua` | Same |
| Lua statuses | `allowed`, `forbidden`, `denied` | Map 1:1 to AC1 / AC2 / AC3 |
| Probe method | `Outcome` | Generic; not `CrossAccount…` |
| Cache group | `cross-account-cache` | Distinct from compliance/BOP |
| Identity fields | `employee_account_number`, `employee_org_id` | Ticket names; siblings of `account_number` on `identity` |

## Test Plan

Per `docs/testing.md`: hermetic, no I/O, no mocks, prefer real instances and fakes.

### Unit Tests

| Test | Package | What it verifies |
|------|---------|-----------------|
| `TestCrossAccountLua_NoCookies_ReturnsNil` | `internal/datasource` | AC4; no HTTP |
| `TestCrossAccountLua_NonInternal_Forbidden` | `internal/datasource` | AC2; no RBAC call |
| `TestCrossAccountLua_BypassIsInternal_StillRequiresEmail` | `internal/datasource` | AC6 |
| `TestCrossAccountLua_Approved_ReturnsTargets` | `internal/datasource` | AC1 payload |
| `TestCrossAccountLua_EmptyRBAC_Denied` | `internal/datasource` | AC3 |
| `TestCrossAccountLua_RBACUnavailable_FetchError` | `internal/datasource` | AC5 |
| `TestCrossAccountLua_QueryByOrgID` | `internal/datasource` | AC7 |
| `TestCrossAccountLua_CacheKey_EmployeeAndCookies` | `internal/datasource` | AC9 |
| `TestLuaFetchProbe_OutcomeFromStatus` | `internal/datasource` | AC8 generic hook |
| `TestRedHatIdentityCEL_CrossAccountAllowed` | `configs/scripts` | AC1 mutation |
| `TestRedHatIdentityCEL_CrossAccountForbidden` | `configs/scripts` | AC2 `accessDenied` |
| `TestRedHatIdentityCEL_CrossAccountDenied` | `configs/scripts` | AC3 `accessDenied` |
| `TestRedHatIdentityCEL_NoCookiesUnchanged` | `configs/scripts` | AC4; no `employee_*` |
| `TestRedHatIdentityCEL_RBACErrorIsInternal` | `configs/scripts` | AC5 `Map` error |
| `TestRedHatIdentityCEL_CertAuthDoesNotCallDS` | `configs/scripts` | JWT-only (static DS that fatals on Fetch) |
| `TestRedHatIdentityCEL_MissingDS_Skip` | `configs/scripts` | Fail-safe |
| `TestCredentialContext_NoIdentityFields` | `internal/server` | Stub gone; existing cookie parse tests still pass |

### Contract Tests

None. No new domain interface beyond an additive probe method (NoOp is the
contract; existing observer tests extended).

### Benchmarks

Not required. Lua fetch path is existing; no new hot-path Go.

### Integration / E2E

| Test | What it verifies |
|------|------------------|
| Happy path cookies + RBAC 200 + internal JWT | AC1 identity on Check() |
| External user + cookies | AC2 403 body |
| Internal + RBAC empty | AC3 403 body |
| No cookies | AC4 normal identity |
| RBAC fixture timeout/5xx | AC5 500 |
| `export_compliance=false` still swaps | Compliance ordering: swap happens after skip |
| Blocked compliance + cookies | Compliance 403; RBAC not required to succeed |

## Observability

Per `docs/observer-pattern.md`.

### Observer Hierarchy

```text
DataSourceObserver                 (package aggregate)
├── CacheObserver
│   └── CacheFetchProbe            (existing; miss/hit around RBAC cache)
└── LuaObserver
    └── LuaFetchProbe              (leaf; + Outcome)
```

No new package aggregate. Constructors still take the leaf they need;
config still passes `DataSourceObserver`.

### New Probes

| Probe | Metrics | Logs | Key Attributes |
|-------|---------|------|----------------|
| `LuaFetchProbe.Outcome` | existing Lua fetch histogram + `result` when set | Info: `lua fetch outcome` | `datasource`, `status` (`allowed`/`forbidden`/`denied`) |
| Lua `error` (existing) | `status=error` | Error: `lua script execution failed` | AC5 |
| CEL `accessDenied` (existing) | mapping oauth_error | mapper deny log | AC2/AC3 message |

### Injection

Unchanged: `NewLuaDataSource` already takes `LuaObserver`. Config layer
passes the datasource aggregate.

## Security

- [x] Input validation: cookie values treated as opaque IDs; `url.encode` into query; reject empty target when cookies present but values blank → `denied` or `forbidden`, never interpolate raw cookies into paths unsanitized
- [x] Error handling: ticket messages only on 403; Lua/RBAC internals stay in logs, not `error_description`
- [x] Credential handling per `docs/CREDENTIAL_DESIGN.md`: cookies are request attributes, not credentials; JWT still extracted via existing sources
- [x] TLS/mTLS: RBAC calls use the DS HTTP client (timeout, optional `ca_cert`); no new credential type
- [x] JWT-only: CEL branches; cert/SA cannot trigger swap even if cookies are sent
- [x] `is_org_admin` forced false on success so a TAM does not inherit customer org-admin
- [x] RBAC sees **employee** identity, not the target (confused-deputy)
- [x] Do not cache 5xx/errors (already true)

## Maintainability

- [x] Constructor pattern: no new required Go constructors; probe method is additive
- [x] Forward compatibility: `NoOpLuaFetchProbe.Outcome`
- [x] Config vs. domain: 3scale strings/URLs/cookie names in Lua/CEL/YAML
- [x] Downstream app-interface impact: yes — see Configuration Impact

## Configuration Impact

> **Fail-safe rule**: See [config-constraints.md](config-constraints.md). Code
> deploys before config. Absent fields preserve previous behavior.

### Backward Compatibility

| New Field | Type | Default / Zero Value | Behavior When Absent |
|-----------|------|---------------------|----------------------|
| `data_sources[]` entry `cross_account` | YAML list item | omitted | `datasource()` → null → CEL skips (previous identity) |
| `rbac_api` | string | `""` | DS registered but empty URL → Lua `error` → 500 **only if CEL calls it**. Until CEL ships with the DS, no call. After CEL ships, operators must set the URL when they add the DS. |
| `query_by` | string | `"account"` | Account-number RBAC query (AC7) |
| `bypass_is_internal` | bool | `false` | Flag check enforced |
| `internal_email_suffix` | string | `"@redhat.com"` | Ticket default |
| `LuaFetchProbe.Outcome` | method | NoOp | Existing probes compile via embed |

- [x] Every new field has a safe default that preserves prior behavior
- [x] No `panic` or `log.Fatal` on missing new config
- [x] Test verifies missing DS matches previous identity (AC4 / fail-safe)

### Local Config (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `configs/parsec.yaml` | Add `cross_account` DS | `ttl` ~5m in-memory; example `rbac_api` |
| `configs/examples/parsec-production.yaml` | Add DS | distributed cache; `rbac_api` via env |
| `configs/scripts/cross_account.lua` | New | Validation + RBAC |
| `configs/scripts/redhat_identity.cel` | JWT User wrap | After compliance |
| `internal/config/loader_test.go` | Update fixture | If example YAML is asserted |

Suggested env override (index depends on list order — same caveat as
compliance):

```bash
PARSEC_DATA_SOURCES__N__CONFIG__RBAC_API=https://rbac.example.internal
```

### Deploy Templates (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `deploy/parsec.yaml` | volumeMount `cross_account.lua` | Secret key must match; coordinate with app-interface |
| `deploy/parsec-ephem.yaml` | none | Ephem ConfigMap has no lua key and no RBAC; fail-safe skip |

### Downstream app-interface (follow-up required)

> **Action required after merge**: Update the downstream app-interface secrets
> to reflect config changes. Until updated, the new code runs with previous
> behavior (fail-safe). Once config is applied, new behavior activates.
>
> Refer to `.cursor/rules/deploy-config-sync.mdc` for specific paths and
> validation checks for stage and prod environments.

These config changes also need to be applied to the downstream app-interface
secret(s).

| Environment | What to update |
|-------------|----------------|
| Stage | Add `cross_account.lua` to secret `stringData`; register DS with real `rbac_api`; mount script; ship updated `redhat_identity.cel` |
| Prod | Same |

Keep `internal_idp_target` / `role_fallback_enabled` in Lua config aligned
with the `identity-policy` static DS (duplicated YAML values). Document in
`configs/README.md`.

## Documentation

### New Documentation

| Doc | Path | Purpose |
|-----|------|---------|
| This plan | `docs/impl-plans/RHCLOUD-47320.md` | Implementation record |

No new architecture doc — this reuses Lua DS + CEL issuance policy.

### Documentation Updates

| Doc | Path | What changes |
|-----|------|-------------|
| Lua DS guide | `internal/datasource/LUA_DATASOURCE.md` | `cross_account` example; `status`/`Outcome` convention; fail-closed vs compliance fail-open |
| Lua services | `internal/lua/README.md` | Pointer to the script |
| Config | `configs/README.md` | DS YAML, cache key, fail-safe, app-interface reminder |
| CEL script header | `configs/scripts/redhat_identity.cel` | Cross-account after compliance |
| `AGENTS.md` | `AGENTS.md` | No change (no new convention) |

### Config Examples

```yaml
data_sources:
  - name: cross_account
    type: lua
    script_file: ./configs/scripts/cross_account.lua
    config:
      rbac_api: "https://rbac.example.internal"
      requests_path: "/api/rbac/v1/cross-account-requests/"
      query_by: "account"          # or "org_id"
      bypass_is_internal: false
      internal_email_suffix: "@redhat.com"
      internal_idp_target: "https://sso.redhat.com/auth/realms/internal"
      role_fallback_enabled: true
    http:
      timeout: 5s
    caching:
      type: in_memory
      ttl: 5m
      group_name: cross-account-cache
```

## Completeness Checklist

- [x] **Server code vs. configuration gate passed**: 3scale names stay in Lua/CEL/config; Go is generic `Outcome` + stub removal
- [x] No new policy layer; `Outcome` is not a separate abstraction PR
- [x] Every AC maps to at least one step (AC1–9 → Steps 3, 5, 6; AC8 → Step 2)
- [x] New exported names follow parsec conventions
- [x] New probe method has NoOp
- [x] Observability entries for Lua outcome + existing mapper denies
- [x] Tests cover new behavior (Lua, CEL, e2e)
- [x] Security implications addressed
- [x] Documentation steps included
- [x] Config impact: local, deploy, app-interface
- [x] New config fail-safe (absent DS)
- [x] Test for absent DS = previous behavior
- [x] App-interface follow-up called out
- [x] Steps are reviewable units
- [x] Single PR (optional split after Step 3 noted)
- [x] PR compiles independently via fail-safe if split
- [x] Plan can be executed top-to-bottom

## Risks & Open Questions

| # | Item | Status | Resolution |
|---|------|--------|------------|
| 1 | Exact RBAC URL, query params, and what JSON means “approved” | Open | Proposed `GET /api/rbac/v1/cross-account-requests/?query_by=user_id&account=…&approved_only=true` from the public RBAC client. Confirm against 3scale / RBAC before merge. |
| 2 | Where `employee_*` fields live on `x-rh-identity` | Open | Plan puts them on `identity` next to `account_number`. If 3scale nests them under `internal`, move in CEL only. |
| 3 | Extra RBAC auth (PSK / service headers) beyond `x-rh-identity` | Open | Start with employee identity header only (same as compliance). Add named `http_client` headers if stage RBAC requires PSK. |
| 4 | Unsigned-json BOP path | Resolved | Treat as User jwt-auth: if cookies are present, run the same Lua+CEL wrap. No cookies → nil. |
| 5 | Lua vs identity-policy duplication for `is_internal` | Open | Duplicate `internal_idp_target` / `role_fallback_enabled` in Lua config and document sync. Do not teach Lua to call other datasources. |
| 6 | Cookie header parsing edge cases (quoted values, duplicates) | Resolved | Use `;` split and first matching name; tests with quoted values. Optional later: generic parsed cookies on `RequestAttributes`. |
| 7 | Mid-rebase stub `5ec349d` | Open | Discard in Step 1; do not `rebase --continue` that commit as-is. |
| 8 | CEL size: four User branches each grow | Resolved | Accept duplication (same as compliance). No CEL macros. |

## Review Log

| Date | Reviewer | Feedback | Changes Made |
|------|----------|----------|--------------|
| 2026-09-03 | — | Draft from Jira ACs + codebase | Initial plan |
| 2026-09-03 | implementation | Ephem mount without ConfigMap key would crash pods | Left ephem without DS/mount (same as export compliance) |
