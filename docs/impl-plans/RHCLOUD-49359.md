# RHCLOUD-49359: Export Compliance Check

**JIRA**: https://redhat.atlassian.net/browse/RHCLOUD-49359
**Status**: In Progress
**Author**: Adam O'Brien / AI Assistant
**Date**: 2026-08-19

## Context

Legacy `insights-3scale` rejects users subject to U.S. export restrictions
before granting platform access. Parsec currently has no compliance check. This
feature adds one using the established Lua DS + CEL pattern.

Parent epic: [RHCLOUD-43993](https://redhat.atlassian.net/browse/RHCLOUD-43993)
(SSO feature parity). Related:
[RHCLOUD-49315](https://redhat.atlassian.net/browse/RHCLOUD-49315)
(entitlements, same Lua+header pattern),
[RHCLOUD-47320](https://redhat.atlassian.net/browse/RHCLOUD-47320)
(cross-account, compliance must check original user identity first — AC9).

> **Note**: The JIRA mentions an `IssuancePolicy` interface from RHCLOUD-47315 —
> that interface was replaced before this ticket was written. Policy lives in CEL
> claim mappers per [`docs/issuance-policy.md`](../issuance-policy.md).

## Acceptance Criteria

- [x] AC1: Compliance runs for SSO bearer (`jwt-auth` + `User`) only; all other auth types skip it
- [x] AC2: HTTP GET to compliance service with `x-rh-identity` (base64-encoded identity JSON) + `Accept: application/json;charset=UTF-8`
- [x] AC3: Fail-open — any error, non-200, malformed JSON, or missing username → allow through
- [x] AC4: Reject with **403** only when result code matches a configured error code
- [x] AC5: Gated on `context_extensions.enable_compliance == "true"` (per-gateway enablement)
- [x] AC6: Cache by username; default TTL **24 hours**
- [x] AC7: Fail-open synthetic results are **never** cached under the username key; only real compliance responses are cached
- [x] AC8: Cache bypass via `x-rh-insights-gateway-use-compliance-cache: 0` request header — disables both reads and writes (bypass key includes the bypass header, so bypass and normal responses never share a cache slot)
- [x] AC9: For JWT auth, check the **original** user identity (before any cross-account swap in CEL) — compliance guard placed before cross-account logic
- [x] AC10: Configurable error codes (default: `ERROR_T5`, `ERROR_EXPORT_CONTROL`, `ERROR_OFAC`) — inline list in `redhat_identity.cel`

## Design

### Server Code vs. Configuration Gate

| Question | Answer |
|----------|--------|
| Modifies server Go code or uses configuration/policy? | **Both** — compliance logic is Lua DS + CEL. One generic Go addition: `OAuthAccessDenied = "access_denied"` + 403 mapping. |
| If server code: generic or specific? | **Generic** — `access_denied` is RFC 6749 §4.1.2.1; valid for any denying mapper. |
| Hardcoded claim names / issuer URLs in Go? | **No** — claim paths and compliance URL stay in Lua/CEL/config only. |
| New abstraction needed? | **No** — extends one table (`oauthDenialStatuses`) and adds one CEL function. |

### Key Design Decisions

1. **403 via `access_denied`**: `accessDenied(message)` → `OAuthAccessDenied`
   → `oauthDenialStatuses` case → `codes.PermissionDenied` + HTTP 403.
   RFC 6749 §4.1.2.1 defines `access_denied` as "The resource owner or
   authorization server denied the request" — correct for policy-level denial.

2. **Fail-open via nil cache key**: `fetch_cache_key` returns `nil` when
   `synthetic = true`. Go `CacheKey()` falls back to the full `DataSourceInput`
   — preventing synthetic results from sharing the username cache slot.

3. **Cache bypass**: `fetch_cache_key` returns `nil` when the bypass header
   `x-rh-insights-gateway-use-compliance-cache: 0` is present. Go falls back to
   the full input (which includes the bypass header), ensuring bypass and normal
   responses never share a cache slot.

4. **Username-based cache key**: Compliance is per-user. Cache key is the
   resolved username from subject claims, stored under `preferred_username`.

5. **Claim-shape duplication (Risk #1, recurs from RHCLOUD-49315 Risk #7)**:
   Lua must branch on console/rhsm/portal token shapes to build `x-rh-identity`.
   This is the second occurrence confirming the pattern warrants a follow-up JIRA
   for `datasource(name, params)`.

6. **CEL key-guard fix**: Context extensions map access (`map.key`) fails at
   runtime if the key is absent. Fixed by guarding with `"key" in map` before
   accessing the value. Applied to both `enable_compliance` and
   `enable_entitlements` guards in `redhat_identity.cel`.

## Implementation Steps

### Step 1: `OAuthAccessDenied` + `accessDenied` CEL function ✅

**Files changed**:
- `internal/service/mapper.go` — `OAuthAccessDenied OAuthErrorCode = "access_denied"`
- `internal/server/oauth_errors.go` — `case OAuthAccessDenied: 403 + PermissionDenied`
- `internal/cel/mapper_input.go` — `{"accessDenied", func(m) { return DenyOAuth(OAuthAccessDenied, m) }}`

**Tests added**:
- `TestExchangeErrToAuthzDenial/access_denied_is_forbidden` (`internal/server`)
- `TestAbortDecision_MatchesDenyConstructors/layer_a_access_denied` (`internal/cel`)
- `TestCELMapper_LayerA/access_denied` (`internal/mapper`)

### Step 2: `Base64Service` ✅

Already present on main branch (`internal/lua/base64.go`). No work needed.

### Step 3: `configs/scripts/export_compliance.lua` ✅

**File created**: `configs/scripts/export_compliance.lua`

Fail-open Lua script with:
- `resolve_username(input)` — console/rhsm/portal claim shapes
- `resolve_org_and_account(input)` — for identity envelope
- `build_identity_envelope(username, org_id, account_number)` — minimal identity
- `fetch(input)` — fail-open, JSON result `{result_code, synthetic}`
- `fetch_cache_key(input)` — nil for bypass/synthetic, username-based otherwise

### Step 4: `configs/scripts/redhat_identity.cel` ✅

**File changed**: `configs/scripts/redhat_identity.cel`

- Compliance guard added to all three User jwt-auth branches (console, rhsm, portal)
- Guard uses `"enable_compliance" in map` to avoid "no such key" runtime errors
- Entitlements guard updated similarly (`"enable_entitlements" in map`)
- Compliance check placed before identity map output (before any future cross-account swap)

### Step 5: Configuration ✅

**Files changed**:
- `configs/parsec.yaml` — `export_compliance` DS with `compliance_api`, `ttl: 24h`, `in_memory`
- `configs/examples/parsec-production.yaml` — `export_compliance` DS with `distributed` cache

### Step 6: Tests ✅

**Files created**:
- `internal/datasource/export_compliance_lua_test.go` — 13 Lua unit tests covering all ACs
- `test/e2e/hermetic_authz_compliance_test.go` — 8 hermetic e2e tests

### Step 7: Docs ✅

**Files changed**:
- `configs/README.md` — compliance DS example + smoke test instructions
- `internal/datasource/LUA_DATASOURCE.md` — pointer to `export_compliance.lua`
- `docs/issuance-policy.md` — `accessDenied` in Layer A table + transport mapping

### Step 8: Downstream app-interface synchronization (merge prerequisite)

**Status**: Pending (required before enabling in production)

Per [`.cursor/rules/deploy-config-sync.mdc`](../../.cursor/rules/deploy-config-sync.mdc):

- Add `export_compliance` DS + `export_compliance.lua` script mount to stage and prod app-interface secrets
- Set `compliance_api` via secret/env (`PARSEC_DATA_SOURCES__N__CONFIG__COMPLIANCE_API`)
- Configure `enable_compliance: "true"` on eligible Envoy gateways **only after stage validation**
- Until updated: gate off / no DS → current behavior (fail-safe — compliance not called)
- Confirm cache bypass header name (`x-rh-insights-gateway-use-compliance-cache`) with gateway team

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| OAuth code | `OAuthAccessDenied` | RFC 6749 §4.1.2.1; parallel to `OAuthInvalidRequest` |
| CEL function | `accessDenied` | Layer A; parallel to `invalidRequest`, `invalidSubject` |
| Data source | `export_compliance` | Matches feature name |
| Script | `export_compliance.lua` | Same |
| Config key | `compliance_api` | Parallel to `entitlements_api` |
| Context extension | `enable_compliance` | Parallel to `enable_entitlements` |
| Cache group | `compliance-cache` | Parallel to `entitlements-cache` |

## Test Plan

Per [`docs/testing.md`](../testing.md): hermetic, fixtures not mocks.

### Unit Tests

| Test | Package | AC |
|------|---------|----|
| `TestExchangeErrToAuthzDenial/access_denied_is_forbidden` | `internal/server` | AC4 |
| `TestAbortDecision_MatchesDenyConstructors/layer_a_access_denied` | `internal/cel` | AC4 |
| `TestCELMapper_LayerA/access_denied` | `internal/mapper` | AC4 |
| `TestExportComplianceLua_Fetch_Pass` | `internal/datasource` | AC2 |
| `TestExportComplianceLua_Header_XRhIdentity` | same | AC2 |
| `TestExportComplianceLua_Fetch_FailOpen_Non200` | same | AC3 |
| `TestExportComplianceLua_Fetch_FailOpen_TransportError` | same | AC3 |
| `TestExportComplianceLua_Fetch_FailOpen_MissingUsername` | same | AC3 |
| `TestExportComplianceLua_Fetch_FailOpen_MalformedJSON` | same | AC3 |
| `TestExportComplianceLua_Fetch_BlockedResultCode` | same | AC4 |
| `TestExportComplianceLua_CacheKey_Username` | same | AC6 |
| `TestExportComplianceLua_CacheKey_NilForSynthetic` | same | AC7 |
| `TestExportComplianceLua_CacheKey_NilForBypassHeader` | same | AC8 |
| `TestExportComplianceLua_DifferentUsers` | same | AC6 |
| `TestExportComplianceLua_MissingConfig` | same | AC3 |
| `TestExportComplianceLua_RHSMTokenShape` | same | AC1, AC2 |

### E2E Tests (hermetic)

| Test | AC |
|------|----|
| `gate off does not call compliance service` | AC5 |
| `gate on + pass result code → token issued` | AC3, AC4 |
| `gate on + ERROR_T5 → 403 denied` | AC4 |
| `gate on + ERROR_EXPORT_CONTROL → 403 denied` | AC4, AC10 |
| `gate on + ERROR_OFAC → 403 denied` | AC4, AC10 |
| `gate on + unknown result code → token issued` | AC10 |
| `gate on + compliance service down → fail-open` | AC3 |
| `service account: no compliance check` | AC1 |

## Risks & Open Questions

| # | Item | Status |
|---|------|--------|
| 1 | **Claim-shape duplication recurs** (Risk #7 from RHCLOUD-49315) | Open / track |
| 2 | **Cache bypass header name** — confirm `x-rh-insights-gateway-use-compliance-cache` with gateway team | Confirm before enabling |
| 3 | **`access_denied` semantics** — using RFC 6749 §4.1.2.1 code for server-side policy denial | Accepted (close enough) |
| 4 | **CEL ordering: compliance before cross-account** — verify AC9 holds as cross-account logic (RHCLOUD-47320) is implemented | Verify in RHCLOUD-47320 |
| 5 | **`"key" in map` guard added to both enable_compliance and enable_entitlements** — this fixes a pre-existing latent bug in redhat_identity.cel | Fixed in this PR |

## Review Log

| Date | Reviewer | Notes |
|------|----------|-------|
| 2026-08-19 | Adam O'Brien | Implementation complete; all tests pass |
