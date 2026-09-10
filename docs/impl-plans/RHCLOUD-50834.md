# HTTP-CLIENT-BASE-URL: Shared host on named HTTP clients

**JIRA**: [RHCLOUD-50834](https://redhat.atlassian.net/browse/RHCLOUD-50834) (follow-up to [PR 188](https://github.com/project-kessel/parsec/pull/188) / RHCLOUD-49359; Slack: shared entitlements host for `/services` and `/compliance`)
**Status**: In review (single PR)
**Author**: Adam O'Brien
**Date**: 2026-09-02

## Context

Named HTTP clients already share timeout, TLS, auth, and the `*http.Client`
connection pool (`http_client: entitlements` on multiple data sources). The
**host** still lives in each Lua `config` as a full URL (`compliance_api`),
because `*http.Client` has no URL and Lua `http.get` requires an absolute URL.

Jozef/Daniel’s follow-up is a single place for
`https://entitlements.example.com`, with each script supplying a path
(`/v1/compliance` vs `/v1/services`). Same gap as BOP: `bop-user` and cert-auth
duplicate the proxy host in two `config:` blocks.

This plan adds optional `base_url` on the HTTP client spec and resolves
relative Lua URLs against it. Absolute URLs stay valid.

**Out of scope:** Implementing `user_entitlements.lua` (production example is
still a placeholder). Migrating BOP scripts to relative paths (same mechanism,
later ticket).

### Acceptance Criteria

- [x] AC1: Optional `base_url` on named and inline HTTP clients. Absent/empty preserves today’s behavior (absolute Lua URLs work).
- [x] AC2: With `base_url` set, Lua `http.get`/`post`/`request` resolve relative URLs against it (`/v1/compliance` → `{base}/v1/compliance`).
- [x] AC3: Absolute Lua URLs (scheme present) are used as-is even when `base_url` is set (JWT JWKS and existing scripts unchanged).
- [x] AC4: Relative Lua URL with no `base_url` returns `(nil, error)` from the Lua HTTP service (does not call the network).
- [x] AC5: Invalid `base_url` (missing scheme or host, non-http(s) scheme, embedded user info, or non-origin form) fails at **config load / registry build**, not on the first request.
- [x] AC6: `export_compliance` uses `compliance_api` as a path (e.g. `/v1/compliance`) resolved against the `entitlements` client’s `base_url`. Full `compliance_api` URLs still work (fail-safe / env overlay).
- [x] AC7: JWT validators ignore `base_url` (they use `Registry.Get` / `*http.Client` with an absolute JWKS URL).
- [x] AC8: Test with `base_url` absent matches previous Lua HTTP behavior.

### External References

- [PR 188](https://github.com/project-kessel/parsec/pull/188) — export compliance; named `entitlements` client already wired
- Slack (2026-09-01): Daniel — share HTTP config between `/services` and `/compliance`; Jozef — not possible today (meant **host**, not the client object); follow-up like BOP base URL
- [RHCLOUD-50414](https://redhat.atlassian.net/browse/RHCLOUD-50414) — env-specific hosts belong in namespace variables
- Cursor draft: `http_client_base_url_917055cb.plan.md`

## Design

### Server Code vs. Configuration

> **Answer these questions FIRST before proceeding with any design.**

| Question | Answer |
|----------|--------|
| Does this modify server Go code or use configuration/policy? | **Both**. Generic Go: optional URL join on the existing Lua HTTP service + `base_url` on `HTTPClientSpec`. Deployment hosts/paths stay in YAML/Lua config. |
| If server code: is the change generic (any IdP/vendor/deployment) or specific? | **Generic** — RFC 3986 resolve of relative URLs against a configured base. No entitlements/BOP/compliance strings in Go. |
| Does any proposed server code hardcode claim names, issuer URLs, vendor behaviors, or deployment-specific logic? | **No.** |
| Which existing parsec policy/config layer fits? | Existing `http_clients` registry + Lua `http` service. |
| If none: does this need a new abstraction layer? | **No.** Extends the current HTTP client layer in a **single PR** (generic join + `export_compliance` YAML/script). |

_Parsec is a generic service. Server code must never contain logic specific to
a particular IdP, vendor, or deployment. Use configuration/policy layers for
deployment-specific behavior. If a new abstraction is needed, it gets its own
dedicated PR — designed generically, tested, and documented — before the
use-case PR that wires it up._

### Approach

`*http.Client` cannot store a base URL. Join **before** `http.NewRequestWithContext` in [`internal/lua/http.go`](../../internal/lua/http.go). Config resolves a [`httpclient.LuaClient`](../../internal/httpclient/lua_client.go) (client + optional `BaseURL`) via `GetLua` / `BuildLua` and passes it into Lua data sources and Lua validators; each wires `WithBaseURL` from `LuaClient.BaseURL`.

```mermaid
flowchart LR
  yaml["http_clients.base_url"] --> spec["ClientSpec.BaseURL"]
  spec --> luaHTTP["lua.HTTPService"]
  script["http.get('/v1/compliance')"] --> luaHTTP
  luaHTTP -->|"url.ResolveReference"| doReq["http.Client.Do"]
```

Resolution (`net/url`):

1. Parse the Lua URL string.
2. If it has a scheme → use as-is (AC3).
3. Else if `base_url` is empty → return Lua `(nil, error)` (AC4).
4. Else `base.ResolveReference(rel)`.

Document **origin-form** bases (`https://host.example`, no path; optional trailing `/` only). Non-origin bases are rejected at startup. Lua paths should start with `/` so the joined URL is `{base}/path`.

Registry `Get`/`Build` still return `*http.Client` for non-Lua callers. Lua consumers use `GetLua` / `BuildLua`, which return `LuaClient{Client, BaseURL}`. `BaseURL` is stored beside each named client in the registry. Unexported `resolveHTTPClient` returns `httpclient.LuaClient`.

JWT validators keep calling `Get` only (or use `LuaClient` without a base URL); they never resolve relative URLs (AC7).

`base_url` validation is centralized in [`httpclient.ParseBaseURL`](../../internal/httpclient/base_url.go): origin-form only; scheme must be `http` or `https`; user info (`user:pass@`) rejected.

Env overlay: `PARSEC_HTTP_CLIENTS__N__BASE_URL` via existing slice-aware merge ([`internal/config/merge.go`](../../internal/config/merge.go)).

### Alternatives Considered

| Alternative | Pros | Cons | Why not |
|-------------|------|------|---------|
| YAML-only: duplicate `entitlements_url` + path per DS (BOP-style) | No Go | Host still copied; Jozef’s gap remains | Does not meet AC2 |
| YAML anchors for the host string | No Go | Fragile with koanf/env overlay; not a runtime join | Rejected |
| Put `base_url` on stdlib `*http.Client` / custom `CheckRedirect` | One object | Client.Do still requires an absolute URL; `NewRequest` fails first | Impossible without join in HTTPService |
| Custom `RoundTripper` that prefixes paths | Transport-level | Relative URLs never reach RoundTrip | Rejected |
| Shared static data source for the host | Config-only | Lua cannot read another DS’s config | Rejected |

### Interface Changes

No new observer interfaces. Additive options and config fields only.

```go
// internal/httpclient — shared validation and Lua bundle.
func ParseBaseURL(raw string) (*url.URL, error)

type LuaClient struct {
    Client  *http.Client
    BaseURL string
}
func (r *Registry) GetLua(name ClientName) (LuaClient, error)
func (r *Registry) BuildLua(spec ClientSpec) (LuaClient, error)

// internal/lua — optional constructor option (zero = no base).
func WithBaseURL(base string) HTTPServiceOption

// internal/trust — Lua validators take the same bundle as data sources.
func WithLuaHTTP(client httpclient.LuaClient) LuaValidatorOption

// internal/datasource — HTTP field on existing config structs.
type LuaDataSourceConfig struct {
    // ...
    HTTP httpclient.LuaClient
}

// internal/config — resolver returns the bundle for Lua consumers.
func resolveHTTPClient(name string, spec *HTTPClientSpec, registry *httpclient.Registry) (httpclient.LuaClient, error)
```

[`httpclient.Registry.Get`](../../internal/httpclient/httpclient.go) signature **unchanged** for JWT and other non-Lua callers. Internally register:

```go
type registeredClient struct {
    client  *http.Client
    baseURL string
}
```

`Build` (inline) returns `*http.Client`; `BuildLua` returns `LuaClient` with the spec’s `BaseURL`.

**Backward compatibility:** Existing `Get` callers (JWT) unaffected. Existing Lua scripts that pass absolute URLs unaffected when `base_url` is absent or set.

### Package Impact

| Package | Change Type | Description |
|---------|------------|-------------|
| `internal/lua` | Modified | `WithBaseURL`, `resolveRequestURL` on get/post/request |
| `internal/httpclient` | Modified | `ParseBaseURL`; store `baseURL` on register; `GetLua` / `BuildLua`; `LuaClient` |
| `internal/config` | Modified | `HTTPClientSpec.BaseURL`; validate via `ParseBaseURL`; `resolveHTTPClient` → `LuaClient` |
| `internal/datasource` | Modified | `LuaDataSourceConfig.HTTP` is `httpclient.LuaClient`; pass `WithBaseURL` in Fetch |
| `internal/trust` | Modified | `WithLuaHTTP(httpclient.LuaClient)` on Lua validators |
| `configs/` | Modified | `base_url` on `entitlements`; `export_compliance` uses path-only `compliance_api` |
| `configs/scripts` | Modified | `export_compliance.lua` — single `compliance_api` key (path or full URL) |

## Implementation Steps

Single PR: generic `base_url` join, config validation, and `export_compliance` path config together.

### Step 1: `ParseBaseURL` + Lua `WithBaseURL` and resolve (TDD)

**Package**: `internal/httpclient`, `internal/lua`
**Files**: `base_url.go`, `base_url_test.go`, `http.go`, `http_base_url_test.go`
**Status**: Done

- `ParseBaseURL`: origin-form; scheme must be `http` or `https`; reject path/query/fragment
- `WithBaseURL` + `resolveRequestURL` on get/post/request
- Relative URL without base → Lua error; absolute URL unchanged

Run: `GOEXPERIMENT=jsonv2 go test ./internal/httpclient/ ./internal/lua/ -count=1`

### Step 2: Registry `LuaClient`; config validates and plumbs

**Package**: `internal/httpclient`, `internal/config`
**Files**: `httpclient.go`, `lua_client.go`, `config.go`, `http_clients.go`, `loader_test.go`, `datasources.go`, `validators.go`
**Status**: Done

- `HTTPClientSpec.BaseURL`, `ClientSpec.BaseURL`
- `resolveClientSpec` validates with `ParseBaseURL`
- Registry stores `baseURL`; `GetLua` / `BuildLua`; `Get` unchanged for JWT
- `resolveHTTPClient` returns `httpclient.LuaClient`
- Loader + env overlay tests for `PARSEC_HTTP_CLIENTS__N__BASE_URL`

Run: `GOEXPERIMENT=jsonv2 go test ./internal/httpclient/ ./internal/config/ ./internal/datasource/ ./internal/trust/ -count=1`

### Step 3: Docs for `base_url` and shared-host example

**Package**: docs / configs README
**Files**: `configs/README.md`, `internal/lua/README.md`
**Status**: Done

### Step 4: `export_compliance` — single `compliance_api` param

**Package**: `configs/scripts`, `internal/datasource`, `test/e2e`
**Files**: `export_compliance.lua`, `export_compliance_lua_test.go`, `hermetic_authz_compliance_test.go`, `configs/parsec.yaml`, `configs/examples/parsec-production.yaml`
**Status**: Done

Script behavior (no separate `compliance_path` key):

- `compliance_api` unset → default `/v1/compliance` (relative; joins against client `base_url`)
- `compliance_api` without `://` → treated as path (joined against `base_url`)
- `compliance_api` with `://` → absolute URL (fail-safe / env overlay via `PARSEC_DATA_SOURCES__N__CONFIG__COMPLIANCE_API`)

Unit/e2e tests construct the DS with `httpclient.LuaClient{BaseURL: …}` so joined URLs match fixture keys.

Run: `GOEXPERIMENT=jsonv2 go test ./internal/datasource/ -run TestExportCompliance -count=1` and `./test/e2e/ -run TestHermeticAuthzCompliance -count=1`

### Step 5: Downstream app-interface (follow-up, not this repo)

**Status**: Pending (after merge)

Per `.cursor/rules/deploy-config-sync.mdc`:

- Stage/prod secrets: set `http_clients` entry `base_url` (namespace variable)
- Set `compliance_api` to a path (e.g. `/v1/compliance`) once `base_url` is set, or leave full URL until cutover (fail-safe)
- `deploy/parsec.yaml` / `deploy/parsec-ephem.yaml`: no schema change unless they embed HTTP client YAML (today they mount `/etc/parsec/parsec.yaml`)

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| Config field | `base_url` | Origin (scheme + host) for relative Lua URLs |
| Validator | `ParseBaseURL` | Shared origin-form + http(s) validation |
| Lua bundle | `httpclient.LuaClient` | Client + optional `BaseURL` for Lua DS/validators |
| Registry API | `GetLua` / `BuildLua` | Lua consumers; `Get` unchanged for JWT |
| Lua option | `WithBaseURL` | Matches `WithRequestOptions` |
| Validator option | `WithLuaHTTP(LuaClient)` | Same bundle as data sources |
| DS field | `HTTP httpclient.LuaClient` | Replaces bare `*http.Client` on Lua configs |
| Helper | `resolveRequestURL` | Unexported; one place for get/post/request |
| Lua config | `compliance_api` | Path (joined against `base_url`) or full URL (`://`); default `/v1/compliance` when unset |

No new Observer/Probe types.

## Test Plan

Per [`docs/testing.md`](../testing.md): hermetic, no method-verifying mocks. HTTP tests use `httptest` / `httpfixture`.

### Unit Tests

| Test | Package | What it verifies |
|------|---------|-----------------|
| `TestHTTPService_Get_RelativeWithBaseURL` | `internal/lua` | AC2 |
| `TestHTTPService_Post_RelativeWithBaseURL` | `internal/lua` | AC2 |
| `TestHTTPService_Request_RelativeWithBaseURL` | `internal/lua` | AC2 |
| `TestHTTPService_AbsoluteURLIgnoresBaseURL` | `internal/lua` | AC3 |
| `TestHTTPService_RelativeWithoutBaseURLErrors` | `internal/lua` | AC4 |
| `TestHTTPService_Get` (existing) | `internal/lua` | AC8 |
| `TestParseBaseURL` | `internal/httpclient` | AC5 origin-form + http(s) scheme |
| `TestNewHTTPClientRegistry_InvalidBaseURL` | `internal/config` | AC5 |
| `TestNewLoader_HTTPClientBaseURL` | `internal/config` | unmarshal |
| `TestNewLoader_EnvOverrideHTTPClientBaseURL` | `internal/config` | `PARSEC_HTTP_CLIENTS__0__BASE_URL` |
| `TestRegistry_GetLua` / `TestRegistry_BuildLua` | `internal/httpclient` | bundle wiring |
| `TestExportComplianceLua_Fetch_PathWithBaseURL` | `internal/datasource` | AC6 path + join |
| `TestExportComplianceLua_Fetch_*` (absolute URL) | `internal/datasource` | AC6 full-URL fail-safe |

### Contract Tests

N/A — no new interfaces.

### Benchmarks

N/A — one `url.Parse` per Lua HTTP call; not a new hot-path abstraction.

### Integration / E2E

| Test | What it verifies |
|------|-----------------|
| `TestHermeticAuthzCompliance` (updated wiring) | Compliance still 403/fail-open after join (AC6) |

## Observability

Per [`docs/observer-pattern.md`](../observer-pattern.md). No new Observer/Probe.

Existing `HTTPClientObserver` wraps `Client.Do` **after** join, so metrics/traces already see the absolute URL and host.

### Observer Hierarchy

Unchanged (`HTTPClientObserver` on the registry transport).

### New Probes

None.

### Injection

Unchanged: `NewHTTPService(ctx, client, WithBaseURL(...), WithRequestOptions(...))`.

## Security

- [x] Input validation: `base_url` must be origin-form `http` or `https` at config time; relative Lua URLs cannot target an arbitrary host unless `base_url` is set (then only that origin, plus absolute URLs still allowed — same as today)
- [x] Error handling: Lua error strings are parse/join failures, not response bodies
- [x] Credential handling per `docs/CREDENTIAL_DESIGN.md`: N/A — no credential types
- [x] TLS/mTLS: still on the named client (`ca_cert`, `client_cert_source`); `base_url` is scheme+host only

Open redirect: Lua scripts can still pass `https://evil.example` as an absolute URL (AC3). That is existing capability, not introduced here.

## Maintainability

- [x] Constructor pattern: `WithBaseURL` optional; required HTTP client stays positional on `NewHTTPService`
- [x] Forward compatibility: no new interfaces
- [x] Config vs. domain: host in `http_clients`; path in Lua `config`
- [x] Downstream app-interface impact: **yes** — Step 5 after merge

## Configuration Impact

> **Fail-safe rule**: See [config-constraints.md](../../.claude/skills/parsec-impl/config-constraints.md). Absent fields must preserve previous behavior.

### Backward Compatibility

| New Field | Type | Default / Zero Value | Behavior When Absent |
|-----------|------|---------------------|----------------------|
| `http_clients[].base_url` | `string` | `""` | Absolute Lua URLs work as today (AC1, AC8) |
| inline `http.base_url` | `string` | `""` | Same |
| `LuaDataSourceConfig.HTTP` | `httpclient.LuaClient` | zero | Same (empty `BaseURL`) |
| `config.compliance_api` | Lua config | unset | Default path `/v1/compliance`; joined when client has `base_url` |
| `config.compliance_api` | Lua config | full URL with `://` | Used as-is (fail-safe overlay) |

- [x] Every new field has a safe default that preserves prior behavior
- [x] No `panic` or `log.Fatal` on missing new config
- [x] Test verifies behavior with new field absent matches previous version (`TestHTTPService_Get` + AC8)

Invalid **present** `base_url` fails startup (AC5) — that is explicit misconfiguration, not absent config.

### Local Config (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `internal/config/config.go` | New field | `HTTPClientSpec.BaseURL` default `""` |
| `internal/config/http_clients.go` | Validation + resolve | Absolute URL required when set |
| `internal/config/flags.go` | None | No new flags |
| `configs/README.md` | Document field | Done |
| `configs/parsec.yaml` | `base_url` + path-only `compliance_api` | Done |
| `configs/examples/parsec-production.yaml` | Same | Done |

### Deploy Templates (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `deploy/parsec.yaml` | None expected | Mounts `/etc/parsec/parsec.yaml`; schema lives in the secret |
| `deploy/parsec-ephem.yaml` | None expected | Same |

### Downstream app-interface (follow-up required)

> **Action required after merge**: Update the downstream app-interface secrets
> to reflect config changes. Until updated, the new code runs with previous
> behavior (fail-safe). Once config is applied, new behavior activates.
>
> Refer to `.cursor/rules/deploy-config-sync.mdc` for specific paths and
> validation checks for stage and prod environments.

| Environment | What to update |
|-------------|----------------|
| Stage | Add `base_url` on the entitlements HTTP client via namespace var; set `compliance_api` to a path or keep full URL until cutover |
| Prod | Same after stage |

These config changes also need to be applied to the downstream app-interface secret(s).

## Documentation

### New Documentation

None. HTTP clients and Lua HTTP are already documented.

### Documentation Updates

| Doc | Path | What changes |
|-----|------|-------------|
| Config README | `configs/README.md` | `base_url`, origin-form, http(s) only, env overlay, shared-host + `compliance_api` path example |
| Lua services | `internal/lua/README.md` | Relative URLs + `WithBaseURL` |
| Lua DS | `internal/datasource/LUA_DATASOURCE.md` | `compliance_api` path vs full URL |
| AGENTS.md | `AGENTS.md` | No new convention |

### Config Examples

```yaml
http_clients:
  - name: entitlements
    timeout: "5s"
    base_url: "https://entitlements.internal.example.com"

data_sources:
  - name: export_compliance
    type: lua
    http_client: entitlements
    config:
      compliance_api: "/v1/compliance"
```

Lua:

```lua
local response, err = http.get(config.get("compliance_api") or "/v1/compliance")
```

## Completeness Checklist

- [x] **Server code vs. configuration gate passed**: join is generic RFC 3986; hosts/paths stay in YAML/Lua
- [x] Single PR: generic join + `export_compliance` use case (review feedback: no 2-PR split)
- [x] Every acceptance criterion maps to at least one implementation step
- [x] Every new exported type/function has a proposed name
- [x] No new interfaces (NoOp N/A)
- [x] No new observer/probe (existing HTTP client observer sees joined URL)
- [x] Test cases cover new behavior
- [x] Security implications addressed
- [x] Documentation steps included
- [x] Config impact assessed: local, deploy, app-interface
- [x] New config fields fail-safe
- [x] Test with field absent (AC8)
- [x] Explicit app-interface follow-up (Step 5)
- [x] Steps are reviewable units
- [x] Single PR ships generic mechanism and compliance YAML together
- [x] Fail-safe: full `compliance_api` URL and absent `base_url` preserve prior behavior
- [x] Plan can be executed top-to-bottom

## Risks & Open Questions

| # | Item | Status | Resolution |
|---|------|--------|------------|
| 1 | RFC 3986: base `https://h/api` + `/v1/x` drops `/api` | Resolved | **Reject** non-origin `base_url` at startup (scheme + host, optional trailing `/` only). Lua relative paths join as `{base}/path`. Host-specific path prefixes belong in full Lua URLs or `compliance_api`-style config, not in `base_url`. |
| 2 | Absolute Lua URLs still allow any host | Accepted | Same as today (AC3) |
| 3 | Index-based `PARSEC_HTTP_CLIENTS__N__BASE_URL` | Same as data sources | Document index; no name-based env in this work |
| 4 | PR 188 not merged yet | Resolved | Merged as PR #188; this work stacks on it |
| 5 | `user_entitlements.lua` missing | Out of scope | Future ticket; `/v1/services` can reuse same `base_url` pattern |
| 6 | 2-PR split in original plan | Resolved | **Single PR** per review: `LuaClient` bundle + one `compliance_api` key |

## Review Log

| Date | Reviewer | Feedback | Changes Made |
|------|----------|----------|--------------|
| 2026-09-02 | — | Cursor plan `http_client_base_url_917055cb` | Rewritten to parsec-impl template; ACs confirmed |
| 2026-09-09 | Rajagopalan-Ranganathan | Plan outdated vs PR (2-PR split, `compliance_path`); restrict `base_url` scheme to http(s) + tests | Plan aligned to single PR / `LuaClient` / single `compliance_api`; `ParseBaseURL` rejects non-http(s) |
| 2026-09-10 | Rajagopalan-Ranganathan (+1 CodeRabbit) | Reject user info in `base_url` (`https://user:pass@host`) | `ParseBaseURL` rejects `parsed.User != nil`; tests at unit, config, and Lua layers |
