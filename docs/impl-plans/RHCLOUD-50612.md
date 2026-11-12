# RHCLOUD-50612: Keep deployment audit events out of core

**JIRA**: RHCLOUD-50612 ([PR 207](https://github.com/project-kessel/parsec/pull/207))
**Status**: In review (single PR)
**Date**: 2026-11-12

## Context

Review of PR 207 asked that deployment-specific concepts stay out of the Go
core. Names such as `cross_account_access` had already been removed, but three
routes still existed only so that one script or config could make core emit
its own named audit event:

| Route | Used by | Event produced |
|---|---|---|
| `Signal.Event` (Lua `audit.record{event=...}`) | `bop_user.lua`, `export_compliance.lua` | `supplemental_user_data_failure`, `compliance_failure` |
| Three-argument `accessDenied` and `ExchangeError.AuditEvent` | `redhat_identity.cel` | `auth_compliance_failure` |
| `audit_credential_events` config | deploy and example configs | `validate_ssl_cert`, `verify_psk` |

Core also needed `ReservedEvent` to protect its own event names from these
routes, and it emitted two duplicate events (`authorize` and
`dependency_failure`) that no recorded requirement asked for.

**Test of success:** deleting any script in `configs/scripts/` leaves no dead
code in `internal/`.

### Acceptance Criteria

- [x] AC1: The audit observer emits exactly one `<prefix>request` record per request, plus the `process_status` and `key_rotation` lifecycle events.
- [x] AC2: Lua, CEL and config have no way to name an audit event.
- [x] AC3: The request record carries what a log pipeline needs to derive the removed events: signals, each principal's credential type and validation result, `reason_code`, and `resource.failed_component`.
- [x] AC4: A config that still sets `audit_credential_events` loads without error.

## Design

### Server Code vs. Configuration

| Question | Answer |
|----------|--------|
| Does this modify server Go code or use configuration/policy? | Server code. Every change removes deployment-shaped surface or adds one generic field. |
| Does any proposed server code hardcode claim names, issuer URLs, vendor behaviors, or deployment-specific logic? | No |
| Which existing parsec policy/config layer fits? | None is needed. Deployment event names are derived downstream from the request record. |

### Decisions

| Decision | Choice | Why |
|---|---|---|
| Where deployment event names come from | The log pipeline, from the request record | Core keeps no concept of a deployment event. A config matcher can still be added later without rework. |
| `authorize` and `dependency_failure` events | Removed | They repeat `action == "authorize"` and `reason_code == "dependency_failure"` from the request record. |
| Signals lost on a data-source cache hit | Follow-up | Fixing this changes both cache entry formats. It is documented as a known gap. |
| Token types in the audit record | Taken from configured issuers | The earlier hardcoded list, which included the Red Hat identity type, hid any other configured type. The exchange handler passes the client's `requested_token_type` through unchanged, so a type with no configured issuer is recorded as `unrecognized`, not copied. |
| Signals discarded by the Lua adapter | Counted in `signals_rejected` | An unknown field or malformed metadata used to drop the signal with no trace in the record. |

### Interface Changes

- `audit.Signal` loses `Event`. Lua `audit.record` returns `false` for an `event` field, as it does for any unknown field.
- CEL `accessDenied(message, classification, event)` is removed. `accessDenied(message, classification)` still records a `policy` signal.
- `service.ExchangeError.AuditEvent` is removed.
- `audit.WithCredentialEvents`, `audit.CredentialEvents`, `audit.ReservedEvent` and `config.AuditCredentialEventsConfig` are removed.
- The `subject` and `actor` in the request record gain `validation: {outcome, reason_code}`. It is absent when that principal's credential was never validated.

### Mapping from removed events to the request record

| Earlier event | Request record where |
|---|---|
| `authorize` | `action == "authorize"` |
| `dependency_failure` | `reason_code == "dependency_failure"`, or a signal with that `reason_code` |
| `validate_ssl_cert` | `subject.credential_type` is `mtls` or `forwarded_client_cert`; result in `subject.validation` |
| `verify_psk` | `actor.credential_type == "header"`; result in `actor.validation` |
| `supplemental_user_data_failure` | a signal with `operation == "user_enrichment"` and `outcome == "failure"` |
| `compliance_failure` | a signal with `operation == "export_compliance"` and `outcome == "failure"` |
| `auth_compliance_failure` | a signal with `source == "policy"` and `classification == "compliance_denied"` |

## Configuration Impact

`audit_credential_events` is removed. koanf ignores the key, so an existing
config still loads, but the extra events stop. This is covered by
`TestLoaderReadsAuditPrincipalClaims`.

| Environment | What to update |
|-------------|----------------|
| Stage / Prod (`PARSEC_CONFIG_SECRET`) | Remove `audit_credential_events`. Make sure log pipeline rules derive the events listed above before deploying. |

## Execution record

- Production code: `internal/audit/signal.go`, `internal/lua/audit.go`, `internal/cel/mapper_input.go`, `internal/service/mapper.go`, `internal/probe/audit/audit.go`, `internal/config/{config,provider}.go`.
- Scripts and configs: `bop_user.lua`, `export_compliance.lua` and `redhat_identity.cel` no longer name events. `audit_credential_events` is removed from every shipped and deploy config.
- Tests: `cross_account_lua_test.go` and `export_compliance_lua_test.go` moved from `internal/datasource` to `configs/scripts`, so core test packages no longer load deployment scripts.
- Docs: `configs/README.md` (mapping table), `internal/cel/README.md`, `internal/datasource/LUA_DATASOURCE.md` (cache-hit gap).
- Deviations from the plan: the work landed as one commit, because the steps edit the same functions.
- Review follow-ups in the same commit: `validation` is omitted for a principal with no credential; token types come from configured issuers; Lua adapter rejections are counted.
- Verification: `make test`, `make lint` (0 issues), and boundary greps for `AuditEvent|ReservedEvent|CredentialEvents|MaxEventLength|reasonEventSuffix`. The greps find nothing outside the config-compatibility test.

## Risks & Open Questions

| # | Item | Status | Resolution |
|---|------|--------|------------|
| 1 | A consumer already alerts on a removed event name | Open | Mapping table in README and PR description. The pipeline owner must confirm before merge. |
| 2 | Signals from cached data-source results | Open | Follow-up PR: store signals with cache entries and replay them on a hit. |
