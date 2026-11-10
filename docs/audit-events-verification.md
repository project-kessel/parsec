# Audit events: local verification

How to run parsec with audit logging on and check the records it emits. The
records below were captured from this configuration.

## Run

`configs/examples/parsec-audit-verification.yaml` uses a stub validator that
accepts any bearer token, and the server listens on all interfaces (there is
no bind-address setting). Run it only on a machine that untrusted networks
cannot reach.

```bash
make build
./bin/parsec serve --config ./configs/examples/parsec-audit-verification.yaml
```

Audit records are JSON lines on stdout with `"event":"parsec_..."`. Diagnostic
logs from the `logging` observer are interleaved; filter with:

```bash
./bin/parsec serve --config ... | grep '"event":"parsec_'
```

## Requests and the records they produce

Token exchange over HTTP (`request_id` in the record is the `x-request-id`
sent):

```bash
TE=urn:ietf:params:oauth:grant-type:token-exchange
JWT=urn:ietf:params:oauth:token-type:jwt

# success
curl -X POST localhost:8080/v1/token -H 'x-request-id: verify-exchange-ok' \
  -d grant_type=$TE -d subject_token=abc -d subject_token_type=$JWT \
  -d audience=parsec.demo.local

# unsupported grant type
curl -X POST localhost:8080/v1/token -H 'x-request-id: verify-exchange-bad-grant' \
  -d grant_type=password -d subject_token=abc -d subject_token_type=$JWT

# audience does not match the trust domain
curl -X POST localhost:8080/v1/token -H 'x-request-id: verify-exchange-bad-audience' \
  -d grant_type=$TE -d subject_token=abc -d subject_token_type=$JWT \
  -d audience=other.example

# request_context that is not JSON
curl -X POST localhost:8080/v1/token -H 'x-request-id: verify-exchange-bad-context' \
  -d grant_type=$TE -d subject_token=abc -d subject_token_type=$JWT \
  --data-urlencode 'request_context={not json'
```

The authorization check is gRPC only (`envoy.service.auth.v3.Authorization/Check`
on port 9090; reflection is enabled, so `grpcurl` works). Send one request with
`authorization: Bearer abc` and one with no credential.

| Request | `event` | `action` | `outcome` | `reason_code` | `level` |
|---|---|---|---|---|---|
| server start | `parsec_process_status` | `process_ready` | `success` | | `info` |
| exchange, valid | `parsec_request` | `token_exchange` | `success` | | `info` |
| exchange, unsupported grant type | `parsec_request` | `token_exchange` | `denied` | `grant_type_unsupported` | `warn` |
| exchange, audience mismatch | `parsec_request` | `token_exchange` | `denied` | `invalid_request` | `warn` |
| exchange, bad `request_context` | `parsec_request` | `token_exchange` | `denied` | `invalid_request` | `warn` |
| check, bearer token | `parsec_request` and `parsec_authorize` | `authorize` | `success` | | `info` |
| check, no credential | `parsec_request` and `parsec_authorize` | `authorize` | `denied` | `credential_missing` | `warn` |
| SIGTERM | `parsec_process_status` | `process_stop` | `success` | | `info` |

`parsec_authorize` is emitted next to `parsec_request` for every authorization
check and copies its outcome and reason.

## Record shape

A successful authorization check:

```json
{
  "level": "info",
  "time": "2026-11-10T18:49:44+05:30",
  "event": "parsec_request",
  "schema_version": "1.0",
  "action": "authorize",
  "outcome": "success",
  "request_id": "verify-authz-ok",
  "duration_ms": 0,
  "service": {"name": "parsec", "version": "v0.11.0", "trust_domain": "parsec.demo.local"},
  "request": {"protocol": "ext_authz", "method": "GET", "path": "/api/inventory/v1/hosts"},
  "subject": {"id": "test-subject", "trust_domain": "test-domain", "credential_type": "bearer"},
  "actor": {},
  "resource": {
    "type": "authorization_request",
    "token_types": ["urn:ietf:params:oauth:token-type:txn_token"],
    "requested_token_types": ["urn:ietf:params:oauth:token-type:txn_token"]
  },
  "message": "parsec_request"
}
```

A denied token exchange adds `reason_code` and has empty principals when the
request was refused before validation:

```json
{
  "level": "warn",
  "event": "parsec_request",
  "action": "token_exchange",
  "outcome": "denied",
  "request_id": "verify-exchange-bad-context",
  "request": {"protocol": "grpc", "method": "POST", "path": "/v1/token"},
  "subject": {},
  "actor": {},
  "resource": {"type": "token_exchange_request"},
  "reason_code": "invalid_request"
}
```

Fields that appear only when they apply, all under `resource`:

| Field | Meaning |
|---|---|
| `cache_layers` | One entry per cache consulted: `layer` and `status` (`hit`, `miss`, `expired`, `failure`). A `miss` followed by a failed load is still a `miss`; `failure` means the cache itself failed. |
| `failed_component` | The first dependency that failed, for example `jwks` or `datasource:<name>`. |
| `signals_dropped` | Signals refused because the request already held 32. |
| `signals_rejected` | Signals refused because they failed validation. |
| `metadata_keys_stripped` | Metadata keys removed because they are not in `audit_metadata_keys`. The signal is kept. |
| `key_name` | On key rotation events, the key the event is about. |

Signals recorded by scripts through `audit.record()` appear in the request
record's top-level `signals` array.

## Outcomes

- `success`: the request was allowed, or the token was issued.
- `denied`: the request was refused for a reason attributable to the caller or
  to policy (bad or missing credential, policy decision, malformed request).
- `failure`: parsec or a dependency failed. A request that ends without any
  component stating an outcome is recorded as `failure` / `internal_error`.

Reason codes are a fixed list defined in `internal/audit/signal.go`. A signal
sent with a `reason_code` outside that list is kept: the value is cleared and,
if the signal has no `classification`, moved there.
Deployment-specific detail belongs in a signal's `classification`.
