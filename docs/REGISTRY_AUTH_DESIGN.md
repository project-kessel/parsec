# Registry Auth Design

## Overview

Registry auth extends parsec's credential system to authenticate users via HTTP Basic Auth against an external container registry authorization service. It adds a `BasicAuthCredentialSource` for credential extraction and a Lua validator script for validation, reusing the same `CredentialSource` / trust store / CEL mapper pipeline as bearer tokens.

The external registry service is a POST endpoint that accepts `{"credentials":{"username":"...","password":"..."}}` and returns `{"access":{"pull":"granted"}}` on success.

## End-to-End Flow

```
Envoy CheckRequest (Authorization: Basic <base64>)
  |
  v
[BasicAuthCredentialSource.Extract]
  - Decodes base64 → username:password
  - Returns BasicAuthCredential + marks "authorization" in HeadersUsed
  |
  v
[TrustStore.Validate]
  - Routes by credential type (basic_auth → LuaValidator)
  |
  v
[CacheableLuaValidator.Validate]
  - Checks cache using key derived from validate_cache_key() → returns cached Result on hit
  - Runs validate() in Lua sandbox:
    - Checks username against Lua pattern
    - POSTs credentials to registry service via named HTTP client (mTLS)
    - Verifies access.pull == "granted"
    - Parses "org_id|username" format
  - Returns trust.Result with org_id claim (when present)
  |
  v
[CEL Claim Mapper]
  - Detects registry auth via:
      subject.issuer.contains(<configured registry service url>)
  - Maps claims into x-rh-identity envelope
  |
  v
[Response]
  - Issued tokens set as response headers
  - Original Authorization header removed (security boundary)
```

## Components

### BasicAuthCredentialSource

Implements `CredentialSource`. Extracts HTTP Basic Auth credentials from the `Authorization` header.

```go
type BasicAuthCredentialSource struct {
    SourceName string  // default: "authorization_basic_auth"
}
```

**Extraction logic:**
1. Read `authorization` header (normalized to lowercase)
2. Split on first space: `scheme value`
3. Case-insensitive check: scheme must be `"basic"`
4. Trim whitespace from value, reject if empty
5. Base64-decode the value
6. Split on first colon: `username:password`
7. Return `CredentialExtraction` with `BasicAuthCredential` and `HeadersUsed: ["authorization"]`

Returns `nil, nil` when the header is absent or the scheme is not Basic, allowing coexistence with `BearerCredentialSource` in the same source chain.

### Lua Validator Script (`registry_auth.lua`)

Validates `BasicAuthCredential` by calling an external registry authorization service over HTTPS. The script runs inside parsec's Lua sandbox with access to `config`, `json`, and `http` modules.

**`validate(input)` steps:**
1. Read `registry_url`, `trust_domain`, `username_pattern` from `config.get()`
2. Reject empty username or password (return `nil`)
3. Match username against Lua pattern if `username_pattern` is configured
4. Parse username as `org_id|username` or `|username` (split on first `|`); reject if pipe is missing or parsed username is empty (return `nil`)
5. POST `{"credentials":{"username":"...","password":"..."}}` to registry URL via `http.post()`
6. Error if response is nil (raises Lua `error()`, propagates as a Go error)
7. Reject non-200 status codes (return `nil`)
8. Parse JSON response, verify `access.pull == "granted"` (return `nil` if not granted)
9. Return result table with `subject`, `issuer`, `trust_domain`, and claims

**`validate_cache_key(input)` steps:**
1. Return a table containing only `credential.type`, `credential.username`, and `credential.password`
2. This defines which input fields affect the validation result — the Go caching layer uses this to derive cache keys

**Result claims:**

| Claim | Value | Source |
|-------|-------|--------|
| `org_id` | Parsed from username prefix (only set when non-empty) | `"123\|alice"` → `"123"`, `"\|alice"` → not set |

### Username Format

Usernames follow the pattern `org_id|username` or `|username` (without org ID):

```
123|alice       → org_id="123", subject="alice"
999|bob         → org_id="999", subject="bob"
123|alice|extra → org_id="123", subject="alice|extra"  (split on first |)
|alice          → org_id not set, subject="alice"
```

The `username_pattern` config validates the raw username before parsing. The default pattern for Red Hat is `^%d*|.+` (zero or more digits before pipe, non-empty username) using Lua pattern syntax.

### Caching

Successful validations are cached to avoid repeated calls to the registry service. Caching is split into two layers:

1. **Key definition (Lua)**: `validate_cache_key(input)` returns a table with only the fields that affect the result. The Go caching layer serializes this to JSON and uses it as the cache key.

2. **Storage (Go)**: Configured via the `caching:` YAML block on the validator:
   - `in_memory` — `InMemoryCachingValidator` stores results in a local map
   - `distributed` — `DistributedCachingValidator` uses groupcache for cluster-wide caching
   - `none` — caching disabled

**TTL**: Configured via `caching.ttl` in YAML. The `CacheableLuaValidator` exposes this to the caching wrapper.

### HTTP Client

The Lua script makes HTTP calls via a named HTTP client resolved from the `http_clients` registry. This provides:

- **mTLS**: Client certificate authentication via `CertSource` (file-based or other providers)
- **Timeouts**: Configured on the named client
- **Reuse**: The same client can be shared across validators and data sources

The HTTP client is injected into the Lua sandbox's `http` module, so `http.post()` calls in the script use the configured client transparently.

### CEL Integration

Registry auth is detected in CEL mapper expressions by checking the issuer set by the Lua validator:

```cel
has(subject.issuer) && subject.issuer.contains(<configured registry service url>)
```

The `issuer` is set to the `registry_url` config value by the Lua script on successful validation. The CEL script should use the appropriate URL substring for the target environment.

When `org_id` is absent from claims, the identity envelope sets `org_id` to `null`.

## Configuration

```yaml
http_clients:
  - name: registry-mtls
    timeout: "30s"
    client_cert_source:
      type: file
      cert: "./local/client.crt"
      key: "./local/client.key"

credential_sources:
  - name: basic-auth
    type: authorization_basic_auth
  - name: authorization-bearer
    type: authorization_bearer_opaque

trust_store:
  type: stub_store
  validators:
    - name: registry-auth
      type: lua_validator
      script_file: ./configs/scripts/registry_auth.lua
      credential_types: ["basic_auth"]
      http_client: registry-mtls
      config:
        registry_url: "https://container-registry-authorizer.stage.api.redhat.com/v1/authorization"
        trust_domain: "registry.redhat.com"
        username_pattern: "^%d*|.+"
      caching:
        type: in_memory
        ttl: "5m"
```

### Validator Config Fields

| Field | Required | Description |
|-------|----------|-------------|
| `script_file` | Yes | Path to the Lua script |
| `credential_types` | Yes | Must include `"basic_auth"` |
| `http_client` | No | Name of a client from `http_clients` registry (provides mTLS) |
| `config.registry_url` | Yes | HTTPS URL of the registry authorization service |
| `config.trust_domain` | Yes | Trust domain assigned to validated results |
| `config.username_pattern` | No | Lua pattern usernames must match |
| `caching.type` | No | `in_memory`, `distributed`, or `none` |
| `caching.ttl` | No | Cache duration for successful validations |

### HTTP Client Config Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Identifier referenced by `http_client` on the validator |
| `timeout` | No | HTTP client timeout (default `30s`) |
| `client_cert_source.type` | No | Certificate source type (`file`) |
| `client_cert_source.cert` | Yes (if mTLS) | Path to client certificate |
| `client_cert_source.key` | Yes (if mTLS) | Path to client private key |

## Security Considerations

- **Credential removal**: The `Authorization` header is stripped from requests forwarded to backends.
- **Cache key derivation**: Cache keys are derived from the JSON serialization of `validate_cache_key()` output (credential type, username, password). The caching wrappers handle key hashing.
- **mTLS**: Client certificate authentication to the registry service is configured via the named HTTP client.
- **Lua sandbox**: The validation script runs in a restricted Lua environment with no filesystem or OS access — only `config`, `json`, and `http` modules are available.

## Testing

Key test scenarios:
- Successful validation with claim extraction
- Username pattern rejection
- Cache hit / cache miss
- Registry returns non-200 / denies access / returns malformed JSON
- Username parsing edge cases (multiple pipes, empty parts)
- BasicAuth extraction (case-insensitive scheme, invalid base64, coexistence with bearer)
- Credential JSON roundtrip serialization for `BasicAuthCredential`
