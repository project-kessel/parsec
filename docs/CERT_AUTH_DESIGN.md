# Cert Auth Design

## Overview

Cert auth extends parsec's credential system to authenticate systems via forwarded client certificate headers. A TLS-terminating proxy (e.g., Akamai CDN) validates the client certificate and forwards the subject and issuer as HTTP headers. Parsec extracts these headers via `ForwardedClientCertCredentialSource`, validates them against BOP (Back Office Proxy) using a Lua validator script, and maps the result into an x-rh-identity envelope via CEL.

BOP resolves the certificate CN to an account by calling RHSM's `findOwner` endpoint, returning `account_number`, `org_id`, and certificate `type` (e.g., `satellite`).

## End-to-End Flow

```
Envoy CheckRequest (x-rh-certauth-cn, x-rh-certauth-issuer headers)
  |
  v
[ForwardedClientCertCredentialSource.Extract]
  - Reads subject from configured subject_header (e.g., "x-rh-certauth-cn")
  - Reads issuer from configured issuer_header (e.g., "x-rh-certauth-issuer")
  - Returns ForwardedClientCertCredential{Subject, Issuer}
  - Marks both headers in HeadersUsed
  |
  v
[TrustStore.Validate]
  - Routes by credential type (forwarded_client_cert → LuaValidator)
  |
  v
[CacheableLuaValidator.Validate]
  - Checks cache using key derived from validate_cache_key() → returns cached Result on hit
  - Runs validate() in Lua sandbox:
    - Reads BOP certauth secret from config (resolved from env var at startup)
    - Parses CN value from subject string (/CN=<value>)
    - Calls BOP GET /v1/auth with auth headers + cert headers + env header
    - Parses BOP response for account_number, org_id, type
  - Returns trust.Result with cert-specific claims
  |
  v
[CEL Claim Mapper]
  - Detects cert auth via:
      subject.issuer.contains("backoffice-proxy")
  - Maps claims into x-rh-identity envelope with type "System"
  |
  v
[Response]
  - Issued tokens set as response headers
  - Original cert auth headers removed (security boundary)
```

## Components

### ForwardedClientCertCredentialSource

Implements `CredentialSource`. Extracts certificate subject and issuer from configurable request headers.

```go
type ForwardedClientCertCredentialSource struct {
    SourceName    string
    SubjectHeader string  // e.g., "x-rh-certauth-cn"
    IssuerHeader  string  // e.g., "x-rh-certauth-issuer"
}
```

**Extraction logic:**
1. Read subject value from configured `subject_header`
2. Read issuer value from configured `issuer_header`
3. If both are absent, return `nil, nil` (no credential found)
4. If one is present but the other is missing, return an error
5. Return `CredentialExtraction` with `ForwardedClientCertCredential{Subject, Issuer}` and `HeadersUsed` containing both header names

Returns `nil, nil` when neither header is present, allowing coexistence with other credential sources (e.g., bearer) in the same source chain.

### ForwardedClientCertCredential

```go
type ForwardedClientCertCredential struct {
    Subject string `json:"subject"`  // e.g., "/CN=f6ef9cc8-..."
    Issuer  string `json:"issuer"`   // e.g., "/C=US/ST=North Carolina/..."
}
```

The credential type is `forwarded_client_cert`. The subject contains the raw header value (e.g., `/CN=<uuid>`); CN parsing happens in the Lua validator.

### Lua Validator Script (`forwarded_client_cert_auth.lua`)

Validates `ForwardedClientCertCredential` by calling BOP's `/v1/auth` endpoint. The script runs inside parsec's Lua sandbox with access to `config`, `json`, `http`, and `os` modules.

**`validate(input)` steps:**
1. Read `bop_url`, `trust_domain`, `bop_env` from `config.get()`
2. Read `bop_certauth_secret` from `config.get()` (resolved from env var at startup via `{env: "VAR"}` syntax)
3. Read `input.credential.subject` and `input.credential.issuer`
4. Reject if either is nil or empty (return `nil`)
5. Parse CN value from subject string using pattern `/CN=([^/]+)`
6. GET `bop_url + "/v1/auth"` with headers:
   - `x-rh-clientid` — BOP client ID (injected by HTTP client via `http_auth.type: headers`)
   - `x-rh-apitoken` — BOP API token (injected by HTTP client via `http_auth.type: headers`)
   - `x-rh-insights-certauth-secret` — proxy proof secret (from config, resolved from env at startup)
   - `x-rh-insights-env` — environment routing (from config, defaults to `"stage"`)
   - `x-rh-certauth-cn` — certificate subject
   - `x-rh-certauth-issuer` — certificate issuer
7. Error if response is nil (raises Lua `error()`)
8. Reject non-200 status codes (return `nil`)
9. Parse JSON response, extract `account_number`, `org_id`, `type`
10. Return result table with `subject`, `issuer`, `trust_domain`, and claims

**`validate_cache_key(input)` steps:**
1. Return a table containing `credential.type`, `credential.subject`, and `credential.issuer`
2. This defines which input fields affect the validation result

**Result claims:**

| Claim | Value | Source |
|-------|-------|--------|
| `account_number` | Account number | BOP response `account_number` |
| `org_id` | Organization ID | BOP response `org_id` |
| `cert_type` | Certificate type (e.g., `satellite`) | BOP response `type` |
| `cn` | Parsed CN value | Extracted from subject `/CN=<value>` |

### BOP Authentication

BOP requires three authentication headers on every request. These are split across two layers:

**HTTP client layer** (`http_auth.type: headers`) — injected on every request by the transport:

| Header | Source | Purpose |
|--------|--------|---------|
| `x-rh-clientid` | K8s secret `parsec` | Identifies the calling service |
| `x-rh-apitoken` | K8s secret `parsec` | API authentication token |

**Lua script layer** — set per-request by the validation script:

| Header | Source | Purpose |
|--------|--------|---------|
| `x-rh-insights-certauth-secret` | K8s secret `backoffice-proxy-config` | Proxy proof — BOP validates this matches its `PROXY_PROOF` config |

The client ID and API token are general BOP credentials shared across all requests, so they're configured at the HTTP client level. The certauth secret is specific to the cert auth flow and is read via `config.get("bop_certauth_secret")`, resolved from an env var at startup using the `{env: "VAR"}` config syntax.

BOP also validates the certificate issuer against its `TRUSTED_ISSUERS` list (semicolon-separated). The default trusted issuers include multiple Red Hat Candlepin Authority variants with both `Email` and `emailAddress` formats.

The `x-rh-insights-env` header controls which downstream RHSM environment BOP calls (e.g., `stage` vs `prod`).

### Caching

Successful validations are cached to avoid repeated BOP calls. Caching is split into two layers:

1. **Key definition (Lua)**: `validate_cache_key(input)` returns a table with only `credential.type`, `credential.subject`, and `credential.issuer`. The Go caching layer serializes this to JSON and uses it as the cache key.

2. **Storage (Go)**: Configured via the `caching:` YAML block on the validator:
   - `in_memory` — local map
   - `distributed` — groupcache for cluster-wide caching
   - `none` — caching disabled

### HTTP Client

The Lua script makes HTTP calls via a named HTTP client (`backoffice-proxy`) resolved from the `http_clients` registry. The BOP connection does not require mTLS — only TLS with proper CA verification.

The `ca_cert` option on the HTTP client appends a custom CA to the system cert pool, enabling TLS verification against internal services signed by the Red Hat IT CA.

The HTTP client uses `http_auth.type: headers` to inject `x-rh-clientid` and `x-rh-apitoken` at the transport layer via `HeadersTransport`. Header values can be static strings or resolved from environment variables at startup using `{env: "VAR"}` syntax.

### CEL Integration

Cert auth is detected in CEL mapper expressions by checking the issuer set by the Lua validator:

```cel
has(subject.issuer) && subject.issuer.contains("backoffice-proxy")
```

The `issuer` is set to the `bop_url` config value by the Lua script on successful validation. The CEL script maps cert auth results into a `System` type identity envelope:

```json
{
  "identity": {
    "auth_type": "cert-auth",
    "account_number": "...",
    "org_id": "...",
    "type": "System",
    "system": {
      "cn": "...",
      "cert_type": "..."
    },
    "internal": {
      "org_id": "...",
      "cross_access": false,
      "auth_time": ...
    }
  },
  "entitlements": {}
}
```

## Configuration

```yaml
http_clients:
  - name: backoffice-proxy
    timeout: "30s"
    ca_cert: "/etc/parsec/secrets/it-ca-bundle/it-ca-bundle.crt"
    http_auth:
      type: headers
      headers:
        x-rh-clientid:
          env: PARSEC_BOP_CLIENT_ID
        x-rh-apitoken:
          env: PARSEC_BOP_TOKEN

credential_sources:
  - name: cert-auth
    type: forwarded_client_cert_auth
    subject_header: "x-rh-certauth-cn"
    issuer_header: "x-rh-certauth-issuer"
  - name: authorization-bearer
    type: authorization_bearer_opaque

trust_store:
  type: stub_store
  validators:
    - name: cert-auth
      type: lua_validator
      script_file: ./configs/scripts/forwarded_client_cert_auth.lua
      credential_types: ["forwarded_client_cert"]
      http_client: backoffice-proxy
      config:
        bop_url: "https://backoffice-proxy.apps.ext.spoke.preprod.us-west-2.aws.paas.redhat.com"
        bop_env: "stage"
        trust_domain: "cert.redhat.com"
        bop_certauth_secret:
          env: "PARSEC_BOP_CERTAUTH_SECRET"
      caching:
        type: in_memory
        ttl: "5m"
```

### Credential Source Config Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique identifier for this credential source |
| `type` | Yes | Must be `forwarded_client_cert_auth` |
| `subject_header` | Yes | Header name containing the certificate subject (e.g., `x-rh-certauth-cn`) |
| `issuer_header` | Yes | Header name containing the certificate issuer (e.g., `x-rh-certauth-issuer`) |

### Validator Config Fields

| Field | Required | Description |
|-------|----------|-------------|
| `script_file` | Yes | Path to the Lua script |
| `credential_types` | Yes | Must include `"forwarded_client_cert"` |
| `http_client` | No | Name of a client from `http_clients` registry |
| `config.bop_url` | Yes | Common HTTPS base URL for BOP endpoints |
| `config.bop_env` | No | Environment for `x-rh-insights-env` header (defaults to `"stage"`) |
| `config.trust_domain` | Yes | Trust domain assigned to validated results |
| `config.bop_certauth_secret` | Yes | Proxy proof secret (supports `{env: "VAR"}` syntax for env var resolution) |
| `caching.type` | No | `in_memory`, `distributed`, or `none` |
| `caching.ttl` | No | Cache duration for successful validations |

### Deployment

BOP secrets are injected as environment variables from two K8s secrets:

| Env Var | K8s Secret | Key | Purpose |
|---------|------------|-----|---------|
| `PARSEC_BOP_CERTAUTH_SECRET` | `backoffice-proxy-config` | `certauth-secret` | Proxy proof for BOP cert auth |
| `PARSEC_BOP_CLIENT_ID` | `parsec` | `client_id` | BOP client identifier |
| `PARSEC_BOP_TOKEN` | `parsec` | `token` | BOP API token |

The Red Hat IT CA bundle is mounted from a K8s secret (`it-ca-bundle`) at `/etc/parsec/secrets/it-ca-bundle/`. The HTTP client's `ca_cert` option appends this CA to the system cert pool for TLS verification against BOP.

All secret references use `optional: true` to allow the pod to start without cert auth configured.

## Security Considerations

- **Credential removal**: The `x-rh-certauth-cn` and `x-rh-certauth-issuer` headers are stripped from requests forwarded to backends.
- **Proxy proof**: BOP validates `x-rh-insights-certauth-secret` matches its `PROXY_PROOF` config, ensuring only authorized proxies can trigger cert auth.
- **Issuer validation**: BOP checks the certificate issuer against its `TRUSTED_ISSUERS` list before resolving the CN.
- **Cache key derivation**: Cache keys include credential type, subject, and issuer. The caching wrappers handle key hashing.
- **Lua sandbox**: The validation script runs in a restricted Lua environment — only `config`, `json`, `http`, and `os` modules are available.
- **Secret management**: BOP credentials are resolved from environment variables at startup. The `{env: "VAR"}` syntax in config values and `http_auth.headers` entries resolves env vars eagerly — if a required env var is empty or unset, startup fails immediately.

## Testing

Key test scenarios:
- Successful validation with claim extraction (simple CN, compound subject)
- Missing subject header (partial extraction → error)
- Missing issuer header (partial extraction → error)
- No cert headers present (nil extraction, falls through to next source)
- BOP returns non-200 (validation rejected)
- CN parsing from various subject formats
- Cache hit / cache miss
- Credential JSON roundtrip serialization for `ForwardedClientCertCredential`
- CEL mapper produces correct System type identity envelope
