# Credential Design

## Overview

Credentials in parsec are strongly typed values that encapsulate only the material needed for validation. The extraction layer uses a `CredentialSource` interface to parse credentials from a `CredentialContext`, tracking which headers were consumed. Source provenance is carried on `trust.Result` so both actor and subject results know how their credential was presented.

## Extraction Architecture

Three extraction paths share one `CredentialSource` interface:

| Path | Transport | CredentialContext built by |
|------|-----------|--------------------------|
| ext_authz **subject** | Envoy CheckRequest HTTP attrs | `CredentialContextFromCheckRequest` |
| ext_authz **actor** | gRPC peer + metadata | `CredentialContextFromGRPC` |
| exchange **caller** | gRPC peer + metadata | `CredentialContextFromGRPC` |

Exchange body tokens (`subject_token`, `actor_token`) are a **protocol-level concern** above credential extraction. They are wrapped directly as `BearerCredential` without going through `CredentialSource`. See "Exchange Subject Token Mapping" below for future direction.

### CredentialContext

`CredentialContext` holds the normalized context needed for credential extraction -- headers, path, and TLS peer info. Callers build one from their specific transport before calling `CredentialSource.Extract`:

```go
type CredentialContext struct {
    Headers map[string]string  // normalized lowercase keys
    Path    string             // request path; empty for gRPC-native calls
    TLSPeer *TLSPeerInfo      // mTLS client cert info; nil when absent
}
```

Normalization constructors:
- `CredentialContextFromCheckRequest(req)` -- Envoy ext_authz
- `CredentialContextFromGRPC(ctx)` -- gRPC metadata + peer TLS

### CredentialSource interface

```go
type CredentialSource interface {
    Extract(cc CredentialContext) (*CredentialExtraction, error)
}
```

Built-in implementations: `BearerCredentialSource`, `CookieCredentialSource`, `QueryCredentialSource`.

### Source provenance on Result

The `validateCredential` helper encapsulates validation and source stamping:

```go
result, err := validateCredential(ctx, store, ext)
// result.CredentialSource is set to ext.SourceName
```

This makes the credential's presentation protocol available in CEL as `subject.credential_source` and `actor.credential_source`.

### Configuration

Credential sources are configured at the top level and shared by both the ext_authz and token exchange servers:

```yaml
credential_sources:
  - name: authorization-bearer
    type: bearer
  - name: cs-jwt-cookie
    type: cookie
    cookie_name: cs_jwt
  - name: query-token
    type: query
    parameter_name: token
```

## Design Principles

### 1. Strongly Typed Credentials

Each credential type has its own struct with type-specific fields:

```go
type Credential interface {
    Type() CredentialType
}

type BearerCredential struct {
    Token string  // The bearer token; issuer determined by validator store
}

type JWTCredential struct {
    Token          string
    Algorithm      string  // Parsed from JWT header
    KeyID          string  // Parsed from JWT header
    IssuerIdentity string  // Parsed from JWT "iss" claim (used by trust store)
}

type MTLSCredential struct {
    Certificate         []byte
    Chain               [][]byte
    PeerCertificateHash string
    IssuerIdentity      string  // CA identifier (used by trust store)
}
```

### 2. Issuer Identification for Validator Store

Most credentials contain issuer information that the validator store uses to select the appropriate validator. Bearer tokens are an exception -- the store determines their issuer based on configuration.

**How issuers are determined:**
- **JWT/OIDC**: Parsed from the `iss` claim in the token during extraction
- **Bearer (opaque)**: Uses default "bearer" issuer; store configured with appropriate validator
- **mTLS**: From the certificate authority identifier

### 3. Separation of Concerns

Credentials contain **only validation data**, not transport metadata:

- Credentials do NOT know about HTTP headers
- Credentials do NOT know how they were extracted
- Credentials ARE just the material needed for validation

The **extraction layer** handles transport concerns via `CredentialSource.Extract(CredentialContext)` and returns a `CredentialExtraction` containing the credential, consumed headers, and sanitization info.

### 4. Security Boundary in ext_authz

The extraction layer tracks which headers were used, and ext_authz removes them from requests forwarded to backends:

```go
// 1. Build CredentialContext from transport
cc, err := CredentialContextFromCheckRequest(req)

// 2. Extract credential via CredentialSource chain
ext, err := extractCredentialFromSources(cc, sources)

// 3. Validate with source provenance
result, err := validateCredential(ctx, store, ext)

// 4. Remove external credential headers -- security boundary
return &CheckResponse{
    OkResponse: &OkHttpResponse{
        HeadersToRemove:         ext.Headers,
        QueryParametersToRemove: ext.QueryParamsToRemove,
    },
}
```

## Future Enhancements

### mTLS CredentialSource

`CredentialContext.TLSPeer` is ready for a future `MTLSCredentialSource` that reads client certificates from the peer info. Currently, mTLS actor extraction is handled directly in `extractActorCredential` as a priority check before the source chain.

### Exchange Subject Token Mapping

The exchange endpoint currently wraps `subject_token` as a `BearerCredential` regardless of `subject_token_type`. A future enhancement should map RFC 8693 token types (e.g., `urn:ietf:params:oauth:token-type:jwt`) to specific credential types. This mapping likely belongs on the exchange server configuration or a top-level token type registry, not on `CredentialSource` (since exchange body tokens have exactly one extraction path by definition).

### Composite Credentials

For multi-factor auth:

```go
type CompositeCredential struct {
    Primary   Credential  // e.g., JWT
    Secondary Credential  // e.g., API key
}
```

### Proof-of-Possession

For DPoP or similar:

```go
type DPoPCredential struct {
    AccessToken string
    ProofJWT    string
    Method      string
    URI         string
}
```

## Summary

| Aspect | Approach |
|--------|----------|
| **Credential Type** | Strongly typed structs implementing `Credential` interface |
| **Credential Content** | Only validation material, no transport metadata |
| **Credential Context** | `CredentialContext` struct normalizes headers/path/TLS from any transport |
| **Extraction Interface** | `CredentialSource.Extract(CredentialContext)` -- transport-neutral |
| **Source Provenance** | `validateCredential` stamps `trust.Result.CredentialSource` |
| **Per-Role Provenance** | Both actor and subject results carry their own credential source |
| **Configuration** | Top-level `credential_sources` shared by authz and exchange |
| **Issuer Identification** | Each credential identifies its issuer for trust store lookup |
| **Security Boundary** | ext_authz removes headers used for external credentials |
| **Exchange Body Tokens** | Protocol-level concern, separate from `CredentialSource` |
| **Extensibility** | Easy to add new credential types or sources without changing contracts |

This design cleanly separates:
1. **Normalization** (transport -> CredentialContext)
2. **Extraction** (CredentialContext -> credential via CredentialSource)
3. **Validation** (credential -> claims via validateCredential)
4. **Provenance** (CredentialSource name stamped on trust.Result)
5. **Security** (removing external credentials at boundary)
