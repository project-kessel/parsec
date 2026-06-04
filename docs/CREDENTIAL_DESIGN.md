# Credential Design

## Overview

Credentials in parsec are strongly typed values that encapsulate only the material needed for validation. The extraction layer uses a `CredentialSource` interface to parse credentials from a transport-neutral `TransportContext`, tracking which headers were consumed. Source provenance is carried on `trust.Result` so both actor and subject results know how their credential was presented.

## Extraction Architecture

Three extraction paths share one `CredentialSource` interface:

| Path | Transport | TransportContext built by |
|------|-----------|--------------------------|
| ext_authz **subject** | Envoy CheckRequest HTTP attrs | `TransportContextFromCheckRequest` |
| ext_authz **actor** | gRPC peer + metadata | `TransportContextFromGRPC` |
| exchange **caller** | gRPC peer + metadata | `TransportContextFromGRPC` |

Exchange body tokens (`subject_token`, `actor_token`) are a **protocol-level concern** above transport extraction. They are wrapped directly as `BearerCredential` without going through `CredentialSource`.

### TransportContext

`TransportContext` is a normalized struct holding headers, path, and TLS peer info. Callers build one from their specific transport before credential extraction:

```go
type TransportContext struct {
    Headers map[string]string  // normalized lowercase keys
    Path    string             // request path; empty for gRPC-native calls
    TLSPeer *TLSPeerInfo      // mTLS client cert info; nil when absent
}
```

Normalization constructors:
- `TransportContextFromCheckRequest(req)` -- Envoy ext_authz
- `TransportContextFromGRPC(ctx)` -- gRPC metadata + peer TLS

### CredentialSource interface

```go
type CredentialSource interface {
    Extract(tc TransportContext) (*CredentialExtraction, error)
}
```

Built-in implementations: `BearerCredentialSource`, `CookieCredentialSource`, `QueryCredentialSource`.

### Source provenance on Result

After extraction and validation, callers stamp `result.CredentialSource = ext.SourceName`. This makes the credential's presentation protocol available in CEL as `subject.credential_source` and `actor.credential_source`.

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

**Benefits:**
- Type safety at compile time
- Type-specific methods available (e.g., `JWTCredential` could have `GetClaims()`)
- Clear documentation of what data each credential type needs
- No `map[string]string` soup
- IssuerIdentity field on JWT/OIDC/mTLS credentials enables multi-trust-domain support
- Bearer tokens use a default issuer determined by the validator store

### 2. Issuer Identification for Validator Store

Most credentials contain issuer information that the validator store uses to select the appropriate validator. Bearer tokens are an exception - the store determines their issuer based on configuration:

```go
cred := &JWTCredential{
    Token:          token,
    IssuerIdentity: "https://accounts.google.com",
}

result, err := store.Validate(ctx, cred)
```

**How issuers are determined:**
- **JWT/OIDC**: Parsed from the `iss` claim in the token during extraction
- **Bearer (opaque)**: Uses default "bearer" issuer; store configured with appropriate validator
- **mTLS**: From the certificate authority identifier
- **API Key**: From configuration mapping key to issuer

### 3. Separation of Concerns

Credentials contain **only validation data**, not transport metadata:

- Credentials do NOT know about HTTP headers
- Credentials do NOT know how they were extracted
- Credentials ARE just the material needed for validation

The **extraction layer** handles transport concerns via `CredentialSource.Extract(TransportContext)` and returns a `CredentialExtraction` containing the credential, consumed headers, and sanitization info.

### 4. Security Boundary in ext_authz

The extraction layer tracks which headers were used, and ext_authz removes them from requests forwarded to backends:

```go
// 1. Normalize transport to TransportContext
tc, err := TransportContextFromCheckRequest(req)

// 2. Extract credential via CredentialSource chain
ext, err := extractCredentialFromSources(tc, sources)

// 3. Validate and stamp provenance
result, err := store.Validate(ctx, ext.Credential)
result.CredentialSource = ext.SourceName

// 4. Remove external credential headers - security boundary
return &CheckResponse{
    OkResponse: &OkHttpResponse{
        HeadersToRemove:         ext.Headers,
        QueryParametersToRemove: ext.QueryParamsToRemove,
    },
}
```

**Why this matters:**
- External credentials (OAuth tokens, API keys, etc.) stay at the perimeter
- Backend services only see transaction tokens
- Prevents credential leakage to untrusted services
- Clear trust boundary enforcement

## Type Assertions in Validators

Validators can use type assertions to access type-specific fields:

```go
type JWTValidator struct {
    jwksClient *jwks.Client
}

func (v *JWTValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
    jwtCred, ok := credential.(*JWTCredential)
    if !ok {
        return nil, fmt.Errorf("expected JWTCredential, got %T", credential)
    }
    
    key, err := v.jwksClient.GetKey(jwtCred.KeyID)
    if err != nil {
        return nil, err
    }
    
    return validateJWT(jwtCred.Token, key, jwtCred.Algorithm)
}
```

## Future Enhancements

### mTLS CredentialSource

`TransportContext.TLSPeer` is ready for a future `MTLSCredentialSource` that reads client certificates from the peer info.

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
| **Transport Abstraction** | `TransportContext` struct normalizes headers/path/TLS from any transport |
| **Extraction Interface** | `CredentialSource.Extract(TransportContext)` -- transport-neutral |
| **Source Provenance** | `trust.Result.CredentialSource` carries how the credential was presented |
| **Per-Role Provenance** | Both actor and subject results carry their own credential source |
| **Issuer Identification** | Each credential identifies its issuer for trust store lookup |
| **Security Boundary** | ext_authz removes headers used for external credentials |
| **Exchange Body Tokens** | Protocol-level concern, separate from `CredentialSource` |
| **Extensibility** | Easy to add new credential types or sources without changing contracts |

This design cleanly separates:
1. **Normalization** (transport -> TransportContext)
2. **Extraction** (TransportContext -> credential via CredentialSource)
3. **Validation** (credential -> claims via trust.Store)
4. **Provenance** (CredentialSource name stamped on trust.Result)
5. **Security** (removing external credentials at boundary)
