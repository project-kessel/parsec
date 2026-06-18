# Credential Design

## Overview

Credentials in parsec are strongly typed values that encapsulate only the material needed for validation. The extraction layer uses a `CredentialSource` interface to parse credentials from a `CredentialContext`, tracking which headers were consumed. Policy decisions are based on the verified claims of the credential itself, not the transport mechanism used to present it.

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
    TLSPeer *TLSPeerInfo      // mTLS client cert info; nil when absent
}
```

Normalization constructors:
- `CredentialContextFromCheckRequest(req)` -- Envoy ext_authz
- `CredentialContextFromGRPC(ctx)` -- gRPC metadata + peer TLS

### CredentialSource interface

```go
type CredentialSource interface {
    Extract(ctx context.Context, cc CredentialContext) (*CredentialExtraction, error)
}
```

Built-in implementations: `BearerCredentialSource`, `CookieCredentialSource`.

### Configuration

Credential sources are configured globally and shared by all extraction paths (ext_authz subject, ext_authz actor, exchange caller). The trust store determines which credentials are usable; credential sources only handle extraction.

```yaml
credential_sources:
  - name: authorization-bearer
    type: authorization_bearer_opaque
  - name: cs-jwt-cookie
    type: cookie_bearer_opaque
    cookie_name: cs_jwt
```

Sources are tried in order; the first match wins. A source returns `nil` (no match) when the expected header or credential is absent.

### Configuration Sharing

All three extraction paths share the same `credential_sources` list:

| Path | Transport | Typical Sources |
|------|-----------|-----------------|
| ext_authz **subject** | Envoy HTTP headers | bearer, cookie |
| ext_authz **actor** | gRPC metadata | bearer |
| exchange **caller** | gRPC metadata | bearer |

This works because each `CredentialSource` returns `nil` when the expected header is missing. When no `credential_sources` are configured, `DefaultCredentialSources()` is used (bearer-only).

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
- **JWT/OIDC**: Parsed from the `iss` claim during validation (extracted as `BearerCredential`, JWT parsing is validator-level)
- **Bearer (opaque)**: Uses default "bearer" issuer; store configured with appropriate validator
- **mTLS**: From the certificate authority identifier

### 3. Separation of Concerns

Credentials contain **only validation data**, not transport metadata:

- Credentials do NOT know about HTTP headers
- Credentials do NOT know how they were extracted
- Credentials ARE just the material needed for validation

The **extraction layer** handles transport concerns via `CredentialSource.Extract(CredentialContext)` and returns a `CredentialExtraction` containing the credential, consumed headers, and sanitization info.

### 4. Claims-Based Policy

Policy decisions (claim mappers, validator filtering, etc.) operate on the verified claims of the credential, not how it was presented. The transport mechanism (bearer header, cookie, etc.) is a presentation concern handled by the extraction layer. Once a credential is validated, the resulting `trust.Result` carries only identity and claims.

### 5. Security Boundary in ext_authz

The extraction layer tracks which headers were used, and ext_authz removes them from requests forwarded to backends:

```go
// 1. Build CredentialContext from transport
cc, err := CredentialContextFromCheckRequest(req)

// 2. Extract credential via CredentialSources chain
ext, err := sources.Extract(ctx, cc)

// 3. Validate
result, err := validateCredential(ctx, store, ext)

// 4. Remove external credential headers -- security boundary
return &CheckResponse{
    OkResponse: &OkHttpResponse{
        HeadersToRemove: ext.RemoveHeaders,
    },
}
```

## Examples

### Example 1: Bearer Token

```go
// 1. Normalize transport to CredentialContext
cc, err := CredentialContextFromCheckRequest(req)

// 2. Extract via configured source chain
ext, err := subjectSources.Extract(ctx, cc)
// ext.Credential is *trust.BearerCredential{Token: "..."}
// ext.RemoveHeaders is []string{"authorization"}

// 3. Validate
result, err := validateCredential(ctx, store, ext)

// 4. Security: authorization header removed from forwarded request
```

### Example 2: Cookie

The cookie source extracts a JWT from a named cookie and sanitizes the `Cookie` header so other cookies remain intact:

```go
cc, err := CredentialContextFromCheckRequest(req)
ext, err := subjectSources.Extract(ctx, cc)
// ext.Credential is *trust.BearerCredential{Token: "..."}
// ext.SetHeaders["cookie"] is "session=abc" (cs_jwt removed)

result, err := validateCredential(ctx, store, ext)
```

### Example 3: mTLS Actor

mTLS actor extraction reads TLS peer info from `CredentialContext` before falling through to the bearer source chain. A future `MTLSCredentialSource` will replace the inline check in `extractActorCredential`:

```go
cc := CredentialContextFromGRPC(ctx)
// cc.TLSPeer.Certificates populated from gRPC TLS state

ext, err := extractActorCredential(ctx, actorSources)
// ext.Credential is *trust.MTLSCredential when client cert is present

result, err := validateCredential(ctx, store, ext)
// No headers to remove (TLS layer)
```

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

Bearer tokens extracted by `BearerCredentialSource` or `CookieCredentialSource` arrive as `*BearerCredential`. The trust store selects a validator based on configuration; JWT validators parse the token internally.

## Testing

Type safety makes testing straightforward -- construct credentials directly without HTTP plumbing:

```go
func TestJWTValidation(t *testing.T) {
    cred := &JWTCredential{
        Token:     "eyJhbGc...",
        Algorithm: "RS256",
        KeyID:     "key-1",
    }

    result, err := validator.Validate(ctx, cred)
    // ... assertions
}
```

Credential sources can be tested with a plain `CredentialContext`:

```go
ext, err := (&BearerCredentialSource{SourceName: "bearer"}).Extract(CredentialContext{
    Headers: map[string]string{"authorization": "Bearer test-token"},
})
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
| **Policy Basis** | Verified claims from `trust.Result`, not transport/presentation details |
| **Configuration** | Global `credential_sources` shared by all extraction paths; trust store determines usability |
| **Issuer Identification** | Some credential types carry issuer info for trust store routing; bearer tokens rely on store configuration |
| **Security Boundary** | ext_authz removes headers used for external credentials |
| **Exchange Body Tokens** | Protocol-level concern, separate from `CredentialSource` |
| **Extensibility** | Easy to add new credential types or sources without changing contracts |

This design cleanly separates:
1. **Normalization** (transport -> CredentialContext)
2. **Extraction** (CredentialContext -> credential via CredentialSource)
3. **Validation** (credential -> claims via trust store)
4. **Security** (removing external credentials at boundary)
