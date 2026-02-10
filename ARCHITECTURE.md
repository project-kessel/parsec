# parsec Architecture

## Overview

parsec is a gRPC-first service that implements:
1. **Envoy ext_authz** (gRPC) - for authorization at the perimeter
2. **OAuth 2.0 Token Exchange** (HTTP via gRPC transcoding) - RFC 8693 compliant

Both services issue transaction tokens following the [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) specification.

### Key Features

- **Dual identity support**: Subject credentials (end users) and actor credentials (services/machines)
- **Pluggable validation**: JWT (JWKS), JSON (unsigned structured credentials), OAuth2 introspection
- **Dynamic claim enrichment**: Lua-scriptable data sources with HTTP/JSON services
- **CEL-based claim mapping**: Flexible policy language for token claims
- **Caching**: In-memory and distributed caching for data sources
- **Validator filtering**: Actor-based authorization for credential validation

## Protocol Architecture

### Unified Stack

```
                    ┌─────────────────┐
                    │   parsec        │
                    │                 │
  gRPC clients ────▶│  gRPC Server    │◀──── Envoy (ext_authz)
                    │    :9090        │
                    │                 │
                    │  ┌───────────┐  │
  HTTP clients ────▶│  │  grpc-    │  │
                    │  │  gateway  │  │
                    │  │   :8080   │  │
                    │  └─────┬─────┘  │
                    │        │        │
                    │        ▼        │
                    │  gRPC Services  │
                    └─────────────────┘
```

**Key Design Decision**: Single gRPC service with HTTP transcoding via grpc-gateway
- No separate HTTP server implementation
- Consistent type definitions across protocols
- Single code path for business logic

## Services

### 1. Authorization Service (ext_authz)

**Interface**: `envoy.service.auth.v3.Authorization`

Implements Envoy's external authorization protocol:
- Receives requests from Envoy with external credentials
- Validates credentials against trust store
- Issues transaction token
- Returns authorization decision with token in custom header

### 2. Token Exchange Service

**Interface**: `parsec.v1.TokenExchange`

Implements RFC 8693 OAuth 2.0 Token Exchange:
- gRPC service definition with HTTP annotations
- Exposed at `POST /v1/token`
- Accepts external tokens, returns tokens of the request type (e.g. transaction token)
- Fully RFC 8693 compliant message structure

**RFC 8693 Compliance:**
The token exchange endpoint supports `application/x-www-form-urlencoded` as required by [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html):
- Custom marshaler registered with grpc-gateway
- Automatically decodes form-encoded requests
- Also accepts JSON for gRPC-style clients
- Responses are JSON (standard OAuth 2.0 token response)

Example RFC 8693 request:
```bash
curl -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=eyJhbGc..." \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=https://api.example.com"
```

## Project Structure

```
parsec/
├── api/
│   ├── proto/parsec/v1/          # Proto definitions
│   │   └── token_exchange.proto  # Token exchange with HTTP annotations
│   └── gen/                      # Generated code (gitignored)
│
├── cmd/parsec/
│   └── main.go                   # Entry point
│
├── internal/
│   ├── server/
│   │   ├── server.go            # gRPC + HTTP server setup
│   │   ├── authz.go             # ext_authz implementation
│   │   ├── exchange.go          # Token exchange implementation
│   │   └── form_marshaler.go    # RFC 8693 form encoding support
│   │
│   ├── trust/                   # Trust and credential validation
│   │   ├── validator.go         # Validator interface and credential types
│   │   ├── jwt_validator.go     # JWT validation with JWKS
│   │   ├── json_validator.go    # JSON credential validation
│   │   ├── store.go             # Trust store interface
│   │   ├── filtered_store.go    # Actor-based store filtering
│   │   ├── cel_validator_filter.go  # CEL-based validator filtering
│   │   └── stub.go              # Stub implementations for testing
│   │
│   ├── service/                 # Token issuance orchestration
│   │   ├── service.go           # TokenService orchestrates issuance
│   │   ├── issuer.go            # Issuer interface and TokenContext
│   │   ├── registry.go          # Registry for managing issuers
│   │   ├── mapper.go            # ClaimMapper interface
│   │   ├── datasource.go        # DataSource interface for enrichment
│   │   ├── stub_mapper.go       # Stub mapper for testing
│   │   └── types.go             # TokenType definitions
│   │
│   ├── issuer/                  # Token issuer implementations
│   │   ├── unsigned_issuer.go   # Unsigned token issuer
│   │   └── stub.go              # Stub issuer for testing
│   │
│   ├── mapper/                  # Claim mapper implementations
│   │   └── cel_mapper.go        # CEL-based claim mapping
│   │
│   ├── datasource/              # Data source implementations
│   │   ├── lua_datasource.go    # Lua-scriptable data sources
│   │   ├── in_memory_caching_datasource.go
│   │   ├── distributed_caching_datasource.go
│   │   ├── examples/            # Example Lua scripts
│   │   └── LUA_DATASOURCE.md    # Lua data source documentation
│   │
│   ├── lua/                     # Lua runtime services
│   │   ├── http.go              # HTTP client for Lua
│   │   ├── json.go              # JSON encoding/decoding
│   │   └── config.go            # Configuration access
│   │
│   ├── cel/                     # CEL (Common Expression Language) support
│   │   ├── mapper_input.go      # CEL library for mapper input
│   │   └── README.md            # CEL integration documentation
│   │
│   ├── claims/                  # Claims handling
│   │   ├── claims.go            # Claims type with helper methods
│   │   └── filter.go            # Claims filtering interfaces
│   │
│   ├── request/                 # Request attributes
│   │   └── request.go           # RequestAttributes type
│   │
│   ├── keymanager/              # Key management (TODO)
│   └── config/                  # Configuration loading (TODO)
│
├── docs/
│   └── CREDENTIAL_DESIGN.md     # Credential extraction and validation design
│
└── configs/                     # Configuration files (TODO)
```

## Building and Running

```bash
# Generate proto code
make proto

# Build
make build

# Run
./bin/parsec
```

Server will start on:
- gRPC: `localhost:9090` (ext_authz, token exchange)
- HTTP: `localhost:8080` (token exchange via transcoding)

## Core Concepts

### Token Issuance Flow

parsec uses a layered architecture for token issuance:

```
1. Credential Extraction
   └─> Strongly-typed credentials (Bearer, JWT, JSON, mTLS, etc.)

2. Validation (trust.Validator → trust.Store)
   └─> Validated identity (trust.Result with claims)
   └─> Trust store determines appropriate validator based on credential type
   └─> Optional actor-based filtering (ForActor method)

3. Data Enrichment (service.DataSource)
   └─> Fetch additional context from external sources
   └─> Lua-scriptable with HTTP/JSON services
   └─> In-memory and distributed caching
   └─> Lazy evaluation during claim mapping

4. Claim Mapping (service.ClaimMapper)
   └─> Build transaction context (tctx) and request context (req_ctx)
   └─> CEL expressions for flexible policy logic
   └─> Access to subject, actor, request, and data sources
   └─> Multiple mappers compose to build final claims

5. Token Issuance (service.Issuer)
   └─> Sign and mint transaction tokens
   └─> JWT with draft-ietf-oauth-transaction-tokens claims
   └─> Support for unsigned tokens (development/testing)
```

### Dual Identity Model

parsec supports two types of identity:

1. **Subject**: The end user or principal being authorized
   - Extracted from standard OAuth/OIDC tokens
   - Goes into the `sub` claim of transaction tokens
   
2. **Actor**: The service or machine making the request
   - Extracted from mTLS certificates or service tokens
   - Goes into transaction context claims
   - Used for authorization decisions (ForActor filtering)

This enables patterns like "service X acting on behalf of user Y" which is critical for microservice architectures.

### Data Sources

Data sources enable token enrichment by fetching data from external systems:

- **Lua-scriptable**: Write data sources in Lua without recompiling
- **HTTP/JSON/Config services**: Built-in services for common operations
- **Caching**: Automatic in-memory and distributed caching
- **Examples**: User profiles, permissions, regional data, multi-source aggregation

See `internal/datasource/LUA_DATASOURCE.md` for comprehensive documentation.

### Security Boundary

parsec enforces a security boundary at the perimeter:

1. External credentials (OAuth tokens, API keys) are extracted at ext_authz
2. Credentials are validated and transaction tokens are issued
3. **External credential headers are removed** from requests
4. Only transaction tokens reach backend services

This prevents credential leakage and establishes clear trust boundaries.

## Component Interfaces

parsec is built around well-defined interfaces that enable testability, flexibility, and extensibility.

### trust.Validator

**Purpose**: Validates external credentials and returns claims about the authenticated subject.

```go
type Validator interface {
    // Validate validates a credential and returns the validation result
    Validate(ctx context.Context, credential Credential) (*Result, error)
    
    // CredentialTypes returns the set of credential types this validator can handle
    CredentialTypes() []CredentialType
}
```

**Key Types**:
```go
type Result struct {
    Subject     string           // Unique identifier of the authenticated subject
    Issuer      string           // Issuer of the credential (e.g., IdP URL)
    TrustDomain string           // Trust domain the credential belongs to
    Claims      claims.Claims    // Additional claims from the credential
    ExpiresAt   time.Time        // When the credential expires
    IssuedAt    time.Time        // When the credential was issued
    Audience    []string         // Intended audience
    Scope       string           // OAuth2 scope
}
```

**Implementations**:
- `JWTValidator` - Validates JWT tokens with JWKS (production-ready)
- `JSONValidator` - Validates unsigned JSON credentials with structured Result format
- `StubValidator` - For testing, accepts any non-empty token

### trust.Store

**Purpose**: Manages trust domains and provides validators for credentials.

```go
type Store interface {
    // Validate validates a credential, determining the appropriate validator
    // based on the credential type and issuer
    Validate(ctx context.Context, credential Credential) (*Result, error)
    
    // ForActor returns a filtered Store that only includes validators
    // the given actor is allowed to use
    ForActor(ctx context.Context, actor *Result, 
             requestAttrs *request.RequestAttributes) (Store, error)
}
```

**Key Features**:
- Automatically routes credentials to appropriate validators
- Supports multiple validators per credential type
- Actor-based filtering for authorization
- Credential type hierarchy (Bearer tokens can be JWTs)

**Implementations**:
- `StubStore` - In-memory store for testing
- `FilteredStore` - Wraps another store with validator filtering

### service.Issuer

**Purpose**: Issues transaction tokens based on validated credentials.

```go
type Issuer interface {
    // Issue creates a signed token from the provided context
    Issue(ctx context.Context, tokenCtx *TokenContext) (*Token, error)
    
    // PublicKeys returns public keys for verifying tokens
    PublicKeys(ctx context.Context) ([]PublicKey, error)
}

type TokenContext struct {
    Subject            *trust.Result   // Subject identity
    Actor              *trust.Result   // Actor identity
    TransactionContext claims.Claims   // Goes into "tctx" claim
    RequestContext     claims.Claims   // Goes into "req_ctx" claim
    Audience           string          // Trust domain (aud claim)
    Scope              string          // OAuth2 scope
}
```

**Implementations** (in `internal/issuer/`):
- `issuer.StubIssuer` - Generates simple token strings for testing
- `issuer.UnsignedIssuer` - Base64-encoded JSON tokens (development/testing)
- TODO: `issuer.JWTIssuer` - Real JWT implementation with signing

### service.DataSource

**Purpose**: Provides additional data for token context building.

```go
type DataSource interface {
    // Name identifies this data source
    Name() string
    
    // Fetch retrieves data based on the input
    Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error)
}

type DataSourceInput struct {
    Subject           *trust.Result
    Actor             *trust.Result
    RequestAttributes *request.RequestAttributes
}
```

**Optional Interface for Caching**:
```go
type Cacheable interface {
    // CacheKey returns a masked copy of input with only fields that affect result
    CacheKey(input *DataSourceInput) DataSourceInput
    
    // CacheTTL returns the time-to-live for cached entries
    CacheTTL() time.Duration
}
```

**Implementations** (in `internal/datasource/`):
- `datasource.LuaDataSource` - Scriptable data sources with HTTP/JSON services
- `datasource.InMemoryCachingDataSource` - Wraps data source with local cache
- `datasource.DistributedCachingDataSource` - Wraps data source with distributed cache (groupcache)

### service.ClaimMapper

**Purpose**: Transforms inputs into claims for the token (policy logic).

```go
type ClaimMapper interface {
    // Map produces claims based on the input
    Map(ctx context.Context, input *MapperInput) (claims.Claims, error)
}

type MapperInput struct {
    Subject            *trust.Result
    Actor              *trust.Result
    RequestAttributes  *request.RequestAttributes
    DataSourceRegistry *DataSourceRegistry  // For lazy data fetching
    DataSourceInput    *DataSourceInput
}
```

**Implementations** (in `internal/mapper/` and `internal/service/`):
- `mapper.CELMapper` - Uses CEL (Common Expression Language) expressions
- `service.PassthroughSubjectMapper` - Passes through subject claims
- `service.RequestAttributesMapper` - Maps request attributes to claims
- `service.StubMapper` - Returns fixed claims for testing

**CEL Example**:
```javascript
{
  "user": subject.subject,
  "roles": datasource("user_roles").roles,
  "region": datasource("geo").region,
  "path": request.path
}
```

### service.TokenService

**Purpose**: Orchestrates the complete token issuance process.

```go
type TokenService struct {
    trustDomain    string
    dataSources    *DataSourceRegistry
    claimMappers   *ClaimMapperRegistry
    issuerRegistry Registry
}

func (ts *TokenService) IssueTokens(ctx context.Context, 
                                     req *IssueRequest) (map[TokenType]*Token, error)
```

**Orchestration Flow**:
1. Build data source input from request
2. Build mapper input with lazy data source registry
3. Apply transaction context mappers
4. Apply request context mappers
5. Build token context with composed claims
6. Issue tokens for each requested type via registry

## Data Flow

### Token Exchange Flow

```
1. Client → POST /v1/token (RFC 8693 request)
   - subject_token: external credential
   - subject_token_type: token type
   - audience: target trust domain
                ↓
2. ExchangeServer.Exchange()
   - Extract subject credential from request
   - Optionally extract actor credential (mTLS, service token)
   - Apply actor-based filtering to trust store
                ↓
3. Store.Validate(subject_credential)
   - Determine appropriate validator
   - Validate credential (signature, expiration, claims)
   - Return trust.Result with subject claims
                ↓
4. TokenService.IssueTokens()
   - Build data source input
   - Apply claim mappers (transaction context + request context)
   - Mappers lazily fetch from data sources as needed
   - Compose final TokenContext
                ↓
5. Issuer.Issue(TokenContext)
   - Create token with standard + transaction claims
   - Sign token (if applicable)
   - Return Token with value, type, expiry
                ↓
6. Return ExchangeResponse
   - access_token: issued token value
   - token_type: token type
   - expires_in: seconds until expiration
```

### ext_authz Flow

```
1. Envoy → gRPC Check(CheckRequest)
   - Request attributes (method, path, headers, etc.)
   - Optional mTLS peer certificate
                ↓
2. AuthzServer.Check()
   - Extract subject credential from Authorization header
   - Extract actor credential from mTLS peer certificate
   - Apply actor-based filtering to trust store
                ↓
3. Store.Validate(subject_credential)
   - Validate credential against trust domain
   - Return trust.Result
                ↓
4. TokenService.IssueTokens()
   - Enrich with data sources
   - Apply claim mappers
   - Build transaction context
                ↓
5. Issuer.Issue()
   - Generate transaction token
                ↓
6. Return CheckResponse
   - Status: OK/Denied
   - Headers: Transaction-Token header added
   - Headers: Original Authorization header removed
```

## Key Design Patterns

### Interface-Driven Design

All major components are defined by interfaces, enabling:
- **Testability**: Stub implementations for all interfaces
- **Flexibility**: Swap implementations without modifying consumers
- **Extensibility**: New implementations without breaking changes

Example interfaces:
- `trust.Validator` - Credential validation
- `trust.Store` - Trust domain management
- `service.Issuer` - Token issuance
- `service.DataSource` - Data enrichment
- `service.ClaimMapper` - Claim transformation
- `service.TokenService` - Orchestration

### Registry Pattern

Multiple implementations are managed via registries:
- **`service.Registry`**: Maps token types to issuers
- **`service.DataSourceRegistry`**: Named data sources
- **`service.ClaimMapperRegistry`**: Transaction/request context mappers

This enables dynamic configuration of token issuance behavior.

### Lazy Evaluation

Data sources are fetched lazily during claim mapping:
- Claim mappers receive a `DataSourceRegistry`
- Only fetch data sources they actually need
- Prevents unnecessary external calls
- Caching further optimizes repeated access

### Caching Layers

Data sources support transparent caching:
- **`Cacheable` interface**: Defines cache key and TTL
- **In-memory caching**: Fast local cache with LRU eviction
- **Distributed caching**: groupcache for multi-instance deployments
- Automatic cache key generation from inputs

### Dependency Injection

All services accept dependencies via constructors, enabling explicit dependency graphs and testability:

```go
// 1. Create validators
jwtValidator, _ := trust.NewJWTValidator(trust.JWTValidatorConfig{
    Issuer:      "https://idp.example.com",
    JWKSURL:     "https://idp.example.com/.well-known/jwks.json",
    TrustDomain: "example.com",
})

// 2. Create trust store and add validators
trustStore := trust.NewStubStore()
trustStore.AddValidator(jwtValidator)

// 3. Create data source registry
dataSourceRegistry := service.NewDataSourceRegistry()
// Register Lua data sources
userRolesDS, _ := datasource.NewLuaDataSource("user_roles", luaScript, /* config */)
dataSourceRegistry.Register(userRolesDS)

// 4. Create claim mapper registry
claimMapperRegistry := service.NewClaimMapperRegistry()
// Register CEL mappers for transaction context
celMapper, _ := mapper.NewCELMapper(`{
  "user": subject.subject,
  "roles": datasource("user_roles").roles
}`)
claimMapperRegistry.RegisterTransactionContext(celMapper)
// Register request attributes mapper for request context
claimMapperRegistry.RegisterRequestContext(service.NewRequestAttributesMapper())

// 5. Create issuer registry
issuerRegistry := service.NewSimpleRegistry()
txnIssuer := issuer.NewStubIssuer("https://parsec.example.com", 5*time.Minute)
issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

// 6. Wire together with token service
tokenService := service.NewTokenService(
    "parsec.example.com",  // trust domain
    dataSourceRegistry,
    claimMapperRegistry,
    issuerRegistry,
)

// 7. Create claims filter registry for actor authorization
claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

// 8. Inject into servers
authzServer := server.NewAuthzServer(trustStore, tokenService)
exchangeServer := server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry)

// 9. Create and start server
srv := server.New(server.Config{
    GRPCPort:       9090,
    HTTPPort:       8080,
    AuthzServer:    authzServer,
    ExchangeServer: exchangeServer,
})
srv.Start(ctx)
```

This enables:
- **Testability**: Swap real implementations with stubs/mocks
- **Flexibility**: Change implementations without modifying consumers
- **Clarity**: Explicit dependencies visible in function signatures
- **Composition**: Build complex behavior from simple components

## Testing Strategy

parsec's interface-driven design enables comprehensive testing at multiple levels.

### Unit Tests

Each component can be tested in isolation:

```go
// Test validator independently
validator := trust.NewStubValidator(trust.CredentialTypeBearer)
result, err := validator.Validate(ctx, &trust.BearerCredential{Token: "test"})

// Test issuer independently
iss := issuer.NewStubIssuer("https://parsec.test", 5*time.Minute)
token, err := iss.Issue(ctx, tokenContext)

// Test claim mapper independently
mapper, _ := mapper.NewCELMapper(`{"user": subject.subject}`)
claims, err := mapper.Map(ctx, mapperInput)

// Test data source independently
ds := datasource.NewLuaDataSource("test", script, config)
result, err := ds.Fetch(ctx, input)
```

### Integration Tests

Wire components together with stubs for higher-level testing:

```go
// Setup
trustStore := trust.NewStubStore()
trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))

tokenService := service.NewTokenService(
    "test.example.com",
    service.NewDataSourceRegistry(),
    service.NewClaimMapperRegistry(),
    issuerRegistry,
)

// Test full flow
authzServer := server.NewAuthzServer(trustStore, tokenService)
response, err := authzServer.Check(ctx, envoyRequest)
assert.Equal(t, CheckResponse_OK, response.Status.Code)
```

## Related Documentation

- **`docs/CREDENTIAL_DESIGN.md`**: Credential extraction and validation patterns
- **`internal/datasource/LUA_DATASOURCE.md`**: Lua data source guide with examples
- **`internal/datasource/examples/`**: Example Lua scripts for common scenarios
- **`internal/trust/VALIDATOR_FILTERING.md`**: Validator filtering and actor authorization
- **`internal/trust/README.md`**: Trust package overview
- **`internal/server/README.md`**: Server implementation details
- **`internal/service/README.md`**: Service package overview
