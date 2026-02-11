# JWKS Endpoint

The JWKS (JSON Web Key Set) endpoint provides public keys from all configured issuers that sign tokens. This allows clients to verify the signatures of tokens issued by Parsec.

## Specification

The endpoint follows [RFC 7517 - JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517.html), which defines a standard format for representing cryptographic keys in JSON.

## Endpoints

The JWKS endpoint is available at two URLs for compatibility:

### Standard Path
```
GET /v1/jwks.json
```

### Well-Known Path
```
GET /.well-known/jwks.json
```

Both endpoints return identical responses and follow the OAuth 2.0 discovery convention of serving JWKS at `/.well-known/jwks.json`.

## Response Format

The endpoint returns a JSON object with a `keys` array containing one or more JSON Web Keys:

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "kid": "key-a-86a68b9f-b6f4-4226-99e4-5d1e86cfcba8",
      "alg": "ES256",
      "crv": "P-256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  ]
}
```

### Key Fields

Per RFC 7517, each key includes:

- **`kty`** (Key Type): The cryptographic algorithm family
  - `"RSA"` - RSA keys
  - `"EC"` - Elliptic Curve keys
  - `"OKP"` - Octet string key pairs (e.g., Ed25519)

- **`use`** (Public Key Use): Intended use of the key
  - `"sig"` - Signature verification

- **`kid`** (Key ID): Unique identifier for the key, used during key rotation

- **`alg`** (Algorithm): Specific algorithm for use with the key
  - `"ES256"` - ECDSA using P-256 and SHA-256
  - `"ES384"` - ECDSA using P-384 and SHA-384
  - `"RS256"` - RSASSA-PKCS1-v1_5 using SHA-256
  - etc.

- **Key-specific parameters**:
  - For EC keys: `crv` (curve name), `x`, `y` (coordinates)
  - For RSA keys: `n` (modulus), `e` (exponent)
  - For OKP keys: `crv`, `x`

## Behavior

### Multi-Issuer Support

The JWKS endpoint aggregates public keys from **all** configured token issuers. If you have multiple issuers (e.g., transaction tokens and access tokens), the endpoint will return keys from both.

### Key Rotation

The endpoint reflects the current state of key rotation:
- Active signing keys are always included
- Keys in their grace period (still valid for verification but not signing new tokens) are included
- Expired keys are not included

### Issuer Types

Different issuer types contribute keys differently:

- **`SigningTransactionTokenIssuer`**: Provides keys from the rotating key manager
- **`UnsignedIssuer`**: Does not provide keys (unsigned tokens don't need verification)
- **`StubIssuer`**: Does not provide keys (for testing only)

## Usage Examples

### Fetching JWKS

```bash
# Using curl
curl http://localhost:8080/v1/jwks.json

# Or the well-known path
curl http://localhost:8080/.well-known/jwks.json
```

### Verifying Tokens

Most JWT libraries can automatically fetch and use JWKS for verification:

```go
// Example using lestrrat-go/jwx
import (
    "github.com/lestrrat-go/jwx/v3/jwk"
    "github.com/lestrrat-go/jwx/v3/jwt"
)

// Fetch and cache JWKS
cache := jwk.NewCache(ctx)
cache.Register("https://parsec.example.com/v1/jwks.json")

// Parse and verify token
token, err := jwt.Parse(
    []byte(tokenString),
    jwt.WithKeySet(cache, jwk.WithHTTPClient(client)),
)
```

## Testing

The JWKS endpoint is thoroughly tested in:
- `internal/server/jwks_test.go` - Unit tests for key conversion
- `test/integration/jwks_test.go` - Integration tests with real HTTP server

Key test scenarios:
- Empty JWKS when no issuers are configured
- Single issuer with one key
- Multiple issuers with different key types
- Key rotation scenarios
- Unsigned issuers (no keys)

## Implementation

The JWKS server is implemented in:
- `internal/server/jwks.go` - gRPC service implementation with caching
- `internal/service/registry.go` - Registry method for getting all public keys
- `api/proto/parsec/v1/jwks.proto` - Protocol buffer definition
- `api/gen/parsec/v1/jwks*.go` - Generated code

### Caching Architecture

The JWKS endpoint uses **aggressive caching** to ensure maximum performance:

**Cache population:**
1. Cache is populated immediately on `Start()` (before serving requests)
2. If `Start()` wasn't called, cache populates on first request
3. Background refresh runs periodically (default: every 1 minute)

**Serving requests:**
1. Requests are served from cache (O(1) read lock)
2. No issuer calls or key conversions on the hot path
3. Extremely low latency and high throughput

**Refresh behavior:**
1. Uses Clock-based ticker for testability
2. Refresh runs in background (doesn't block requests)
3. If refresh succeeds: updates cache
4. If refresh fails: keeps serving stale data (prioritizes availability)
5. Only returns error if cache is empty AND all issuers fail

**Resilience:**
- Stale data is preferred over service unavailability
- Partial failures don't prevent serving available keys
- Cache ensures consistent response times even during issuer issues

The `GetAllPublicKeys` method in the issuer registry:
- Iterates through all registered issuers
- Collects public keys from each issuer
- Aggregates errors from issuers that fail
- Returns all successfully collected keys along with any errors
- Thread-safe with read lock protection

Error handling:
- If some issuers succeed and others fail: returns partial keys with an aggregated error
- If all issuers fail: returns empty keys with an aggregated error
- Error messages include the token type of each failed issuer for debugging

## Configuration

The JWKS endpoint automatically serves keys from all configured issuers. The cache refresh interval can be customized:

```go
jwksServer := server.NewJWKSServer(server.JWKSServerConfig{
    IssuerRegistry:  issuerRegistry,
    RefreshInterval: 30 * time.Second,  // Default: 1 minute
    Clock:           clock.NewSystemClock(),  // Optional: for testing
})

// Start the background cache refresh
if err := jwksServer.Start(ctx); err != nil {
    return fmt.Errorf("failed to start JWKS server: %w", err)
}
defer jwksServer.Stop()
```

Issuers are configured in your `parsec.yaml`:

```yaml
issuers:
  - token_type: "urn:ietf:params:oauth:token-type:txn_token"
    type: "transaction_token"
    issuer_url: "https://parsec.example.com"
    key_manager:
      type: "aws_kms"
      region: "us-east-1"
      alias_prefix: "alias/parsec/prod-"
```

The JWKS endpoint will automatically serve the public keys from this issuer's key manager.

