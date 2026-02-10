# End-to-End Hermetic Testing

This directory contains end-to-end tests that validate Parsec's **external gRPC API** using hermetic fixtures for reproducible, deterministic testing.

## `hermetic_config_test.go`

This test validates the **external API contract** of Parsec: the gRPC `TokenExchange.Exchange()` RPC. It treats all internal implementation as a black box.

### Testing Philosophy

**External API Contract Testing**

The e2e test focuses on:
- ✅ **gRPC API Contract**: `Exchange(ExchangeRequest)` → `ExchangeResponse`
- ✅ **Observable Behavior**: Does the API succeed/fail appropriately? What's in the response?
- ✅ **Production Configuration**: Uses realistic validators, datasources, and issuers
- ✅ **Hermetic Fixtures**: All I/O (JWKS, HTTP, time) is controlled via fixtures

The e2e test **does not**:
- ❌ Call internal component APIs (like `TokenService.IssueTokens()` or `TrustStore.Validate()`)
- ❌ Inspect internal state or implementation details
- ❌ Parse issued tokens to verify internal structure (unless that's part of the public contract)
- ❌ Make assumptions about how the server implements the API

### Test Structure

```go
// 1. Setup fixtures (control all I/O)
clk := clock.NewFixtureClock(fixedTime)
actorJWKS := httpfixture.NewJWKSFixture(...)
subjectJWKS := httpfixture.NewJWKSFixture(...)
apiFixtures := httpfixture.NewRuleBasedProvider(...)

// 2. Load production configuration (inject fixtures)
actorValidator := trust.NewJWTValidator(..., HTTPClient: fixtureClient, Clock: clk)
dataSource := datasource.NewLuaDataSource(..., FixtureProvider: apiFixtures)

// CEL mapper that includes datasource data
celMapper := mapper.NewCELMapper(`{
    "sub": subject.subject,
    "user_profile": datasource("user-profile"),
    "email": subject.claims.email
}`)

// UnsignedIssuer for claim verification in tests
issuer := issuer.NewUnsignedIssuer(tokenType, []ClaimMapper{celMapper})
tokenService := service.NewTokenService(...)

// 3. Create the external API server
exchangeServer := server.NewExchangeServer(trustStore, tokenService, ...)

// 4. Test the external API ONLY
ctx := metadata.NewIncomingContext(..., "authorization", "Bearer "+actorToken)
resp, err := exchangeServer.Exchange(ctx, &parsecv1.ExchangeRequest{
    GrantType: "urn:ietf:params:oauth:grant-type:token-exchange",
    SubjectToken: subjectToken,
    // ...
})

// 5. Verify the response AND token claims
// UnsignedIssuer returns base64-encoded JSON we can parse
tokenJSON, _ := base64.StdEncoding.DecodeString(resp.AccessToken)
var claims map[string]interface{}
json.Unmarshal(tokenJSON, &claims)

// Verify expected claims from datasource fixtures
if claims["user_profile"]["department"] != "engineering" {
    t.Error("datasource enrichment failed")
}
```

### What it Demonstrates

1.  **External API Testing**:
    *   Tests only the `TokenExchange.Exchange()` gRPC RPC
    *   Actor credentials passed via gRPC metadata (`authorization: Bearer <token>`)
    *   Subject credentials in the request body (`subject_token`)
    *   Request context as base64-encoded JSON (`request_context`)
    *   Validates the `ExchangeResponse` structure
    *   **Claims Verification**: Uses `UnsignedIssuer` to issue parseable tokens, allowing verification that:
        - Subject identity claims are included (sub, issuer, trust_domain, email, name)
        - Datasource data is fetched and included (user_profile with department, roles)
        - CEL mappers correctly transform data into claims

2.  **Hermetic Configuration**:
    *   Production-like JWT validators, Lua datasources, token issuers
    *   All external I/O replaced with fixtures (JWKS endpoints, data APIs, time)
    *   Configuration mirrors what would be loaded from a config file

3.  **JWKS Fixtures for Identity Providers**:
    *   Multiple IdPs simulated (actor IdP for the calling service, subject IdP for end users)
    *   Fixtures provide both HTTP JWKS endpoints and token signing APIs
    *   Enables testing without real identity providers

4.  **HTTP Fixtures for Datasource APIs**:
    *   External data APIs mocked with `HTTPFixtureRule`
    *   Lua datasources make HTTP calls that are intercepted by fixtures
    *   Rule-based matching (exact URLs, patterns) for flexible mocking

5.  **Clock Fixtures for Time Control**:
    *   Controlled time for deterministic expiration testing
    *   Tests can advance time to validate token expiration behavior
    *   No `time.Sleep()` or waiting for real time to pass

### Test Cases

1.  **Successful Token Exchange**: Valid actor + subject credentials → token issued
2.  **Expired Subject Token**: Expired subject token → error
3.  **Request Context Propagation**: Request context claims included in request → accepted
4.  **Invalid Grant Type**: Wrong grant type → error
5.  **Mismatched Audience**: Audience doesn't match trust domain → error

### Benefits

*   **Zero External I/O**: No network calls, no real IdPs, no external services
*   **Deterministic**: Same results every run, regardless of environment
*   **Fast**: ~80ms per test run (no network latency or real time delays)
*   **Precise Time Control**: Test exact expiration boundaries without waiting
*   **Production-like**: Same configuration patterns as real deployments
*   **API-focused**: Tests what clients would actually call, not internals
*   **Black Box**: Implementation can be refactored without changing tests

### How to Run

```bash
go test ./test/e2e -v
```

Expected output:
```
=== RUN   TestHermeticTokenExchange
=== RUN   TestHermeticTokenExchange/successful_token_exchange_via_gRPC_API
    ✓ Token issued: stub-txn-token.alice...
    ✓ Expires in: 300 seconds
=== RUN   TestHermeticTokenExchange/rejects_expired_subject_token
    ✓ Token exchange succeeded with fresh credentials
    ⏰ Advanced time to: 2024-06-15 11:01:00 +0000 UTC
    ✓ Expired token rejected: ...
=== RUN   TestHermeticTokenExchange/includes_request_context_in_token
    ✓ Token issued with request context
=== RUN   TestHermeticTokenExchange/rejects_invalid_grant_type
    ✓ Invalid grant_type rejected: unsupported grant_type: invalid-grant-type
=== RUN   TestHermeticTokenExchange/rejects_mismatched_audience
    ✓ Mismatched audience rejected: ...
--- PASS: TestHermeticTokenExchange (0.08s)
PASS
ok      github.com/project-kessel/parsec/test/e2e    0.656s
```

### Key Difference from Integration Tests

**Integration tests** (`test/integration/`) test individual components and their interactions:
- Test `JWTValidator` with real JWKS parsing
- Test `LuaDataSource` with HTTP fixtures
- Test `TokenService` with mappers and issuers

**E2E tests** (`test/e2e/`) test the complete external API:
- Test `TokenExchange.Exchange()` RPC only
- Treat all internals as a black box
- Validate only observable API behavior (request → response)

This e2e test serves as a **contract test** that catches breaking changes to the public API while remaining resilient to internal refactoring.
