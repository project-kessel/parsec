# HTTP Fixture System

The HTTP fixture system provides a general-purpose mechanism for intercepting HTTP requests and returning predefined responses. This enables testing and development without external dependencies.

## Overview

The fixture system is built around a simple interface that allows flexible fixture provision strategies:

```go
type FixtureProvider interface {
    GetFixture(req *http.Request) *Fixture
}
```

This design allows:
- Simple matching implementations
- Script-based dynamic fixture generation
- Stateful providers that learn from requests
- Complete control over fixture selection logic

## Components

### Core Types

#### Fixture

Defines an HTTP response:

```go
type Fixture struct {
    StatusCode int               // HTTP status code
    Headers    map[string]string // Response headers
    Body       string            // Response body
    Delay      *time.Duration    // Optional delay before responding
}
```

#### FixtureProvider

Interface for providing fixtures based on requests:

```go
type FixtureProvider interface {
    GetFixture(req *http.Request) *Fixture
}
```

### Built-in Providers

#### MapProvider

Simple key-based lookup using "METHOD URL" format:

```go
provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
    "GET https://api.example.com/data": {
        StatusCode: 200,
        Body:       `{"result": "success"}`,
    },
})
```

#### RuleBasedProvider

Matches requests against a set of rules with support for:
- Exact URL matching
- Pattern (regex) matching
- Method matching (including wildcard `*`)
- Header matching

```go
rules := []httpfixture.HTTPFixtureRule{
    {
        Request: httpfixture.FixtureRequest{
            Method:  "GET",
            URL:     "https://api.example.com/user/.*",
            URLType: "pattern",
        },
        Response: httpfixture.Fixture{
            StatusCode: 200,
            Body:       `{"user": "any"}`,
        },
    },
}
provider := httpfixture.NewRuleBasedProvider(rules)
```

#### FuncProvider

Maximum flexibility - use any function:

```go
provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
    if strings.HasPrefix(req.URL.Path, "/user/") {
        userID := strings.TrimPrefix(req.URL.Path, "/user/")
        return &httpfixture.Fixture{
            StatusCode: 200,
            Body:       fmt.Sprintf(`{"id": "%s"}`, userID),
        }
    }
    return nil
})
```

### Transport

The `Transport` implements `http.RoundTripper` and delegates fixture provision to a `FixtureProvider`:

```go
transport := httpfixture.NewTransport(httpfixture.TransportConfig{
    Provider: provider,
    Strict:   true,  // Error if no fixture provided
    Fallback: http.DefaultTransport,  // Optional fallback to real HTTP
})

client := &http.Client{Transport: transport}
```

## File-Based Fixtures

### Loading from Files

Fixtures can be defined in JSON or YAML files:

```go
// Load from a single file
provider, err := httpfixture.LoadFixturesFromFile("fixtures.yaml")

// Load from all files in a directory
provider, err := httpfixture.LoadFixturesFromDir("fixtures/")
```

### YAML Format

```yaml
fixtures:
  - request:
      method: GET
      url: https://api.example.com/data
      url_type: exact
    response:
      status: 200
      headers:
        Content-Type: application/json
      body: '{"data": "value"}'

  - request:
      method: GET
      url: https://api.example.com/user/.*
      url_type: pattern
    response:
      status: 200
      body: '{"user": "any"}'
```

### JSON Format

```json
{
  "fixtures": [
    {
      "request": {
        "method": "GET",
        "url": "https://api.example.com/data",
        "url_type": "exact"
      },
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": "{\"data\": \"value\"}"
      }
    }
  ]
}
```

## Usage with Lua Data Sources

The fixture system integrates seamlessly with Lua data sources:

```go
// Create a fixture provider
provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
    "GET https://api.example.com/user/alice": {
        StatusCode: 200,
        Body:       `{"username": "alice"}`,
    },
})

// Configure Lua data source with fixtures
ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
    Name:   "user-data",
    Script: script,
    HTTPConfig: &lua.HTTPServiceConfig{
        Timeout:         30 * time.Second,
        FixtureProvider: provider,
    },
})
```

## Testing Examples

### Basic Test with Fixtures

```go
func TestMyDataSource(t *testing.T) {
    provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
        "GET https://api.example.com/data": {
            StatusCode: 200,
            Body:       `{"test": "data"}`,
        },
    })

    ds := setupDataSource(provider)
    result, err := ds.Fetch(context.Background(), input)
    
    // Assertions...
}
```

### Dynamic Fixtures

```go
func TestWithDynamicFixtures(t *testing.T) {
    callCount := 0
    provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
        callCount++
        return &httpfixture.Fixture{
            StatusCode: 200,
            Body:       fmt.Sprintf(`{"call": %d}`, callCount),
        }
    })

    // Test...
}
```

### File-Based Fixtures for Integration Tests

```go
func TestIntegration(t *testing.T) {
    provider, err := httpfixture.LoadFixturesFromFile("testdata/api_fixtures.yaml")
    if err != nil {
        t.Fatal(err)
    }

    ds := setupDataSource(provider)
    // Run integration test scenarios...
}
```

## Best Practices

1. **Use Fixtures for All Tests**: Avoid real HTTP calls in tests for speed and reliability
2. **Organize Fixtures**: Group related fixtures in separate files
3. **Be Specific**: Match exact URLs when possible, use patterns sparingly
4. **Order Matters**: In rule-based providers, place specific rules before generic ones
5. **Test Fixtures**: Verify your fixtures accurately represent real API responses
6. **Document Fixtures**: Add comments explaining complex patterns or edge cases
7. **Version Control**: Commit fixture files alongside tests

## Advanced Features

### Response Delays

Simulate network latency:

```go
delay := 100 * time.Millisecond
fixture := &httpfixture.Fixture{
    StatusCode: 200,
    Body:       "slow response",
    Delay:      &delay,
}
```

### Header Matching

Match requests based on headers:

```go
rule := httpfixture.HTTPFixtureRule{
    Request: httpfixture.FixtureRequest{
        Method: "GET",
        URL:    "https://api.example.com/secure",
        Headers: map[string]string{
            "Authorization": "Bearer token123",
        },
    },
    Response: httpfixture.Fixture{
        StatusCode: 200,
        Body:       `{"authenticated": true}`,
    },
}
```

### Fallback to Real HTTP

For partial mocking scenarios:

```go
transport := httpfixture.NewTransport(httpfixture.TransportConfig{
    Provider: provider,
    Fallback: http.DefaultTransport,
    Strict:   false,  // Don't error on missing fixtures
})
```

## Architecture

The fixture system is designed to be:

1. **General-Purpose**: Not tied to Lua or any specific use case
2. **Flexible**: Provider interface allows any fixture selection strategy
3. **Composable**: Can be used with any `http.Client`
4. **Testable**: Makes tests fast, deterministic, and hermetic
5. **Extensible**: Easy to add custom providers or matching logic

## Dependencies

The package uses [`github.com/goccy/go-yaml`](https://github.com/goccy/go-yaml) for YAML parsing, which is an actively maintained pure Go YAML 1.2 implementation with excellent error reporting and performance.

## JWKS Fixtures

### Overview

JWKS (JSON Web Key Set) fixtures are specialized fixtures for testing JWT validators without external dependencies. They provide both HTTP fixture responses for JWKS endpoints and a convenient Go API for signing test tokens.

### Key Features

- **Automatic Key Generation**: Generates RSA key pairs on creation
- **FixtureProvider Implementation**: Serves JWKS responses via HTTP fixture interface
- **Signing API**: Convenient methods for creating and signing test tokens
- **Time Control**: Optional clock injection for precise control over token timestamps
- **Hermetic Testing**: No need for httptest servers or external services

### Creating a JWKS Fixture

```go
fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
    Issuer:  "https://test-issuer.example.com",
    JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
    KeyID:   "test-key-1",  // Optional, defaults to "test-key-1"
    Algorithm: jwa.RS256,    // Optional, defaults to RS256
})
if err != nil {
    t.Fatal(err)
}
```

### Using with JWT Validators

```go
// Create HTTP client with fixture transport
httpClient := &http.Client{
    Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
        Provider: fixture,
        Strict:   true,
    }),
}

// Create validator with fixture client
validator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
    Issuer:      fixture.Issuer(),
    JWKSURL:     fixture.JWKSURL(),
    TrustDomain: "test-domain",
    HTTPClient:  httpClient,
})

// Create and sign test tokens
tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
    "sub":   "user@example.com",
    "email": "user@example.com",
    "roles": []string{"admin", "user"},
})
```

### Signing API

#### CreateAndSignToken

Creates a JWT with standard claims (iss, iat, exp) automatically set, plus custom claims:

```go
tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
    "sub":    "user-123",
    "email":  "user@example.com",
    "custom": "value",
})
```

#### CreateAndSignTokenWithExpiry

Creates a JWT with custom expiry time (useful for testing expiration):

```go
expiry := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
tokenString, err := fixture.CreateAndSignTokenWithExpiry(
    map[string]interface{}{"sub": "user@example.com"},
    expiry,
)
```

#### SignToken

Signs a pre-built JWT token for maximum control:

```go
token := jwt.New()
token.Set(jwt.SubjectKey, "custom-subject")
token.Set("custom_claim", "custom_value")

tokenString, err := fixture.SignToken(token)
```

### Testing Multiple Issuers

Create multiple fixtures with different issuers to test authorization scenarios:

```go
prodFixture, _ := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
    Issuer:  "https://prod-issuer.example.com",
    JWKSURL: "https://prod-issuer.example.com/.well-known/jwks.json",
})

testFixture, _ := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
    Issuer:  "https://test-issuer.example.com",
    JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
})

// Create composite provider for both fixtures
compositeProvider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
    if f := prodFixture.GetFixture(req); f != nil {
        return f
    }
    return testFixture.GetFixture(req)
})
```

### Time Control with Clock Fixtures

Use `clock.FixtureClock` for precise control over token timestamps and expiration testing:

```go
import "github.com/project-kessel/parsec/internal/clock"

func TestTokenExpiration(t *testing.T) {
    // Create a fixture clock at a specific time
    fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
    clk := clock.NewFixtureClock(fixedTime)

    // Create JWKS fixture with controlled clock
    fixture, _ := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
        Issuer:  "https://auth.example.com",
        JWKSURL: "https://auth.example.com/.well-known/jwks.json",
        Clock:   clk,
    })

    // Create validator with same clock for consistent time behavior
    httpClient := &http.Client{
        Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
            Provider: fixture,
            Strict:   true,
        }),
    }

    validator, _ := trust.NewJWTValidator(trust.JWTValidatorConfig{
        Issuer:      fixture.Issuer(),
        JWKSURL:     fixture.JWKSURL(),
        TrustDomain: "test-domain",
        HTTPClient:  httpClient,
        Clock:       fixture.Clock(), // Same clock for validator
    })

    // Create token valid for 1 hour
    tokenString, _ := fixture.CreateAndSignToken(map[string]interface{}{
        "sub": "user@example.com",
    })

    cred := &trust.JWTCredential{
        BearerCredential: trust.BearerCredential{Token: tokenString},
    }

    // Token is valid now
    _, err := validator.Validate(context.Background(), cred)
    if err != nil {
        t.Errorf("expected token to be valid: %v", err)
    }

    // Advance clock by 30 minutes - still valid
    clk.Advance(30 * time.Minute)
    _, err = validator.Validate(context.Background(), cred)
    if err != nil {
        t.Errorf("expected token to still be valid: %v", err)
    }

    // Advance clock by 31 more minutes - now expired
    clk.Advance(31 * time.Minute)
    _, err = validator.Validate(context.Background(), cred)
    if err == nil {
        t.Error("expected token to be expired")
    }
}
```

### Complete Example

```go
func TestJWTValidation(t *testing.T) {
    // Setup fixture
    fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
        Issuer:  "https://auth.example.com",
        JWKSURL: "https://auth.example.com/.well-known/jwks.json",
    })
    if err != nil {
        t.Fatal(err)
    }

    // Create validator with fixture
    httpClient := &http.Client{
        Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
            Provider: fixture,
            Strict:   true,
        }),
    }

    validator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
        Issuer:      fixture.Issuer(),
        JWKSURL:     fixture.JWKSURL(),
        TrustDomain: "test-domain",
        HTTPClient:  httpClient,
        Clock:       fixture.Clock(), // Use fixture's clock
    })
    if err != nil {
        t.Fatal(err)
    }

    // Test with valid token
    tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
        "sub":   "user@example.com",
        "role":  "admin",
    })
    if err != nil {
        t.Fatal(err)
    }

    cred := &trust.JWTCredential{
        BearerCredential: trust.BearerCredential{Token: tokenString},
    }

    result, err := validator.Validate(context.Background(), cred)
    if err != nil {
        t.Fatalf("validation failed: %v", err)
    }

    // Assert on result
    if result.Subject != "user@example.com" {
        t.Errorf("unexpected subject: %v", result.Subject)
    }
}
```

## Package Structure

```
internal/httpfixture/
├── fixture.go            # Core types and interfaces
├── providers.go          # Built-in provider implementations
├── transport.go          # HTTP RoundTripper implementation
├── loader.go             # File loading utilities
├── jwks_fixture.go       # JWKS fixture for JWT testing
├── fixture_test.go       # Tests
├── jwks_fixture_test.go  # JWKS fixture tests
└── README.md             # This file
```

## Future Enhancements

Potential future additions:
- Request body matching
- Response templating with request data
- Recording mode (capture real responses as fixtures)
- Fixture validation against OpenAPI specs
- HTTP/2 support

