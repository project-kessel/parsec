package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
)

// --- Shared test fixtures ---

// benchJSONCredential returns a JSONCredential matching the structure both
// the built-in JSONValidator and the equivalent Lua script validate.
func benchJSONCredential() *JSONCredential {
	result := &Result{
		Subject:     "user@example.com",
		Issuer:      "https://issuer.example.com",
		TrustDomain: "example.com",
		Claims: claims.Claims{
			"email":  "user@example.com",
			"groups": []string{"admin", "user"},
			"role":   "editor",
		},
		ExpiresAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IssuedAt:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Audience:  []string{"parsec"},
		Scope:     "read write",
	}
	data, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	return &JSONCredential{RawJSON: data}
}

func benchBearerCredential() *BearerCredential {
	return &BearerCredential{Token: "valid-token"}
}

// --- Built-in JSONValidator (baseline) ---

func BenchmarkJSONValidator(b *testing.B) {
	validator := NewJSONValidator()
	cred := benchJSONCredential()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if result.Subject != "user@example.com" {
			b.Fatal("wrong subject")
		}
	}
}

// --- Lua validator doing equivalent work to JSONValidator ---

// This script mirrors the JSONValidator logic: read JSON fields from the
// credential, check required fields, return a result table.
const luaEquivalentScript = `
function validate(input)
  local cred = input.credential

  if cred.type ~= "bearer" then
    error("expected bearer credential")
  end

  if cred.token ~= "valid-token" then
    return nil
  end

  return {
    subject      = "user@example.com",
    issuer       = "https://issuer.example.com",
    trust_domain = "example.com",
    claims       = {
      email  = "user@example.com",
      groups = {"admin", "user"},
      role   = "editor",
    },
    expires_at = 4102444800,
    issued_at  = 1704067200,
    audience   = {"parsec"},
    scope      = "read write",
  }
end
`

func BenchmarkLuaValidator_Equivalent(b *testing.B) {
	validator, err := NewLuaValidator("bench", luaEquivalentScript, []CredentialType{CredentialTypeBearer})
	if err != nil {
		b.Fatalf("NewLuaValidator: %v", err)
	}

	cred := benchBearerCredential()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if result.Subject != "user@example.com" {
			b.Fatal("wrong subject")
		}
	}
}

// --- Lua validator: minimal script (floor for Lua VM overhead) ---

const luaMinimalScript = `
function validate(input)
  return {
    subject    = "s",
    expires_at = 4102444800,
  }
end
`

func BenchmarkLuaValidator_Minimal(b *testing.B) {
	validator, err := NewLuaValidator("bench-min", luaMinimalScript, []CredentialType{CredentialTypeBearer})
	if err != nil {
		b.Fatalf("NewLuaValidator: %v", err)
	}

	cred := benchBearerCredential()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := validator.Validate(ctx, cred)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// --- JWT validator (built-in, for reference) ---

func BenchmarkJWTValidator(b *testing.B) {
	fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		b.Fatalf("failed to create JWKS fixture: %v", err)
	}

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: fixture,
			Strict:   true,
		}),
	}

	validator, err := NewJWTValidator(JWTValidatorConfig{
		Issuer:      fixture.Issuer(),
		JWKSURL:     fixture.JWKSURL(),
		TrustDomain: "test-domain",
		HTTPClient:  httpClient,
		Clock:       fixture.Clock(),
	})
	if err != nil {
		b.Fatalf("failed to create validator: %v", err)
	}

	tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
		"sub":   "user@example.com",
		"email": "user@example.com",
		"scope": "read write",
	})
	if err != nil {
		b.Fatalf("failed to create token: %v", err)
	}
	cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if result.Subject != "user@example.com" {
			b.Fatal("wrong subject")
		}
	}
}

// --- Lua validator with HTTP call (real-world I/O scenario) ---

func BenchmarkLuaValidator_WithHTTPCall(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"active":true,"sub":"http-user","email":"http@example.com"}`)
	}))
	b.Cleanup(server.Close)

	const httpScript = `
function validate(input)
  local body = json.encode({token = input.credential.token})
  local resp = http.post(config.get("introspection_url"), body, {["Content-Type"] = "application/json"})
  if resp.status ~= 200 then
    return nil
  end
  local decoded = json.decode(resp.body)
  if not decoded.active then
    return nil
  end
  return {
    subject      = decoded.sub,
    issuer       = config.get("issuer"),
    trust_domain = config.get("trust_domain"),
    claims       = {email = decoded.email},
    expires_at   = 4102444800,
  }
end
`

	validator, err := NewLuaValidator("bench-http", httpScript, []CredentialType{CredentialTypeBearer},
		WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"introspection_url": server.URL,
			"issuer":            "https://issuer.example.com",
			"trust_domain":      "example.com",
		})),
	)
	if err != nil {
		b.Fatalf("NewLuaValidator: %v", err)
	}

	cred := benchBearerCredential()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if result.Subject != "http-user" {
			b.Fatal("wrong subject")
		}
	}
}
