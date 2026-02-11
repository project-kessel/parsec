package trust

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
)

// setupTestJWKSFixture creates a JWKS fixture for testing
func setupTestJWKSFixture(t *testing.T) *httpfixture.JWKSFixture {
	t.Helper()

	fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("failed to create JWKS fixture: %v", err)
	}

	return fixture
}

// createValidatorWithFixture creates a JWT validator configured to use the provided fixture
// The validator uses the same clock as the fixture for consistent time behavior
func createValidatorWithFixture(t *testing.T, fixture *httpfixture.JWKSFixture) *JWTValidator {
	t.Helper()

	// Create HTTP client with fixture transport
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
		Clock:       fixture.Clock(), // Use the same clock as the fixture
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	return validator
}

func TestJWTValidator(t *testing.T) {
	ctx := context.Background()

	// Setup test JWKS fixture
	fixture := setupTestJWKSFixture(t)

	t.Run("validates valid JWT successfully", func(t *testing.T) {
		// Create validator with fixture
		validator := createValidatorWithFixture(t, fixture)

		// Create valid JWT using fixture
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub":   "user@example.com",
			"email": "user@example.com",
			"name":  "Test User",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Create credential
		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		// Validate
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		// Check result
		if result.Subject != "user@example.com" {
			t.Errorf("expected subject 'user@example.com', got %q", result.Subject)
		}
		if result.Issuer != "https://test-issuer.example.com" {
			t.Errorf("expected issuer 'https://test-issuer.example.com', got %q", result.Issuer)
		}
		if result.TrustDomain != "test-domain" {
			t.Errorf("expected trust domain 'test-domain', got %q", result.TrustDomain)
		}
		if result.Claims["email"] != "user@example.com" {
			t.Errorf("expected email claim 'user@example.com', got %v", result.Claims["email"])
		}
	})

	t.Run("validates bearer credential as JWT", func(t *testing.T) {
		validator := createValidatorWithFixture(t, fixture)

		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Use BearerCredential instead of JWTCredential
		cred := &BearerCredential{Token: tokenString}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		if result.Subject != "user@example.com" {
			t.Errorf("expected subject 'user@example.com', got %q", result.Subject)
		}
	})

	t.Run("rejects expired JWT", func(t *testing.T) {
		validator := createValidatorWithFixture(t, fixture)

		// Create expired token (expired 1 hour ago)
		expiry := time.Now().Add(-1 * time.Hour)
		tokenString, err := fixture.CreateAndSignTokenWithExpiry(
			map[string]interface{}{"sub": "user@example.com"},
			expiry,
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Fatal("expected validation to fail for expired token")
		}
		if err != ErrExpiredToken {
			t.Errorf("expected ErrExpiredToken, got %v", err)
		}
	})

	t.Run("rejects JWT that expires during validation with clock fixture", func(t *testing.T) {
		// Use a fixture clock for precise time control
		fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
		clk := clock.NewFixtureClock(fixedTime)

		fixtureWithClock, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
			Issuer:  "https://test-issuer.example.com",
			JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
			Clock:   clk,
		})
		if err != nil {
			t.Fatalf("failed to create fixture: %v", err)
		}

		validator := createValidatorWithFixture(t, fixtureWithClock)

		// Create token valid for 1 hour from fixture time
		tokenString, err := fixtureWithClock.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		// Token should be valid now
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("expected token to be valid, got error: %v", err)
		}
		if result.Subject != "user@example.com" {
			t.Errorf("expected subject 'user@example.com', got %q", result.Subject)
		}

		// Advance clock by 30 minutes - still valid
		clk.Advance(30 * time.Minute)
		_, err = validator.Validate(ctx, cred)
		if err != nil {
			t.Errorf("expected token to still be valid after 30 minutes, got error: %v", err)
		}

		// Advance clock by another 31 minutes - now expired (61 minutes total)
		clk.Advance(31 * time.Minute)
		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Error("expected validation to fail after advancing past expiration")
		}
		if err != ErrExpiredToken {
			t.Errorf("expected ErrExpiredToken, got %v", err)
		}
	})

	t.Run("rejects JWT with wrong issuer", func(t *testing.T) {
		validator := createValidatorWithFixture(t, fixture)

		// Create a fixture with a different issuer
		wrongIssuerFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
			Issuer:  "https://wrong-issuer.example.com",
			JWKSURL: "https://wrong-issuer.example.com/.well-known/jwks.json",
		})
		if err != nil {
			t.Fatalf("failed to create wrong issuer fixture: %v", err)
		}

		// Create token with wrong issuer
		tokenString, err := wrongIssuerFixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Fatal("expected validation to fail for wrong issuer")
		}
	})

	t.Run("rejects JWT with missing subject", func(t *testing.T) {
		validator := createValidatorWithFixture(t, fixture)

		// Create token without subject claim
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			// No "sub" claim
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Fatal("expected validation to fail for missing subject")
		}
	})

	t.Run("extracts scope and custom claims", func(t *testing.T) {
		validator := createValidatorWithFixture(t, fixture)

		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub":    "user@example.com",
			"scope":  "read write",
			"groups": []string{"admins", "users"},
			"custom": "value",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		if result.Scope != "read write" {
			t.Errorf("expected scope 'read write', got %q", result.Scope)
		}
		if result.Claims["custom"] != "value" {
			t.Errorf("expected custom claim 'value', got %v", result.Claims["custom"])
		}
	})

	t.Run("extracts all claims including standard JWT claims", func(t *testing.T) {
		// This test verifies the fix where we use AsMap() to get ALL claims,
		// not just PrivateClaims(). Standard JWT claims like sub, iss, exp, iat
		// should be available in the Claims map for transformation.
		validator := createValidatorWithFixture(t, fixture)

		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub":    "user@example.com",
			"aud":    "test-audience",
			"email":  "user@example.com",
			"groups": []string{"admins", "users"},
			"custom": "custom-value",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		// Verify standard claims are in the Claims map
		if result.Claims["sub"] != "user@example.com" {
			t.Errorf("expected 'sub' claim 'user@example.com', got %v", result.Claims["sub"])
		}
		if result.Claims["iss"] != "https://test-issuer.example.com" {
			t.Errorf("expected 'iss' claim 'https://test-issuer.example.com', got %v", result.Claims["iss"])
		}
		if result.Claims["aud"] == nil {
			t.Error("expected 'aud' claim to be present")
		}
		if result.Claims["exp"] == nil {
			t.Error("expected 'exp' claim to be present")
		}
		if result.Claims["iat"] == nil {
			t.Error("expected 'iat' claim to be present")
		}

		// Verify custom claims are also present
		if result.Claims["email"] != "user@example.com" {
			t.Errorf("expected 'email' claim 'user@example.com', got %v", result.Claims["email"])
		}
		if result.Claims["custom"] != "custom-value" {
			t.Errorf("expected 'custom' claim 'custom-value', got %v", result.Claims["custom"])
		}

		// Verify groups claim (array type)
		groups, ok := result.Claims["groups"].([]interface{})
		if !ok {
			t.Errorf("expected 'groups' claim to be an array, got %T", result.Claims["groups"])
		} else if len(groups) != 2 {
			t.Errorf("expected 'groups' to have 2 elements, got %d", len(groups))
		}
	})
}

func TestJWTValidatorConfig(t *testing.T) {
	t.Run("requires issuer", func(t *testing.T) {
		_, err := NewJWTValidator(JWTValidatorConfig{
			JWKSURL:     "https://example.com/jwks",
			TrustDomain: "test-domain",
		})
		if err == nil {
			t.Fatal("expected error for missing issuer")
		}
	})

	t.Run("uses default JWKS URL if not provided", func(t *testing.T) {
		// Create a fixture that uses the default JWKS URL pattern
		fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
			Issuer:  "https://test-issuer.example.com",
			JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
		})
		if err != nil {
			t.Fatalf("failed to create fixture: %v", err)
		}

		// Create HTTP client with fixture transport
		httpClient := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: fixture,
				Strict:   true,
			}),
		}

		// Create validator without explicit JWKS URL
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			TrustDomain: "test-domain",
			HTTPClient:  httpClient,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		expectedURL := "https://test-issuer.example.com/.well-known/jwks.json"
		if validator.jwksURL != expectedURL {
			t.Errorf("expected JWKS URL %q, got %q", expectedURL, validator.jwksURL)
		}
	})
}
