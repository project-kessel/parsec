package httpfixture

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/project-kessel/parsec/internal/clock"
)

func TestNewJWKSFixture(t *testing.T) {
	t.Run("creates fixture with valid config", func(t *testing.T) {
		fixture, err := NewJWKSFixture(JWKSFixtureConfig{
			Issuer:  "https://test-issuer.example.com",
			JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
		})
		if err != nil {
			t.Fatalf("failed to create fixture: %v", err)
		}

		if fixture.issuer != "https://test-issuer.example.com" {
			t.Errorf("expected issuer 'https://test-issuer.example.com', got %q", fixture.issuer)
		}

		if fixture.jwksURL != "https://test-issuer.example.com/.well-known/jwks.json" {
			t.Errorf("expected jwksURL 'https://test-issuer.example.com/.well-known/jwks.json', got %q", fixture.jwksURL)
		}

		// Should use defaults
		if fixture.keyID != "test-key-1" {
			t.Errorf("expected default keyID 'test-key-1', got %q", fixture.keyID)
		}

		if fixture.algorithm != jwa.RS256 {
			t.Errorf("expected default algorithm RS256, got %v", fixture.algorithm)
		}

		// Should have generated keys
		if fixture.privateKey == nil {
			t.Error("expected private key to be generated")
		}

		if fixture.publicKey == nil {
			t.Error("expected public key to be created")
		}

		if fixture.jwks == nil {
			t.Error("expected JWKS to be created")
		}
	})

	t.Run("uses custom key ID and algorithm", func(t *testing.T) {
		fixture, err := NewJWKSFixture(JWKSFixtureConfig{
			Issuer:    "https://test-issuer.example.com",
			JWKSURL:   "https://test-issuer.example.com/.well-known/jwks.json",
			KeyID:     "custom-key-id",
			Algorithm: jwa.RS512,
		})
		if err != nil {
			t.Fatalf("failed to create fixture: %v", err)
		}

		if fixture.keyID != "custom-key-id" {
			t.Errorf("expected keyID 'custom-key-id', got %q", fixture.keyID)
		}

		if fixture.algorithm != jwa.RS512 {
			t.Errorf("expected algorithm RS512, got %v", fixture.algorithm)
		}
	})

	t.Run("requires issuer", func(t *testing.T) {
		_, err := NewJWKSFixture(JWKSFixtureConfig{
			JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
		})
		if err == nil {
			t.Fatal("expected error for missing issuer")
		}
	})

	t.Run("requires JWKS URL", func(t *testing.T) {
		_, err := NewJWKSFixture(JWKSFixtureConfig{
			Issuer: "https://test-issuer.example.com",
		})
		if err == nil {
			t.Fatal("expected error for missing JWKS URL")
		}
	})
}

func TestJWKSFixture_GetFixture(t *testing.T) {
	fixture, err := NewJWKSFixture(JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	t.Run("returns fixture for matching URL", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    mustParseURL(t, "https://test-issuer.example.com/.well-known/jwks.json"),
		}

		result := fixture.GetFixture(req)
		if result == nil {
			t.Fatal("expected fixture to be returned")
		}

		if result.StatusCode != 200 {
			t.Errorf("expected status code 200, got %d", result.StatusCode)
		}

		if result.Headers["Content-Type"] != "application/json" {
			t.Errorf("expected Content-Type 'application/json', got %q", result.Headers["Content-Type"])
		}

		// Parse and validate JWKS
		jwks, err := jwk.Parse([]byte(result.Body))
		if err != nil {
			t.Fatalf("failed to parse JWKS response: %v", err)
		}

		if jwks.Len() != 1 {
			t.Errorf("expected 1 key in JWKS, got %d", jwks.Len())
		}

		// Get the key and verify it has the right properties
		key, ok := jwks.Key(0)
		if !ok {
			t.Fatal("failed to get key from JWKS")
		}

		if key.KeyID() != "test-key-1" {
			t.Errorf("expected key ID 'test-key-1', got %q", key.KeyID())
		}

		if key.Algorithm().String() != "RS256" {
			t.Errorf("expected algorithm RS256, got %s", key.Algorithm())
		}
	})

	t.Run("returns nil for non-matching URL", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    mustParseURL(t, "https://different-issuer.example.com/.well-known/jwks.json"),
		}

		result := fixture.GetFixture(req)
		if result != nil {
			t.Error("expected nil for non-matching URL")
		}
	})
}

func TestJWKSFixture_CreateAndSignToken(t *testing.T) {
	fixture, err := NewJWKSFixture(JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	t.Run("creates and signs valid token", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   "user@example.com",
			"email": "user@example.com",
			"name":  "Test User",
		}

		tokenString, err := fixture.CreateAndSignToken(claims)
		if err != nil {
			t.Fatalf("failed to create and sign token: %v", err)
		}

		// Parse and verify the token
		token, err := jwt.Parse(
			[]byte(tokenString),
			jwt.WithKeySet(fixture.jwks),
			jwt.WithValidate(true),
			jwt.WithIssuer(fixture.issuer),
		)
		if err != nil {
			t.Fatalf("failed to parse/verify token: %v", err)
		}

		// Verify standard claims
		if token.Subject() != "user@example.com" {
			t.Errorf("expected subject 'user@example.com', got %q", token.Subject())
		}

		if token.Issuer() != "https://test-issuer.example.com" {
			t.Errorf("expected issuer 'https://test-issuer.example.com', got %q", token.Issuer())
		}

		// Verify custom claims
		email, ok := token.Get("email")
		if !ok {
			t.Error("expected 'email' claim to be present")
		} else if email != "user@example.com" {
			t.Errorf("expected email 'user@example.com', got %v", email)
		}

		name, ok := token.Get("name")
		if !ok {
			t.Error("expected 'name' claim to be present")
		} else if name != "Test User" {
			t.Errorf("expected name 'Test User', got %v", name)
		}
	})

	t.Run("token has correct expiry", func(t *testing.T) {
		before := time.Now()

		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create and sign token: %v", err)
		}

		after := time.Now()

		token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		// Token should expire 1 hour after creation
		expectedExpiry := after.Add(1 * time.Hour)
		actualExpiry := token.Expiration()

		// Allow some tolerance for test execution time
		tolerance := 5 * time.Second
		if actualExpiry.Before(expectedExpiry.Add(-tolerance)) || actualExpiry.After(expectedExpiry.Add(tolerance)) {
			t.Errorf("expected expiry around %v, got %v", expectedExpiry, actualExpiry)
		}

		// Verify iat is recent
		iat := token.IssuedAt()
		if iat.Before(before.Add(-tolerance)) || iat.After(after.Add(tolerance)) {
			t.Errorf("expected iat between %v and %v, got %v", before, after, iat)
		}
	})
}

func TestJWKSFixture_CreateAndSignTokenWithExpiry(t *testing.T) {
	fixture, err := NewJWKSFixture(JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	t.Run("creates token with custom expiry", func(t *testing.T) {
		expiry := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago

		tokenString, err := fixture.CreateAndSignTokenWithExpiry(
			map[string]interface{}{"sub": "user@example.com"},
			expiry,
		)
		if err != nil {
			t.Fatalf("failed to create and sign token: %v", err)
		}

		// Parse without validation to check expiry
		token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		actualExpiry := token.Expiration()
		tolerance := 1 * time.Second
		if actualExpiry.Before(expiry.Add(-tolerance)) || actualExpiry.After(expiry.Add(tolerance)) {
			t.Errorf("expected expiry %v, got %v", expiry, actualExpiry)
		}
	})
}

func TestJWKSFixture_SignToken(t *testing.T) {
	fixture, err := NewJWKSFixture(JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	t.Run("signs pre-built token", func(t *testing.T) {
		// Create a custom token
		token := jwt.New()
		token.Set(jwt.IssuerKey, fixture.issuer)
		token.Set(jwt.SubjectKey, "custom-subject")
		token.Set(jwt.IssuedAtKey, time.Now())
		token.Set(jwt.ExpirationKey, time.Now().Add(2*time.Hour))
		token.Set("custom_claim", "custom_value")

		tokenString, err := fixture.SignToken(token)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		// Verify the token
		parsed, err := jwt.Parse(
			[]byte(tokenString),
			jwt.WithKeySet(fixture.jwks),
			jwt.WithValidate(true),
		)
		if err != nil {
			t.Fatalf("failed to parse/verify token: %v", err)
		}

		if parsed.Subject() != "custom-subject" {
			t.Errorf("expected subject 'custom-subject', got %q", parsed.Subject())
		}

		customClaim, _ := parsed.Get("custom_claim")
		if customClaim != "custom_value" {
			t.Errorf("expected custom_claim 'custom_value', got %v", customClaim)
		}
	})
}

func TestJWKSFixture_Accessors(t *testing.T) {
	fixture, err := NewJWKSFixture(JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
		KeyID:   "custom-key",
	})
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	if fixture.Issuer() != "https://test-issuer.example.com" {
		t.Errorf("expected issuer 'https://test-issuer.example.com', got %q", fixture.Issuer())
	}

	if fixture.JWKSURL() != "https://test-issuer.example.com/.well-known/jwks.json" {
		t.Errorf("expected JWKS URL 'https://test-issuer.example.com/.well-known/jwks.json', got %q", fixture.JWKSURL())
	}

	if fixture.KeyID() != "custom-key" {
		t.Errorf("expected key ID 'custom-key', got %q", fixture.KeyID())
	}

	if fixture.Clock() == nil {
		t.Error("expected clock to be set")
	}
}

func TestJWKSFixture_WithClockFixture(t *testing.T) {
	// Create a fixture clock at a specific time
	fixedTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	fixture, err := NewJWKSFixture(JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	t.Run("uses clock for token timestamps", func(t *testing.T) {
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Parse token without validation to check timestamps
		token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		// Verify iat matches the fixed time
		iat := token.IssuedAt()
		if !iat.Equal(fixedTime) {
			t.Errorf("expected iat %v, got %v", fixedTime, iat)
		}

		// Verify exp is 1 hour after the fixed time
		expectedExp := fixedTime.Add(1 * time.Hour)
		exp := token.Expiration()
		if !exp.Equal(expectedExp) {
			t.Errorf("expected exp %v, got %v", expectedExp, exp)
		}
	})

	t.Run("advance clock to test expiration", func(t *testing.T) {
		// Create token at current fixture time
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Parse token to get expiry
		token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		originalExp := token.Expiration()

		// Advance clock by 2 hours (past expiration)
		clk.Advance(2 * time.Hour)

		// Verify the token is now expired relative to the clock
		if !fixture.Clock().Now().After(originalExp) {
			t.Error("expected current time to be after token expiration")
		}

		// The fixture time should now be 2 hours ahead
		expectedNow := fixedTime.Add(2 * time.Hour)
		if !fixture.Clock().Now().Equal(expectedNow) {
			t.Errorf("expected clock time %v, got %v", expectedNow, fixture.Clock().Now())
		}
	})

	t.Run("create expired token by rewinding clock", func(t *testing.T) {
		// Reset clock to original time
		clk.Set(fixedTime)

		// Rewind clock to 2 hours ago
		clk.Rewind(2 * time.Hour)

		// Create token (will have iat 2 hours ago, exp 1 hour ago)
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Reset clock to original time
		clk.Set(fixedTime)

		// Parse token
		token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		// Token should be expired relative to current clock time
		if !fixture.Clock().Now().After(token.Expiration()) {
			t.Error("expected token to be expired")
		}
	})

	t.Run("precise control over expiry with custom expiry time", func(t *testing.T) {
		// Reset clock
		clk.Set(fixedTime)

		// Create token that expires exactly 30 minutes from now
		customExpiry := clk.Now().Add(30 * time.Minute)
		tokenString, err := fixture.CreateAndSignTokenWithExpiry(
			map[string]interface{}{"sub": "user@example.com"},
			customExpiry,
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Parse token
		token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		// Verify expiry
		if !token.Expiration().Equal(customExpiry) {
			t.Errorf("expected exp %v, got %v", customExpiry, token.Expiration())
		}

		// Advance clock by 29 minutes (not expired yet)
		clk.Advance(29 * time.Minute)
		if !fixture.Clock().Now().Before(token.Expiration()) {
			t.Error("expected token to not be expired yet")
		}

		// Advance by 2 more minutes (now expired)
		clk.Advance(2 * time.Minute)
		if !fixture.Clock().Now().After(token.Expiration()) {
			t.Error("expected token to be expired now")
		}
	})
}

func mustParseURL(t *testing.T, urlStr string) *url.URL {
	t.Helper()
	u, err := url.Parse(urlStr)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", urlStr, err)
	}
	return u
}
