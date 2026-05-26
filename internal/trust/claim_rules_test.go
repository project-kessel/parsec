package trust

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
)

func TestClaimRules_rejectActClaim(t *testing.T) {
	ctx := context.Background()
	fixture := setupTestJWKSFixture(t)

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
		ClaimRules: NewClaimRules(&ClaimRulesConfig{
			RejectActClaim: true,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("rejects token with act claim", func(t *testing.T) {
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
			"act": map[string]interface{}{"sub": "impersonated"},
		})
		if err != nil {
			t.Fatal(err)
		}

		cred := &BearerCredential{Token: tokenString}
		_, err = validator.Validate(ctx, cred)
		if !errors.Is(err, ErrForbiddenToken) {
			t.Fatalf("expected ErrForbiddenToken, got: %v", err)
		}
	})

	t.Run("accepts token without act claim", func(t *testing.T) {
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}

		cred := &BearerCredential{Token: tokenString}
		if _, err := validator.Validate(ctx, cred); err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
	})
}

func TestClaimRules_allowedIssuers(t *testing.T) {
	ctx := context.Background()
	fixture := setupTestJWKSFixture(t)

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: fixture,
			Strict:   true,
		}),
	}

	allowedIssuer := fixture.Issuer()
	validator, err := NewJWTValidator(JWTValidatorConfig{
		Issuer:      allowedIssuer,
		JWKSURL:     fixture.JWKSURL(),
		TrustDomain: "test-domain",
		HTTPClient:  httpClient,
		Clock:       fixture.Clock(),
		ClaimRules: NewClaimRules(&ClaimRulesConfig{
			AllowedIssuers: []string{allowedIssuer},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("accepts token from allowed issuer", func(t *testing.T) {
		tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
			"sub": "user@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}

		cred := &BearerCredential{Token: tokenString}
		if _, err := validator.Validate(ctx, cred); err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
	})

	t.Run("rejects token when issuer not in allowlist", func(t *testing.T) {
		otherFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
			Issuer:  "https://other-issuer.example.com",
			JWKSURL: "https://other-issuer.example.com/.well-known/jwks.json",
		})
		if err != nil {
			t.Fatal(err)
		}

		// Validator still pins issuer to allowedIssuer; use claim_rules-only check
		// by validating claims path — token from wrong fixture won't pass jwt.WithIssuer anyway.
		// Test Evaluate directly for issuer allowlist semantics.
		rules := NewClaimRules(&ClaimRulesConfig{
			AllowedIssuers: []string{allowedIssuer},
		})
		err = rules.Evaluate(map[string]any{"iss": otherFixture.Issuer()}, otherFixture.Issuer(), time.Now(), time.Now())
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got: %v", err)
		}
	})
}

func TestClaimRules_maxTokenAge(t *testing.T) {
	ctx := context.Background()
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
		Clock:   clk,
	})
	if err != nil {
		t.Fatal(err)
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
		Clock:       clk,
		ClaimRules: NewClaimRules(&ClaimRulesConfig{
			MaxTokenAge: time.Hour,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	staleIAT := fixedTime.Add(-2 * time.Hour)
	tokenString, err := fixture.CreateAndSignToken(map[string]interface{}{
		"sub": "user@example.com",
		"iat": staleIAT.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cred := &BearerCredential{Token: tokenString}
	_, err = validator.Validate(ctx, cred)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for stale iat, got: %v", err)
	}
}
