package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/trust"
)

func loadClaimRulesTestConfig(t *testing.T) *Config {
	t.Helper()

	const yaml = `
trust_store:
  type: stub_store
  claim_rules:
    reject_act_claim: true
    allowed_issuers:
      - "https://test-issuer.example.com"
    max_token_age: "1h"
  validators:
    - name: test-sso
      type: jwt_validator
      issuer: "https://test-issuer.example.com"
      jwks_url: "https://test-issuer.example.com/.well-known/jwks.json"
      trust_domain: "test-domain"
`

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := NewLoader(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loader.Get()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLoadClaimRulesFromYAML(t *testing.T) {
	cfg := loadClaimRulesTestConfig(t)

	rules := cfg.TrustStore.ClaimRules
	if rules == nil {
		t.Fatal("expected claim_rules to be loaded")
	}
	if !rules.RejectActClaim {
		t.Error("expected reject_act_claim=true")
	}
	if len(rules.AllowedIssuers) != 1 || rules.AllowedIssuers[0] != "https://test-issuer.example.com" {
		t.Fatalf("allowed_issuers=%v", rules.AllowedIssuers)
	}
	if rules.MaxTokenAge != "1h" {
		t.Fatalf("max_token_age=%q, want 1h", rules.MaxTokenAge)
	}
}

func TestTrustStoreRejectsActClaim(t *testing.T) {
	fixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://test-issuer.example.com",
		JWKSURL: "https://test-issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatal(err)
	}

	transport := httpfixture.NewTransport(httpfixture.TransportConfig{
		Provider: fixture,
		Strict:   true,
	})

	store, err := NewTrustStore(TrustStoreConfig{
		Type: "stub_store",
		ClaimRules: &ClaimRulesConfig{
			RejectActClaim: true,
			AllowedIssuers: []string{fixture.Issuer()},
		},
		Validators: []NamedValidatorConfig{{
			Name: "test-sso",
			ValidatorConfig: ValidatorConfig{
				Type:        "jwt_validator",
				Issuer:      fixture.Issuer(),
				JWKSURL:     fixture.JWKSURL(),
				TrustDomain: "test-domain",
			},
		}},
	}, transport, trust.NoOpTrustObserver{})
	if err != nil {
		t.Fatal(err)
	}

	token, err := fixture.CreateAndSignToken(map[string]interface{}{
		"sub": "user@example.com",
		"act": map[string]interface{}{"sub": "other"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Validate(context.Background(), &trust.BearerCredential{Token: token})
	if !errors.Is(err, trust.ErrForbiddenToken) {
		t.Fatalf("expected ErrForbiddenToken, got: %v", err)
	}
}
