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

func loadValidatorAudiencesTestConfig(t *testing.T) *Config {
	t.Helper()

	const yaml = `
trust_store:
  type: stub_store
  validators:
    - name: test-sso
      type: jwt_validator
      issuer: "https://test-issuer.example.com"
      jwks_url: "https://test-issuer.example.com/.well-known/jwks.json"
      trust_domain: "test-domain"
      audiences:
        - rhsm-api
        - customer-portal
        - api.console
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

func TestLoadValidatorAudiencesFromYAML(t *testing.T) {
	cfg := loadValidatorAudiencesTestConfig(t)

	if len(cfg.TrustStore.Validators) != 1 {
		t.Fatalf("validators len=%d, want 1", len(cfg.TrustStore.Validators))
	}
	v := cfg.TrustStore.Validators[0]
	if v.Type != "jwt_validator" {
		t.Fatalf("type=%q, want jwt_validator", v.Type)
	}
	want := []string{"rhsm-api", "customer-portal", "api.console"}
	if len(v.Audiences) != len(want) {
		t.Fatalf("audiences=%v, want %v", v.Audiences, want)
	}
	for i := range want {
		if v.Audiences[i] != want[i] {
			t.Fatalf("audiences=%v, want %v", v.Audiences, want)
		}
	}
}

func TestTrustStoreRejectsDisallowedAudience(t *testing.T) {
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
		Validators: []NamedValidatorConfig{{
			Name: "test-sso",
			ValidatorConfig: ValidatorConfig{
				Type:        "jwt_validator",
				Issuer:      fixture.Issuer(),
				JWKSURL:     fixture.JWKSURL(),
				TrustDomain: "test-domain",
				Audiences:   []string{"allowed-aud"},
			},
		}},
	}, transport, trust.NoOpTrustObserver{})
	if err != nil {
		t.Fatal(err)
	}

	token, err := fixture.CreateAndSignToken(map[string]interface{}{
		"sub": "user@example.com",
		"aud": "wrong-aud",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Validate(context.Background(), &trust.BearerCredential{Token: token})
	if err == nil {
		t.Fatal("expected validation error for disallowed audience")
	}
	if !errors.Is(err, trust.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}
}
