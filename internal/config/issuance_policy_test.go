package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/project-kessel/parsec/internal/service"
)

func TestLoadIssuancePolicyFromYAML(t *testing.T) {
	const yaml = `
issuance_policy:
  type: claim_assertions
  required_claims:
    - idp
    - org_id
  rejected_claims:
    impersonated: true
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

	if cfg.IssuancePolicy == nil {
		t.Fatal("expected issuance_policy to be set")
	}
	if cfg.IssuancePolicy.Type != "claim_assertions" {
		t.Fatalf("type=%q, want claim_assertions", cfg.IssuancePolicy.Type)
	}

	wantRequired := []string{"idp", "org_id"}
	if len(cfg.IssuancePolicy.RequiredClaims) != len(wantRequired) {
		t.Fatalf("required_claims=%v, want %v", cfg.IssuancePolicy.RequiredClaims, wantRequired)
	}
	for i := range wantRequired {
		if cfg.IssuancePolicy.RequiredClaims[i] != wantRequired[i] {
			t.Fatalf("required_claims=%v, want %v", cfg.IssuancePolicy.RequiredClaims, wantRequired)
		}
	}

	if v, ok := cfg.IssuancePolicy.RejectedClaims["impersonated"]; !ok {
		t.Fatal("expected rejected_claims to contain 'impersonated'")
	} else if v != true {
		t.Fatalf("rejected_claims[impersonated]=%v, want true", v)
	}
}

func TestIssuancePolicyBackwardCompat(t *testing.T) {
	const yaml = `
trust_domain: "test.example.com"
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

	if cfg.IssuancePolicy != nil {
		t.Fatalf("expected issuance_policy to be nil when not configured, got %+v", cfg.IssuancePolicy)
	}
}

func TestNewIssuancePolicy(t *testing.T) {
	t.Run("claim_assertions creates ClaimAssertionPolicy", func(t *testing.T) {
		policy, err := newIssuancePolicy(IssuancePolicyConfig{
			Type:           "claim_assertions",
			RequiredClaims: []string{"idp"},
			RejectedClaims: map[string]any{"impersonated": true},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := policy.(*service.ClaimAssertionPolicy); !ok {
			t.Fatalf("expected *ClaimAssertionPolicy, got %T", policy)
		}
	})

	t.Run("empty type errors", func(t *testing.T) {
		_, err := newIssuancePolicy(IssuancePolicyConfig{})
		if err == nil {
			t.Fatal("expected error for empty type")
		}
	})

	t.Run("unknown type errors", func(t *testing.T) {
		_, err := newIssuancePolicy(IssuancePolicyConfig{Type: "cel"})
		if err == nil {
			t.Fatal("expected error for unknown type")
		}
	})

	t.Run("claim_assertions with no constraints errors", func(t *testing.T) {
		_, err := newIssuancePolicy(IssuancePolicyConfig{Type: "claim_assertions"})
		if err == nil {
			t.Fatal("expected error for claim_assertions with no required or rejected claims")
		}
	})
}
