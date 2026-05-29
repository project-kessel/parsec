package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/project-kessel/parsec/internal/server"
)

func TestAuthzServerScopePolicyFromYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := `
authz_server:
  scope:
    default: "api.read api.write"
    by_trust_domain:
      "customer.example.com": "customer:access"
    from_request:
      header: "x-oauth-scope"
      query_param: "scope"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loader, err := NewLoader(configPath)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("loader.Get: %v", err)
	}

	if cfg.AuthzServer == nil || cfg.AuthzServer.Scope == nil {
		t.Fatal("expected authz_server.scope config")
	}

	provider := NewProvider(cfg)
	policy, err := provider.AuthzServerScopePolicy()
	if err != nil {
		t.Fatalf("AuthzServerScopePolicy: %v", err)
	}

	resolved := policy.Resolve(nil, nil)
	if resolved.Source != server.ScopeSourceDefault {
		t.Fatalf("Source = %v, want Default", resolved.Source)
	}
	if resolved.Scope.String() != "api.read api.write" {
		t.Fatalf("Scope = %q, want api.read api.write", resolved.Scope.String())
	}
}

func TestAuthzServerScopePolicy_rejectsInvalidConfig(t *testing.T) {
	provider := NewProvider(&Config{
		AuthzServer: &AuthzServerConfig{
			Scope: &ScopeConfig{
				Default: "   ",
			},
		},
	})

	if _, err := provider.AuthzServerScopePolicy(); err == nil {
		t.Fatal("expected error for whitespace default scope")
	}
}
