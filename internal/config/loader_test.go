package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewLoader_WithoutConfigFile(t *testing.T) {
	// Test that loader works with empty config path (no file)
	loader, err := NewLoader("")
	if err != nil {
		t.Fatalf("Expected loader to work without config file, got error: %v", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("Expected to get config without config file, got error: %v", err)
	}

	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}

	// Verify defaults are applied
	if cfg.Server.GRPCPort != 9090 {
		t.Errorf("Expected default GRPC port 9090, got %d", cfg.Server.GRPCPort)
	}
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("Expected default HTTP port 8080, got %d", cfg.Server.HTTPPort)
	}
	if cfg.TrustDomain != "parsec.local" {
		t.Errorf("Expected default trust domain 'parsec.local', got '%s'", cfg.TrustDomain)
	}
	if cfg.TrustStore.Type != "stub_store" {
		t.Errorf("Expected default trust store type 'stub_store', got '%s'", cfg.TrustStore.Type)
	}
}

func TestNewLoader_WithEnvironmentVariables(t *testing.T) {
	t.Setenv("PARSEC_SERVER__GRPC_PORT", "19090")
	t.Setenv("PARSEC_TRUST_DOMAIN", "env.test.com")

	// Create loader without config file
	loader, err := NewLoader("")
	if err != nil {
		t.Fatalf("Expected loader to work without config file, got error: %v", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("Expected to get config, got error: %v", err)
	}

	// Verify environment variables override defaults
	if cfg.Server.GRPCPort != 19090 {
		t.Errorf("Expected GRPC port 19090 from env, got %d", cfg.Server.GRPCPort)
	}
	if cfg.TrustDomain != "env.test.com" {
		t.Errorf("Expected trust domain 'env.test.com' from env, got '%s'", cfg.TrustDomain)
	}
	// Verify other defaults still apply
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("Expected default HTTP port 8080, got %d", cfg.Server.HTTPPort)
	}
	if cfg.TrustStore.Type != "stub_store" {
		t.Errorf("Expected default trust store type 'stub_store', got '%s'", cfg.TrustStore.Type)
	}
}

// TestNewLoader_InlineHTTPKey verifies that the "http" key (chosen for
// readability, and because it happens to match the shape of the fields
// supported by the removed legacy http config) unmarshals into a data
// source's or validator's HTTPClientSpec.
func TestNewLoader_EnvOverrideIndexedDataSourceConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "parsec.yaml")
	const yamlConfig = `
data_sources:
  - name: identity-policy
    type: static
    data:
      enforce_idp_auth: false
  - name: other
    type: static
    data: {}
  - name: export_compliance
    type: lua
    script: "function fetch(input) return {data='{}'} end"
    config:
      compliance_api: "https://example.invalid/compliance"
`
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	t.Setenv("PARSEC_DATA_SOURCES__2__CONFIG__COMPLIANCE_API", "http://127.0.0.1:9099/v1/compliance")

	loader, err := NewLoader(configPath)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("loader.Get(): %v", err)
	}

	if len(cfg.DataSources) != 3 {
		t.Fatalf("len(DataSources) = %d, want 3", len(cfg.DataSources))
	}
	for i, ds := range cfg.DataSources {
		if ds.Name == "" || ds.Type == "" {
			t.Errorf("DataSources[%d] is empty: name=%q type=%q", i, ds.Name, ds.Type)
		}
	}
	got := ""
	if cfg.DataSources[2].Config != nil {
		if v, ok := cfg.DataSources[2].Config["compliance_api"]; ok {
			got, _ = v.(string)
		}
	}
	if got != "http://127.0.0.1:9099/v1/compliance" {
		t.Errorf("DataSources[2].Config[compliance_api] = %q, want local mock URL", got)
	}
	if cfg.DataSources[0].Name != "identity-policy" || cfg.DataSources[0].Type != "static" {
		t.Errorf("DataSources[0] = {%q %q}, want identity-policy/static", cfg.DataSources[0].Name, cfg.DataSources[0].Type)
	}
}

func TestNewLoader_InlineHTTPKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "parsec.yaml")
	const yamlConfig = `
data_sources:
  - name: example
    type: static
    data: {}
    http:
      timeout: "12s"

trust_store:
  type: stub_store
  validators:
    - name: example-validator
      type: stub_validator
      http:
        timeout: "34s"
`
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	loader, err := NewLoader(configPath)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("loader.Get(): %v", err)
	}

	if len(cfg.DataSources) != 1 {
		t.Fatalf("len(DataSources) = %d, want 1", len(cfg.DataSources))
	}
	dsSpec := cfg.DataSources[0].HTTPClientSpec
	if dsSpec == nil {
		t.Fatal("DataSources[0].HTTPClientSpec is nil, want it populated from the \"http\" key")
	}
	if dsSpec.Timeout != "12s" {
		t.Errorf("DataSources[0].HTTPClientSpec.Timeout = %q, want %q", dsSpec.Timeout, "12s")
	}

	if len(cfg.TrustStore.Validators) != 1 {
		t.Fatalf("len(Validators) = %d, want 1", len(cfg.TrustStore.Validators))
	}
	validatorSpec := cfg.TrustStore.Validators[0].HTTPClientSpec
	if validatorSpec == nil {
		t.Fatal("Validators[0].HTTPClientSpec is nil, want it populated from the \"http\" key")
	}
	if validatorSpec.Timeout != "34s" {
		t.Errorf("Validators[0].HTTPClientSpec.Timeout = %q, want %q", validatorSpec.Timeout, "34s")
	}
}

func TestNewLoader_HTTPClientBaseURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "parsec.yaml")
	const yamlConfig = `
http_clients:
  - name: entitlements
    timeout: "5s"
    base_url: "https://entitlements.internal.example.com"
`
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	loader, err := NewLoader(configPath)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("loader.Get(): %v", err)
	}

	if len(cfg.HTTPClients) != 1 {
		t.Fatalf("len(HTTPClients) = %d, want 1", len(cfg.HTTPClients))
	}
	got := cfg.HTTPClients[0].BaseURL
	if got != "https://entitlements.internal.example.com" {
		t.Errorf("HTTPClients[0].BaseURL = %q, want origin-form entitlements host", got)
	}
}

func TestNewLoader_EnvOverrideHTTPClientBaseURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "parsec.yaml")
	const yamlConfig = `
http_clients:
  - name: entitlements
    timeout: "5s"
    base_url: "https://placeholder.example"
`
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	t.Setenv("PARSEC_HTTP_CLIENTS__0__BASE_URL", "https://entitlements.stage.example")

	loader, err := NewLoader(configPath)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("loader.Get(): %v", err)
	}

	if len(cfg.HTTPClients) != 1 {
		t.Fatalf("len(HTTPClients) = %d, want 1", len(cfg.HTTPClients))
	}
	got := cfg.HTTPClients[0].BaseURL
	if got != "https://entitlements.stage.example" {
		t.Errorf("HTTPClients[0].BaseURL = %q, want env overlay value", got)
	}
}
