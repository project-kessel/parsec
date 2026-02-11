package config

import (
	"os"
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
	// Set some environment variables
	_ = os.Setenv("PARSEC_SERVER__GRPC_PORT", "19090")
	_ = os.Setenv("PARSEC_TRUST_DOMAIN", "env.test.com")
	defer func() {
		_ = os.Unsetenv("PARSEC_SERVER__GRPC_PORT")
		_ = os.Unsetenv("PARSEC_TRUST_DOMAIN")
	}()

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
