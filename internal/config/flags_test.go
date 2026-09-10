package config

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestBuildFlagMapping(t *testing.T) {
	mapping, fields := buildFlagMapping()

	// Test some expected mappings
	tests := []struct {
		flagName   string
		configPath string
	}{
		{"server-grpc-port", "server.grpc_port"},
		{"server-http-port", "server.http_port"},
		{"trust-domain", "trust_domain"},
		{"trust-store-type", "trust_store.type"},
		{"observability-type", "observability.type"},
		{"observability-log-level", "observability.log_level"},
		{"observability-log-format", "observability.log_format"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			got, ok := mapping[tt.flagName]
			if !ok {
				t.Errorf("flag %q not found in mapping", tt.flagName)
				return
			}
			if got != tt.configPath {
				t.Errorf("mapping[%q] = %q, want %q", tt.flagName, got, tt.configPath)
			}
		})
	}

	// Verify we have a reasonable number of fields
	if len(fields) < 5 {
		t.Errorf("expected at least 5 fields, got %d", len(fields))
	}
}

func TestConfigPathToFlagName(t *testing.T) {
	tests := []struct {
		configPath string
		want       string
	}{
		{"server.grpc_port", "server-grpc-port"},
		{"trust_domain", "trust-domain"},
		{"observability.log_level", "observability-log-level"},
		{"trust_store.type", "trust-store-type"},
	}

	for _, tt := range tests {
		t.Run(tt.configPath, func(t *testing.T) {
			got := configPathToFlagName(tt.configPath)
			if got != tt.want {
				t.Errorf("configPathToFlagName(%q) = %q, want %q", tt.configPath, got, tt.want)
			}
		})
	}
}

func TestRegisterFlags(t *testing.T) {
	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)

	// Register all flags
	RegisterFlags(flagSet)

	// Verify some expected flags exist with usage strings
	expectedFlags := []struct {
		name  string
		usage string
	}{
		{"server-grpc-port", "gRPC server port (ext_authz, token exchange)"},
		{"server-http-port", "HTTP server port (gRPC-gateway transcoding)"},
		{"trust-domain", "trust domain for issued tokens (audience claim)"},
		{"trust-store-type", "trust store type: stub_store, filtered_store"},
		{"observability-type", "observer type: audit, logging, noop, metrics, composite"},
	}

	for _, tt := range expectedFlags {
		t.Run(tt.name, func(t *testing.T) {
			flag := flagSet.Lookup(tt.name)
			if flag == nil {
				t.Errorf("flag %q not registered", tt.name)
				return
			}
			if flag.Usage != tt.usage {
				t.Errorf("flag %q usage = %q, want %q", tt.name, flag.Usage, tt.usage)
			}
		})
	}
}

func TestGetFlagMapping(t *testing.T) {
	mapping := GetFlagMapping()

	// Verify it's not empty
	if len(mapping) == 0 {
		t.Error("GetFlagMapping() returned empty map")
	}

	// Verify a few known mappings exist
	if _, ok := mapping["server-grpc-port"]; !ok {
		t.Error("mapping missing server-grpc-port")
	}
	if _, ok := mapping["trust-domain"]; !ok {
		t.Error("mapping missing trust-domain")
	}
}
