package config

import (
	"strings"
	"testing"
)

func TestProvider_AuthzServerCredentialSources(t *testing.T) {
	t.Parallel()

	valid := []CredentialSourceConfig{
		{Type: "bearer"},
		{Type: "cookie", Name: "cs_jwt"},
		{Type: "cert", Header: "x-forwarded-client-cert"},
		{Type: "query", Name: "token"},
	}

	tests := []struct {
		name    string
		sources []CredentialSourceConfig
		wantErr string
	}{
		{
			name:    "nil authz server",
			sources: nil,
		},
		{
			name:    "valid sources",
			sources: valid,
		},
		{
			name:    "missing type",
			sources: []CredentialSourceConfig{{Name: "x"}},
			wantErr: "credential_sources[0]: type is required",
		},
		{
			name:    "unknown type",
			sources: []CredentialSourceConfig{{Type: "header"}},
			wantErr: `unknown type "header"`,
		},
		{
			name:    "cookie without name",
			sources: []CredentialSourceConfig{{Type: "cookie"}},
			wantErr: `name is required for type "cookie"`,
		},
		{
			name:    "query without name",
			sources: []CredentialSourceConfig{{Type: "query"}},
			wantErr: `name is required for type "query"`,
		},
		{
			name:    "cert without header",
			sources: []CredentialSourceConfig{{Type: "cert"}},
			wantErr: `header is required for type "cert"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var authz *AuthzServerConfig
			if tt.sources != nil || tt.name != "nil authz server" {
				authz = &AuthzServerConfig{CredentialSources: tt.sources}
			}
			p := NewProvider(&Config{AuthzServer: authz})

			got, err := p.AuthzServerCredentialSources()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.name == "nil authz server" {
				if got != nil {
					t.Fatalf("expected nil sources, got %+v", got)
				}
				return
			}
			if len(got) != len(tt.sources) {
				t.Fatalf("got %d sources, want %d", len(got), len(tt.sources))
			}
		})
	}
}
