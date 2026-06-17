package config

import (
	"strings"
	"testing"
)

func TestProvider_CredentialSources(t *testing.T) {
	t.Parallel()

	valid := []CredentialSourceConfig{
		{Name: "authorization-bearer", Type: "authorization_bearer_opaque"},
		{Name: "cs-jwt-cookie", Type: "cookie_bearer_opaque", CookieName: "cs_jwt"},
	}

	tests := []struct {
		name    string
		sources []CredentialSourceConfig
		wantErr string
	}{
		{
			name:    "nil credential sources",
			sources: nil,
		},
		{
			name:    "valid sources",
			sources: valid,
		},
		{
			name:    "missing source name",
			sources: []CredentialSourceConfig{{Type: "authorization_bearer_opaque"}},
			wantErr: "credential_sources[0]: name is required",
		},
		{
			name: "duplicate source name",
			sources: []CredentialSourceConfig{
				{Name: "bearer-a", Type: "authorization_bearer_opaque"},
				{Name: "bearer-a", Type: "authorization_bearer_opaque"},
			},
			wantErr: "duplicate credential source name: bearer-a",
		},
		{
			name:    "missing type",
			sources: []CredentialSourceConfig{{Name: "x"}},
			wantErr: "credential_sources[0]: type is required",
		},
		{
			name:    "unknown type",
			sources: []CredentialSourceConfig{{Name: "x", Type: "header"}},
			wantErr: `unknown type "header"`,
		},
		{
			name:    "cookie without cookie_name",
			sources: []CredentialSourceConfig{{Name: "cookie", Type: "cookie_bearer_opaque"}},
			wantErr: `cookie_name is required for type "cookie_bearer_opaque"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := NewProvider(&Config{CredentialSources: tt.sources})

			got, err := p.CredentialSources()
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
			if tt.name == "nil credential sources" {
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
