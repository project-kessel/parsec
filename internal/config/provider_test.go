package config

import (
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/server"
)

func TestProvider_CredentialSources(t *testing.T) {
	t.Parallel()

	valid := []CredentialSourceConfig{
		{Name: "authorization-bearer", Type: "bearer"},
		{Name: "cs-jwt-cookie", Type: "cookie", CookieName: "cs_jwt"},
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
			sources: []CredentialSourceConfig{{Type: "bearer"}},
			wantErr: "credential_sources[0]: name is required",
		},
		{
			name: "duplicate source name",
			sources: []CredentialSourceConfig{
				{Name: "bearer-a", Type: "bearer"},
				{Name: "bearer-a", Type: "bearer"},
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
			sources: []CredentialSourceConfig{{Name: "cookie", Type: "cookie"}},
			wantErr: `cookie_name is required for type "cookie"`,
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

func TestProvider_PerExtractionCredentialSources(t *testing.T) {
	t.Parallel()

	globalSources := []CredentialSourceConfig{
		{Name: "global-bearer", Type: "bearer"},
	}
	authzSubject := []CredentialSourceConfig{
		{Name: "subject-bearer", Type: "bearer"},
		{Name: "subject-cookie", Type: "cookie", CookieName: "cs_jwt"},
	}
	authzActor := []CredentialSourceConfig{
		{Name: "actor-bearer", Type: "bearer"},
	}
	exchangeActor := []CredentialSourceConfig{
		{Name: "exchange-bearer", Type: "bearer"},
	}

	t.Run("per-extraction overrides global for authz subject", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{
			CredentialSources: globalSources,
			AuthzServer:       &AuthzServerConfig{SubjectCredentialSources: authzSubject},
		})
		got, err := p.AuthzSubjectCredentialSources()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 sources, got %d", len(got))
		}
		if got[0].(*server.BearerCredentialSource).SourceName != "subject-bearer" {
			t.Fatalf("expected subject-bearer, got %s", got[0].(*server.BearerCredentialSource).SourceName)
		}
	})

	t.Run("authz subject falls back to global", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{
			CredentialSources: globalSources,
			AuthzServer:       &AuthzServerConfig{},
		})
		got, err := p.AuthzSubjectCredentialSources()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 source from global, got %d", len(got))
		}
		if got[0].(*server.BearerCredentialSource).SourceName != "global-bearer" {
			t.Fatalf("expected global-bearer, got %s", got[0].(*server.BearerCredentialSource).SourceName)
		}
	})

	t.Run("per-extraction overrides global for authz actor", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{
			CredentialSources: globalSources,
			AuthzServer:       &AuthzServerConfig{ActorCredentialSources: authzActor},
		})
		got, err := p.AuthzActorCredentialSources()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 source, got %d", len(got))
		}
		if got[0].(*server.BearerCredentialSource).SourceName != "actor-bearer" {
			t.Fatalf("expected actor-bearer, got %s", got[0].(*server.BearerCredentialSource).SourceName)
		}
	})

	t.Run("authz actor falls back to global", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{
			CredentialSources: globalSources,
		})
		got, err := p.AuthzActorCredentialSources()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 source from global, got %d", len(got))
		}
		if got[0].(*server.BearerCredentialSource).SourceName != "global-bearer" {
			t.Fatalf("expected global-bearer, got %s", got[0].(*server.BearerCredentialSource).SourceName)
		}
	})

	t.Run("per-extraction overrides global for exchange actor", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{
			CredentialSources: globalSources,
			ExchangeServer:    &ExchangeServerConfig{ActorCredentialSources: exchangeActor},
		})
		got, err := p.ExchangeActorCredentialSources()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 source, got %d", len(got))
		}
		if got[0].(*server.BearerCredentialSource).SourceName != "exchange-bearer" {
			t.Fatalf("expected exchange-bearer, got %s", got[0].(*server.BearerCredentialSource).SourceName)
		}
	})

	t.Run("exchange actor falls back to global", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{
			CredentialSources: globalSources,
			ExchangeServer:    &ExchangeServerConfig{},
		})
		got, err := p.ExchangeActorCredentialSources()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 source from global, got %d", len(got))
		}
		if got[0].(*server.BearerCredentialSource).SourceName != "global-bearer" {
			t.Fatalf("expected global-bearer, got %s", got[0].(*server.BearerCredentialSource).SourceName)
		}
	})

	t.Run("nil global and nil per-extraction returns nil", func(t *testing.T) {
		t.Parallel()
		p := NewProvider(&Config{})
		for _, fn := range []func() ([]server.CredentialSource, error){
			p.AuthzSubjectCredentialSources,
			p.AuthzActorCredentialSources,
			p.ExchangeActorCredentialSources,
		} {
			got, err := fn()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != nil {
				t.Fatalf("expected nil sources, got %+v", got)
			}
		}
	})
}
