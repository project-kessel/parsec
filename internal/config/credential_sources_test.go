package config

import (
	"testing"

	"github.com/project-kessel/parsec/internal/server"
)

func Test_newCredentialSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  CredentialSourceConfig
		want server.CredentialSource
	}{
		{name: "bearer", cfg: CredentialSourceConfig{Name: "authorization-bearer", Type: "authorization_bearer_opaque"}, want: server.NewBearerCredentialSource("authorization-bearer")},
		{name: "cookie", cfg: CredentialSourceConfig{Name: "cs-jwt-cookie", Type: "cookie_bearer_opaque", CookieName: "cs_jwt"}, want: server.NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := newCredentialSource(tt.cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch want := tt.want.(type) {
			case *server.BearerCredentialSource:
				gotBearer, ok := got.(*server.BearerCredentialSource)
				if !ok || gotBearer.SourceName != want.SourceName {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			case *server.CookieCredentialSource:
				gotCookie, ok := got.(*server.CookieCredentialSource)
				if !ok || gotCookie.SourceName != want.SourceName || gotCookie.CookieName != want.CookieName {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			}
		})
	}

	t.Run("missing name", func(t *testing.T) {
		t.Parallel()
		_, err := newCredentialSource(CredentialSourceConfig{Type: "authorization_bearer_opaque"})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
	})

	t.Run("missing type", func(t *testing.T) {
		t.Parallel()
		_, err := newCredentialSource(CredentialSourceConfig{Name: "x"})
		if err == nil {
			t.Fatal("expected error for missing type")
		}
	})

	t.Run("cookie without cookie_name", func(t *testing.T) {
		t.Parallel()
		_, err := newCredentialSource(CredentialSourceConfig{Name: "cookie", Type: "cookie_bearer_opaque"})
		if err == nil {
			t.Fatal("expected error for cookie without cookie_name")
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, err := newCredentialSource(CredentialSourceConfig{Name: "x", Type: "header"})
		if err == nil {
			t.Fatal("expected error for unknown type")
		}
	})
}
