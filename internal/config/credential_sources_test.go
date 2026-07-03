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
		{name: "bearer", cfg: CredentialSourceConfig{Name: "authorization-bearer", Type: "authorization_bearer_opaque"}, want: mustBearerSource(t, "authorization-bearer")},
		{name: "cookie", cfg: CredentialSourceConfig{Name: "cs-jwt-cookie", Type: "cookie_bearer_opaque", CookieName: "cs_jwt"}, want: mustCookieSource(t, "cs-jwt-cookie", "cs_jwt")},
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

func mustBearerSource(t *testing.T, name string) *server.BearerCredentialSource {
	t.Helper()
	src, err := server.NewBearerCredentialSource(name)
	if err != nil {
		t.Fatalf("NewBearerCredentialSource(%q): %v", name, err)
	}
	return src
}

func mustCookieSource(t *testing.T, name, cookieName string) *server.CookieCredentialSource {
	t.Helper()
	src, err := server.NewCookieCredentialSource(name, cookieName)
	if err != nil {
		t.Fatalf("NewCookieCredentialSource(%q, %q): %v", name, cookieName, err)
	}
	return src
}
