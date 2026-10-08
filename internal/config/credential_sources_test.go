package config

import (
	"context"
	"strings"
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
		{name: "basic_auth", cfg: CredentialSourceConfig{Name: "basic-auth", Type: "authorization_basic_auth"}, want: mustBasicAuthSource(t, "basic-auth")},
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
			case *server.BasicAuthCredentialSource:
				gotBasic, ok := got.(*server.BasicAuthCredentialSource)
				if !ok || gotBasic.SourceName != want.SourceName {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			}
		})
	}

	// match/strip are compiled inside the server package, so assert them
	// through Extract rather than by inspecting unexported state.
	t.Run("header match and strip reach the source", func(t *testing.T) {
		t.Parallel()
		noStrip := false
		got, err := newCredentialSource(CredentialSourceConfig{
			Name: "uhc-auth",
			Type: "header",
			Headers: []HeaderSpec{
				{Name: "authorization"},
				{Name: "user-agent", Match: "^.*-operator/.* cluster/.*", Strip: &noStrip},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ext, err := got.Extract(context.Background(), server.CredentialContext{Headers: map[string]string{
			"authorization": "Bearer ocm-token",
			"user-agent":    "curl/8.0.1",
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatal("expected the source to decline a non-matching user-agent")
		}

		ext, err = got.Extract(context.Background(), server.CredentialContext{Headers: map[string]string{
			"authorization": "Bearer ocm-token",
			"user-agent":    "insights-operator/abcdef cluster/1234321",
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext == nil {
			t.Fatal("expected extraction for a matching user-agent")
		}
		if len(ext.HeadersUsed) != 1 || ext.HeadersUsed[0] != "authorization" {
			t.Errorf("HeadersUsed=%v, want [authorization] only", ext.HeadersUsed)
		}
	})

	t.Run("invalid header match", func(t *testing.T) {
		t.Parallel()
		_, err := newCredentialSource(CredentialSourceConfig{
			Name:    "bad",
			Type:    "header",
			Headers: []HeaderSpec{{Name: "user-agent", Match: "([unclosed"}},
		})
		if err == nil {
			t.Fatal("expected error for an invalid match regex")
		}
	})

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
		_, err := newCredentialSource(CredentialSourceConfig{Name: "x", Type: "unknown_type"})
		if err == nil {
			t.Fatal("expected error for unknown type")
		}
		if !strings.Contains(err.Error(), "unknown type") {
			t.Fatalf("expected 'unknown type' error, got: %v", err)
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

func mustBasicAuthSource(t *testing.T, name string) *server.BasicAuthCredentialSource {
	t.Helper()
	src, err := server.NewBasicAuthCredentialSource(name)
	if err != nil {
		t.Fatalf("NewBasicAuthCredentialSource(%q): %v", name, err)
	}
	return src
}
