package server

import (
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestExtractCredentialFromSources(t *testing.T) {
	t.Parallel()

	makeReq := func(headers map[string]string, path string) *authv3.CheckRequest {
		return &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Headers: headers,
						Path:    path,
					},
				},
			},
		}
	}

	t.Run("bearer from authorization header", func(t *testing.T) {
		t.Parallel()
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"authorization": "Bearer jwt-token",
		}, "/"), defaultCredentialSources())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceType != "bearer" {
			t.Fatalf("expected bearer, got %q", ext.SourceType)
		}
		bearer, ok := ext.Credential.(*trust.BearerCredential)
		if !ok {
			t.Fatalf("expected BearerCredential, got %T", ext.Credential)
		}
		if bearer.Token != "jwt-token" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.Headers) != 1 || ext.Headers[0] != "authorization" {
			t.Fatalf("unexpected headers: %v", ext.Headers)
		}
	})

	t.Run("bearer scheme is case-insensitive", func(t *testing.T) {
		t.Parallel()
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"authorization": "bearer jwt-token",
		}, "/"), defaultCredentialSources())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "jwt-token" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
	})

	t.Run("cookie", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{&CookieCredentialSource{Name: "cs_jwt"}}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"cookie": "session=abc; cs_jwt=cookie-jwt; other=1",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceType != "cookie" {
			t.Fatalf("expected cookie, got %q", ext.SourceType)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "cookie-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.Headers) != 0 {
			t.Fatalf("expected no header removals, got %v", ext.Headers)
		}
		if ext.HeaderSets["cookie"] != "session=abc; other=1" {
			t.Fatalf("expected sanitized cookie header, got %q", ext.HeaderSets["cookie"])
		}
	})

	t.Run("cookie only credential is removed entirely", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{&CookieCredentialSource{Name: "cs_jwt"}}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ext.Headers) != 1 || ext.Headers[0] != "cookie" {
			t.Fatalf("expected cookie header removal, got %v", ext.Headers)
		}
		if len(ext.HeaderSets) != 0 {
			t.Fatalf("expected no header overrides, got %v", ext.HeaderSets)
		}
	})

	t.Run("query", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{&QueryCredentialSource{Param: "token"}}
		ext, err := extractCredentialFromSources(makeReq(nil, "/api?token=query-jwt&foo=bar"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceType != "query" {
			t.Fatalf("expected query, got %q", ext.SourceType)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "query-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.QueryParamsToRemove) != 1 || ext.QueryParamsToRemove[0] != "token" {
			t.Fatalf("expected token query param removal, got %v", ext.QueryParamsToRemove)
		}
	})

	t.Run("cert from x-forwarded-client-cert", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{&CertCredentialSource{Header: "x-forwarded-client-cert"}}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"x-forwarded-client-cert": "By=spiffe://example/ns/default/sa/app;Hash=abc",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceType != "cert" {
			t.Fatalf("expected cert, got %q", ext.SourceType)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token == "" {
			t.Fatal("expected cert material in credential")
		}
	})

	t.Run("cert does not fall back to x-rh-certauth-cn", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{&CertCredentialSource{Header: "x-forwarded-client-cert"}}
		_, err := extractCredentialFromSources(makeReq(map[string]string{
			"x-rh-certauth-cn": "must-not-use",
		}, "/"), sources)
		if err == nil {
			t.Fatal("expected error when configured cert header is absent")
		}
	})

	t.Run("first matching source wins", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{
			&BearerCredentialSource{},
			&CookieCredentialSource{Name: "cs_jwt"},
		}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"authorization": "Bearer header-jwt",
			"cookie":        "cs_jwt=cookie-jwt",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceType != "bearer" {
			t.Fatalf("expected bearer first, got %q", ext.SourceType)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "header-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
	})

	t.Run("falls through to second source", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{
			&BearerCredentialSource{},
			&CookieCredentialSource{Name: "cs_jwt"},
		}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceType != "cookie" {
			t.Fatalf("expected cookie, got %q", ext.SourceType)
		}
	})

	t.Run("no credentials found", func(t *testing.T) {
		t.Parallel()
		_, err := extractCredentialFromSources(makeReq(nil, "/"), defaultCredentialSources())
		if err == nil {
			t.Fatal("expected error when no credentials present")
		}
	})
}

func TestNewAuthzServer_defaultCredentialSources(t *testing.T) {
	t.Parallel()

	srv := NewAuthzServer(nil, nil, nil, nil)
	if len(srv.credentialSources) != 1 {
		t.Fatalf("expected one default source, got %d", len(srv.credentialSources))
	}
	if _, ok := srv.credentialSources[0].(*BearerCredentialSource); !ok {
		t.Fatalf("expected default bearer source, got %T", srv.credentialSources[0])
	}
}

func TestNewCredentialSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec CredentialSourceSpec
		want CredentialSource
	}{
		{name: "bearer", spec: CredentialSourceSpec{Type: CredentialSourceTypeBearer}, want: &BearerCredentialSource{}},
		{name: "cookie", spec: CredentialSourceSpec{Type: CredentialSourceTypeCookie, Name: "cs_jwt"}, want: &CookieCredentialSource{Name: "cs_jwt"}},
		{name: "query", spec: CredentialSourceSpec{Type: CredentialSourceTypeQuery, Name: "token"}, want: &QueryCredentialSource{Param: "token"}},
		{name: "cert", spec: CredentialSourceSpec{Type: CredentialSourceTypeCert, Header: "x-forwarded-client-cert"}, want: &CertCredentialSource{Header: "x-forwarded-client-cert"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewCredentialSource(tt.spec)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch want := tt.want.(type) {
			case *BearerCredentialSource:
				if _, ok := got.(*BearerCredentialSource); !ok {
					t.Fatalf("got %T, want *BearerCredentialSource", got)
				}
			case *CookieCredentialSource:
				gotCookie, ok := got.(*CookieCredentialSource)
				if !ok || gotCookie.Name != want.Name {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			case *QueryCredentialSource:
				gotQuery, ok := got.(*QueryCredentialSource)
				if !ok || gotQuery.Param != want.Param {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			case *CertCredentialSource:
				gotCert, ok := got.(*CertCredentialSource)
				if !ok || gotCert.Header != want.Header {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			}
		})
	}

	t.Run("missing type", func(t *testing.T) {
		t.Parallel()
		_, err := NewCredentialSource(CredentialSourceSpec{})
		if err == nil {
			t.Fatal("expected error for missing type")
		}
	})

	t.Run("cookie without name", func(t *testing.T) {
		t.Parallel()
		_, err := NewCredentialSource(CredentialSourceSpec{Type: CredentialSourceTypeCookie})
		if err == nil {
			t.Fatal("expected error for cookie without name")
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, err := NewCredentialSource(CredentialSourceSpec{Type: "header"})
		if err == nil {
			t.Fatal("expected error for unknown type")
		}
	})
}
