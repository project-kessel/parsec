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
		if ext.sourceType != "bearer" {
			t.Fatalf("expected bearer, got %q", ext.sourceType)
		}
		bearer, ok := ext.credential.(*trust.BearerCredential)
		if !ok {
			t.Fatalf("expected BearerCredential, got %T", ext.credential)
		}
		if bearer.Token != "jwt-token" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.headers) != 1 || ext.headers[0] != "authorization" {
			t.Fatalf("unexpected headers: %v", ext.headers)
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
		bearer := ext.credential.(*trust.BearerCredential)
		if bearer.Token != "jwt-token" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
	})

	t.Run("cookie", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{{Type: "cookie", Name: "cs_jwt"}}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"cookie": "session=abc; cs_jwt=cookie-jwt; other=1",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.sourceType != "cookie" {
			t.Fatalf("expected cookie, got %q", ext.sourceType)
		}
		bearer := ext.credential.(*trust.BearerCredential)
		if bearer.Token != "cookie-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.headers) != 0 {
			t.Fatalf("expected no header removals, got %v", ext.headers)
		}
		if ext.headerSets["cookie"] != "session=abc; other=1" {
			t.Fatalf("expected sanitized cookie header, got %q", ext.headerSets["cookie"])
		}
	})

	t.Run("cookie only credential is removed entirely", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{{Type: "cookie", Name: "cs_jwt"}}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ext.headers) != 1 || ext.headers[0] != "cookie" {
			t.Fatalf("expected cookie header removal, got %v", ext.headers)
		}
		if len(ext.headerSets) != 0 {
			t.Fatalf("expected no header overrides, got %v", ext.headerSets)
		}
	})

	t.Run("query", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{{Type: "query", Name: "token"}}
		ext, err := extractCredentialFromSources(makeReq(nil, "/api?token=query-jwt&foo=bar"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.sourceType != "query" {
			t.Fatalf("expected query, got %q", ext.sourceType)
		}
		bearer := ext.credential.(*trust.BearerCredential)
		if bearer.Token != "query-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.queryParamsToRemove) != 1 || ext.queryParamsToRemove[0] != "token" {
			t.Fatalf("expected token query param removal, got %v", ext.queryParamsToRemove)
		}
	})

	t.Run("cert from x-forwarded-client-cert", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{{Type: "cert"}}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"x-forwarded-client-cert": "By=spiffe://example/ns/default/sa/app;Hash=abc",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.sourceType != "cert" {
			t.Fatalf("expected cert, got %q", ext.sourceType)
		}
		bearer := ext.credential.(*trust.BearerCredential)
		if bearer.Token == "" {
			t.Fatal("expected cert material in credential")
		}
	})

	t.Run("first matching source wins", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{
			{Type: "bearer"},
			{Type: "cookie", Name: "cs_jwt"},
		}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"authorization": "Bearer header-jwt",
			"cookie":        "cs_jwt=cookie-jwt",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.sourceType != "bearer" {
			t.Fatalf("expected bearer first, got %q", ext.sourceType)
		}
		bearer := ext.credential.(*trust.BearerCredential)
		if bearer.Token != "header-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
	})

	t.Run("falls through to second source", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{
			{Type: "bearer"},
			{Type: "cookie", Name: "cs_jwt"},
		}
		ext, err := extractCredentialFromSources(makeReq(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}, "/"), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.sourceType != "cookie" {
			t.Fatalf("expected cookie, got %q", ext.sourceType)
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
	if len(srv.credentialSources) != 1 || srv.credentialSources[0].Type != "bearer" {
		t.Fatalf("expected default bearer source, got %+v", srv.credentialSources)
	}
}
