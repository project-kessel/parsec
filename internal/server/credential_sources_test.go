package server

import (
	"errors"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestExtractCredentialFromSources(t *testing.T) {
	t.Parallel()

	makeCC := func(headers map[string]string) CredentialContext {
		return CredentialContext{
			Headers: headers,
		}
	}

	t.Run("bearer from authorization header", func(t *testing.T) {
		t.Parallel()
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"authorization": "Bearer jwt-token",
		}), defaultCredentialSources())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != "bearer" {
			t.Fatalf("expected bearer, got %q", ext.SourceName)
		}
		bearer, ok := ext.Credential.(*trust.BearerCredential)
		if !ok {
			t.Fatalf("expected BearerCredential, got %T", ext.Credential)
		}
		if bearer.Token != "jwt-token" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.HeadersToRemove) != 1 || ext.HeadersToRemove[0] != "authorization" {
			t.Fatalf("unexpected headers: %v", ext.HeadersToRemove)
		}
	})

	t.Run("bearer scheme is case-insensitive", func(t *testing.T) {
		t.Parallel()
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"authorization": "bearer jwt-token",
		}), defaultCredentialSources())
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
		sources := []CredentialSource{NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt")}
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"cookie": "session=abc; cs_jwt=cookie-jwt; other=1",
		}), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != "cs-jwt-cookie" {
			t.Fatalf("expected cs-jwt-cookie, got %q", ext.SourceName)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "cookie-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.HeadersToRemove) != 0 {
			t.Fatalf("expected no header removals, got %v", ext.HeadersToRemove)
		}
		if ext.HeadersToSet["cookie"] != "session=abc; other=1" {
			t.Fatalf("expected sanitized cookie header, got %q", ext.HeadersToSet["cookie"])
		}
	})

	t.Run("cookie only credential is removed entirely", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt")}
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ext.HeadersToRemove) != 1 || ext.HeadersToRemove[0] != "cookie" {
			t.Fatalf("expected cookie header removal, got %v", ext.HeadersToRemove)
		}
		if len(ext.HeadersToSet) != 0 {
			t.Fatalf("expected no header overrides, got %v", ext.HeadersToSet)
		}
	})

	t.Run("first matching source wins", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{
			NewBearerCredentialSource("authorization-bearer"),
			NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"),
		}
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"authorization": "Bearer header-jwt",
			"cookie":        "cs_jwt=cookie-jwt",
		}), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != "authorization-bearer" {
			t.Fatalf("expected authorization-bearer first, got %q", ext.SourceName)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "header-jwt" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
	})

	t.Run("falls through to second source", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{
			NewBearerCredentialSource("authorization-bearer"),
			NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"),
		}
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != "cs-jwt-cookie" {
			t.Fatalf("expected cs-jwt-cookie, got %q", ext.SourceName)
		}
	})

	t.Run("empty sources returns error", func(t *testing.T) {
		t.Parallel()
		_, err := extractCredentialFromSources(makeCC(nil), nil)
		if err == nil {
			t.Fatal("expected error for empty sources")
		}
	})

	t.Run("no credentials found", func(t *testing.T) {
		t.Parallel()
		_, err := extractCredentialFromSources(makeCC(nil), defaultCredentialSources())
		if err == nil {
			t.Fatal("expected error when no credentials present")
		}
	})

	t.Run("cookie with quoted value", func(t *testing.T) {
		t.Parallel()
		sources := []CredentialSource{NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt")}
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"cookie": `session=abc; cs_jwt="quoted-jwt-token"; other=1`,
		}), sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "quoted-jwt-token" {
			t.Fatalf("expected quotes to be stripped, got %q", bearer.Token)
		}
	})

	t.Run("bearer with extra whitespace returns token with leading space", func(t *testing.T) {
		t.Parallel()
		ext, err := extractCredentialFromSources(makeCC(map[string]string{
			"authorization": "Bearer  extra-space-token",
		}), defaultCredentialSources())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		// strings.Cut splits on the first space only, so the leading space
		// remains in the token. This is safe: the malformed token will be
		// rejected during downstream JWT validation.
		if bearer.Token != " extra-space-token" {
			t.Fatalf("expected token with leading space, got %q", bearer.Token)
		}
	})

	t.Run("aggregates extraction errors from all sources", func(t *testing.T) {
		t.Parallel()
		err1 := errors.New("first source failed")
		err2 := errors.New("second source failed")
		sources := []CredentialSource{
			&stubErrCredentialSource{err: err1},
			&stubErrCredentialSource{err: err2},
		}
		_, err := extractCredentialFromSources(makeCC(nil), sources)
		if !errors.Is(err, err1) || !errors.Is(err, err2) {
			t.Fatalf("expected joined errors, got %v", err)
		}
	})
}

type stubErrCredentialSource struct {
	err error
}

func (s *stubErrCredentialSource) Extract(CredentialContext) (*CredentialExtraction, error) {
	return nil, s.err
}

func TestNewAuthzServer_defaultCredentialSources(t *testing.T) {
	t.Parallel()

	srv := NewAuthzServer(nil, nil, nil, nil)
	if len(srv.credentialSources) != 1 {
		t.Fatalf("expected one default subject source, got %d", len(srv.credentialSources))
	}
	if _, ok := srv.credentialSources[0].(*BearerCredentialSource); !ok {
		t.Fatalf("expected default bearer subject source, got %T", srv.credentialSources[0])
	}
	if len(srv.actorCredentialSources) != 1 {
		t.Fatalf("expected one default actor source, got %d", len(srv.actorCredentialSources))
	}
	if _, ok := srv.actorCredentialSources[0].(*BearerCredentialSource); !ok {
		t.Fatalf("expected default bearer actor source, got %T", srv.actorCredentialSources[0])
	}
}

func TestNewExchangeServer_defaultCredentialSources(t *testing.T) {
	t.Parallel()

	srv := NewExchangeServer(nil, nil, nil, nil)
	if len(srv.callerCredentialSources) != 1 {
		t.Fatalf("expected one default caller source, got %d", len(srv.callerCredentialSources))
	}
	if _, ok := srv.callerCredentialSources[0].(*BearerCredentialSource); !ok {
		t.Fatalf("expected default bearer caller source, got %T", srv.callerCredentialSources[0])
	}
}
