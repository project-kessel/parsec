package server

import (
	"context"
	"errors"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func mustBearerSource(t *testing.T, name string) *BearerCredentialSource {
	t.Helper()
	src, err := NewBearerCredentialSource(name)
	if err != nil {
		t.Fatalf("NewBearerCredentialSource(%q): %v", name, err)
	}
	return src
}

func mustCookieSource(t *testing.T, name, cookieName string) *CookieCredentialSource {
	t.Helper()
	src, err := NewCookieCredentialSource(name, cookieName)
	if err != nil {
		t.Fatalf("NewCookieCredentialSource(%q, %q): %v", name, cookieName, err)
	}
	return src
}

func TestCredentialSources_Extract(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	makeCC := func(t *testing.T, headers map[string]string) CredentialContext {
		t.Helper()
		cookies, err := parseCookies(headers["cookie"])
		if err != nil {
			t.Fatalf("parseCookies: %v", err)
		}
		return CredentialContext{
			Headers: headers,
			Cookies: cookies,
		}
	}

	t.Run("bearer from authorization header", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"authorization": "Bearer jwt-token",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != "authorization_bearer_opaque" {
			t.Fatalf("expected authorization_bearer_opaque, got %q", ext.SourceName)
		}
		bearer, ok := ext.Credential.(*trust.BearerCredential)
		if !ok {
			t.Fatalf("expected BearerCredential, got %T", ext.Credential)
		}
		if bearer.Token != "jwt-token" {
			t.Fatalf("unexpected token: %q", bearer.Token)
		}
		if len(ext.HeadersUsed) != 1 || ext.HeadersUsed[0] != "authorization" {
			t.Fatalf("unexpected headers: %v", ext.HeadersUsed)
		}
	})

	t.Run("bearer scheme is case-insensitive", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"authorization": "bearer jwt-token",
		}))
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
		sources := NewCredentialSources(mustCookieSource(t, "cs-jwt-cookie", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": "session=abc; cs_jwt=cookie-jwt; other=1",
		}))
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
		if len(ext.CookiesUsed) != 1 || ext.CookiesUsed[0] != "cs_jwt" {
			t.Fatalf("expected CookiesUsed=[cs_jwt], got %v", ext.CookiesUsed)
		}
	})

	t.Run("cookie only credential reports cookie used", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "cs-jwt-cookie", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ext.CookiesUsed) != 1 || ext.CookiesUsed[0] != "cs_jwt" {
			t.Fatalf("expected CookiesUsed=[cs_jwt], got %v", ext.CookiesUsed)
		}
		if len(ext.HeadersUsed) != 0 {
			t.Fatalf("expected no HeadersUsed (response builder handles cookie header), got %v", ext.HeadersUsed)
		}
	})

	t.Run("first matching source wins", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(
			mustBearerSource(t, "authorization-bearer"),
			mustCookieSource(t, "cs-jwt-cookie", "cs_jwt"),
		)
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"authorization": "Bearer header-jwt",
			"cookie":        "cs_jwt=cookie-jwt",
		}))
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
		sources := NewCredentialSources(
			mustBearerSource(t, "authorization-bearer"),
			mustCookieSource(t, "cs-jwt-cookie", "cs_jwt"),
		)
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != "cs-jwt-cookie" {
			t.Fatalf("expected cs-jwt-cookie, got %q", ext.SourceName)
		}
	})

	t.Run("empty sources returns error", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources()
		_, err := sources.Extract(ctx, makeCC(t, nil))
		if err == nil {
			t.Fatal("expected error for empty sources")
		}
	})

	t.Run("no credentials returns nil", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		ext, err := sources.Extract(ctx, makeCC(t, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatalf("expected nil extraction, got %+v", ext)
		}
	})

	t.Run("cookie with quoted value", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "cs-jwt-cookie", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": `session=abc; cs_jwt="quoted-jwt-token"; other=1`,
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "quoted-jwt-token" {
			t.Fatalf("expected quotes to be stripped, got %q", bearer.Token)
		}
	})

	t.Run("bearer with extra whitespace trims token", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"authorization": "Bearer  extra-space-token",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bearer := ext.Credential.(*trust.BearerCredential)
		if bearer.Token != "extra-space-token" {
			t.Fatalf("expected trimmed token, got %q", bearer.Token)
		}
	})

	t.Run("cookie source errors when name is empty", func(t *testing.T) {
		t.Parallel()
		_, err := NewCookieCredentialSource("", "session_tok")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("cookie source errors when cookie_name is empty", func(t *testing.T) {
		t.Parallel()
		_, err := NewCookieCredentialSource("my-source", "")
		if err == nil {
			t.Fatal("expected error for empty cookie_name")
		}
	})

	t.Run("cookie source returns nil when named cookie is absent", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "c", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": "session=abc; other=1",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatalf("expected nil extraction when named cookie absent, got %+v", ext)
		}
	})

	t.Run("cookie source errors when cookie value is empty", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "c", "cs_jwt"))
		_, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": "cs_jwt=",
		}))
		if err == nil {
			t.Fatal("expected error for empty cookie value")
		}
	})

	t.Run("cookie source errors when cookie value is only quotes", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "c", "cs_jwt"))
		_, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": `cs_jwt=""`,
		}))
		if err == nil {
			t.Fatal("expected error for quoted-empty cookie value")
		}
	})

	t.Run("cookie source errors on duplicate cookie name", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "c", "cs_jwt"))
		_, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"cookie": "cs_jwt=first; cs_jwt=second",
		}))
		if err == nil {
			t.Fatal("expected error for duplicate cookie name")
		}
	})

	t.Run("cookie source returns nil when no cookie header", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustCookieSource(t, "c", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(t, map[string]string{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatalf("expected nil extraction when cookie header absent, got %+v", ext)
		}
	})

	t.Run("bearer source errors on non-bearer scheme", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustBearerSource(t, "bearer"))
		_, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"authorization": "Basic dXNlcjpwYXNz",
		}))
		if err == nil {
			t.Fatal("expected error for non-bearer scheme")
		}
	})

	t.Run("bearer source errors on empty token after scheme", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(mustBearerSource(t, "bearer"))
		_, err := sources.Extract(ctx, makeCC(t, map[string]string{
			"authorization": "Bearer ",
		}))
		if err == nil {
			t.Fatal("expected error for empty bearer token")
		}
	})

	t.Run("bearer source errors when name is empty", func(t *testing.T) {
		t.Parallel()
		_, err := NewBearerCredentialSource("")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("aggregates extraction errors from all sources", func(t *testing.T) {
		t.Parallel()
		err1 := errors.New("first source failed")
		err2 := errors.New("second source failed")
		sources := NewCredentialSources(
			&stubErrCredentialSource{err: err1},
			&stubErrCredentialSource{err: err2},
		)
		_, err := sources.Extract(ctx, makeCC(t, nil))
		if !errors.Is(err, err1) || !errors.Is(err, err2) {
			t.Fatalf("expected joined errors, got %v", err)
		}
	})
}

type stubErrCredentialSource struct {
	err error
}

func (s *stubErrCredentialSource) Extract(context.Context, CredentialContext) (*CredentialExtraction, error) {
	return nil, s.err
}

func TestNewAuthzServer_credentialSources(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := NewAuthzServer(nil, nil, nil, DefaultCredentialSources(), nil)

	ext, err := srv.credentialSources.Extract(ctx, CredentialContext{
		Headers: map[string]string{"authorization": "Bearer test-token"},
	})
	if err != nil {
		t.Fatalf("credential sources failed to extract: %v", err)
	}
	bearer, ok := ext.Credential.(*trust.BearerCredential)
	if !ok {
		t.Fatalf("expected BearerCredential, got %T", ext.Credential)
	}
	if bearer.Token != "test-token" {
		t.Fatalf("unexpected token: %q", bearer.Token)
	}
}

func TestNewExchangeServer_callerCredentialSources(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := NewExchangeServer(nil, nil, nil, DefaultCredentialSources(), nil)

	ext, err := srv.callerCredentialSources.Extract(ctx, CredentialContext{
		Headers: map[string]string{"authorization": "Bearer caller-token"},
	})
	if err != nil {
		t.Fatalf("caller sources failed to extract: %v", err)
	}
	bearer, ok := ext.Credential.(*trust.BearerCredential)
	if !ok {
		t.Fatalf("expected BearerCredential from caller source, got %T", ext.Credential)
	}
	if bearer.Token != "caller-token" {
		t.Fatalf("unexpected token: %q", bearer.Token)
	}
}
