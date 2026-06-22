package server

import (
	"context"
	"errors"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestCredentialSources_Extract(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	makeCC := func(headers map[string]string) CredentialContext {
		return CredentialContext{
			Headers: headers,
		}
	}

	t.Run("bearer from authorization header", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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
		if len(ext.HeadersToRemove) != 1 || ext.HeadersToRemove[0] != "authorization" {
			t.Fatalf("unexpected headers: %v", ext.HeadersToRemove)
		}
	})

	t.Run("bearer scheme is case-insensitive", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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
		sources := NewCredentialSources(NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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
		if len(ext.HeadersToRemove) != 0 {
			t.Fatalf("expected no header removals, got %v", ext.HeadersToRemove)
		}
		if ext.HeadersToSet["cookie"] != "session=abc; other=1" {
			t.Fatalf("expected sanitized cookie header, got %q", ext.HeadersToSet["cookie"])
		}
	})

	t.Run("cookie only credential is removed entirely", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
			"cookie": "cs_jwt=cookie-jwt",
		}))
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
		sources := NewCredentialSources(
			NewBearerCredentialSource("authorization-bearer"),
			NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"),
		)
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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
			NewBearerCredentialSource("authorization-bearer"),
			NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"),
		)
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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
		_, err := sources.Extract(ctx, makeCC(nil))
		if err == nil {
			t.Fatal("expected error for empty sources")
		}
	})

	t.Run("no credentials found", func(t *testing.T) {
		t.Parallel()
		sources := DefaultCredentialSources()
		_, err := sources.Extract(ctx, makeCC(nil))
		if err == nil {
			t.Fatal("expected error when no credentials present")
		}
	})

	t.Run("cookie with quoted value", func(t *testing.T) {
		t.Parallel()
		sources := NewCredentialSources(NewCookieCredentialSource("cs-jwt-cookie", "cs_jwt"))
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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
		ext, err := sources.Extract(ctx, makeCC(map[string]string{
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

	t.Run("aggregates extraction errors from all sources", func(t *testing.T) {
		t.Parallel()
		err1 := errors.New("first source failed")
		err2 := errors.New("second source failed")
		sources := NewCredentialSources(
			&stubErrCredentialSource{err: err1},
			&stubErrCredentialSource{err: err2},
		)
		_, err := sources.Extract(ctx, makeCC(nil))
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
