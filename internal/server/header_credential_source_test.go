package server

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestHeaderCredentialSource_Extract(t *testing.T) {
	headers := []HeaderSpec{{Name: "x-custom-header-a"}, {Name: "x-custom-header-b"}}
	src, err := NewHeaderCredentialSource("custom-headers", headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("all headers present", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-custom-header-a": "value-a",
				"x-custom-header-b": "value-b",
			},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext == nil {
			t.Fatal("expected extraction, got nil")
		}

		cred, ok := ext.Credential.(*trust.HeaderCredential)
		if !ok {
			t.Fatalf("expected *HeaderCredential, got %T", ext.Credential)
		}
		if cred.Headers["x-custom-header-a"] != "value-a" {
			t.Errorf("expected 'value-a', got %q", cred.Headers["x-custom-header-a"])
		}
		if cred.Headers["x-custom-header-b"] != "value-b" {
			t.Errorf("expected 'value-b', got %q", cred.Headers["x-custom-header-b"])
		}
		if ext.SourceName != "custom-headers" {
			t.Errorf("expected SourceName 'custom-headers', got %q", ext.SourceName)
		}
		if len(ext.HeadersUsed) != 2 {
			t.Fatalf("expected 2 headers used, got %d", len(ext.HeadersUsed))
		}
	})

	t.Run("no headers present returns nil", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatal("expected nil extraction, got non-nil")
		}
	})

	t.Run("partial headers returns error", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-custom-header-a": "value-a",
			},
		}

		_, err := src.Extract(context.Background(), cc)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("unrelated headers returns nil", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"authorization": "Bearer token123",
			},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatal("expected nil extraction, got non-nil")
		}
	})
}

func TestHeaderCredentialSource_MixedCaseHeaders(t *testing.T) {
	src, err := NewHeaderCredentialSource("custom-headers", []HeaderSpec{{Name: "X-Custom-Header-A"}, {Name: "X-Custom-Header-B"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cc := CredentialContext{
		Headers: map[string]string{
			"x-custom-header-a": "value-a",
			"x-custom-header-b": "value-b",
		},
	}

	ext, err := src.Extract(context.Background(), cc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext == nil {
		t.Fatal("expected extraction, got nil")
	}

	cred, ok := ext.Credential.(*trust.HeaderCredential)
	if !ok {
		t.Fatalf("expected *HeaderCredential, got %T", ext.Credential)
	}
	if cred.Headers["x-custom-header-a"] != "value-a" {
		t.Errorf("expected 'value-a', got %q", cred.Headers["x-custom-header-a"])
	}
	if cred.Headers["x-custom-header-b"] != "value-b" {
		t.Errorf("expected 'value-b', got %q", cred.Headers["x-custom-header-b"])
	}
}

func TestHeaderCredentialSource_Match(t *testing.T) {
	src, err := NewHeaderCredentialSource("uhc-auth", []HeaderSpec{
		{Name: "authorization"},
		{Name: "user-agent", Match: "^.*-operator/.* cluster/.*"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("matching value extracts", func(t *testing.T) {
		cc := CredentialContext{Headers: map[string]string{
			"authorization": "Bearer token123",
			"user-agent":    "insights-operator/abcdef cluster/1234321",
		}}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext == nil {
			t.Fatal("expected extraction, got nil")
		}
		cred, ok := ext.Credential.(*trust.HeaderCredential)
		if !ok {
			t.Fatalf("expected *HeaderCredential, got %T", ext.Credential)
		}
		if cred.Headers["user-agent"] != "insights-operator/abcdef cluster/1234321" {
			t.Errorf("user-agent=%q, want the operator user-agent", cred.Headers["user-agent"])
		}
	})

	t.Run("non-matching value declines without error", func(t *testing.T) {
		cc := CredentialContext{Headers: map[string]string{
			"authorization": "Bearer token123",
			"user-agent":    "curl/8.0.1",
		}}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatal("expected nil extraction for a non-matching user-agent, got non-nil")
		}
	})

	t.Run("matched header absent falls back to partial-header error", func(t *testing.T) {
		cc := CredentialContext{Headers: map[string]string{
			"authorization": "Bearer token123",
		}}

		if _, err := src.Extract(context.Background(), cc); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestHeaderCredentialSource_Strip(t *testing.T) {
	strip := false
	src, err := NewHeaderCredentialSource("uhc-auth", []HeaderSpec{
		{Name: "authorization"},
		{Name: "user-agent", Strip: &strip},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cc := CredentialContext{Headers: map[string]string{
		"authorization": "Bearer token123",
		"user-agent":    "insights-operator/abcdef cluster/1234321",
	}}

	ext, err := src.Extract(context.Background(), cc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext == nil {
		t.Fatal("expected extraction, got nil")
	}

	// The header is still part of the credential...
	cred := ext.Credential.(*trust.HeaderCredential)
	if cred.Headers["user-agent"] == "" {
		t.Error("user-agent missing from the credential")
	}
	// ...but must survive into the upstream request.
	if len(ext.HeadersUsed) != 1 || ext.HeadersUsed[0] != "authorization" {
		t.Errorf("HeadersUsed=%v, want [authorization] only", ext.HeadersUsed)
	}
}

func TestNewHeaderCredentialSource_InvalidMatch(t *testing.T) {
	_, err := NewHeaderCredentialSource("test", []HeaderSpec{{Name: "user-agent", Match: "([unclosed"}})
	if err == nil {
		t.Fatal("expected error for an invalid match regex, got nil")
	}
}

func TestNewHeaderCredentialSource_EmptyName(t *testing.T) {
	_, err := NewHeaderCredentialSource("", []HeaderSpec{{Name: "x-header"}})
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestNewHeaderCredentialSource_EmptyHeaders(t *testing.T) {
	_, err := NewHeaderCredentialSource("test", nil)
	if err == nil {
		t.Fatal("expected error for empty headers, got nil")
	}
}
