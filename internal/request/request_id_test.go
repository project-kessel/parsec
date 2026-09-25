package request

import "testing"

func TestDefaultRequestIDConfig(t *testing.T) {
	cfg := DefaultRequestIDConfig()
	if len(cfg.Headers) != 1 || cfg.Headers[0] != "x-request-id" {
		t.Fatalf("DefaultRequestIDConfig() = %#v, want [x-request-id]", cfg.Headers)
	}
	if cfg.CanonicalHeader() != "x-request-id" {
		t.Fatalf("CanonicalHeader() = %q, want x-request-id", cfg.CanonicalHeader())
	}
	// Mutating the returned slice must not affect future defaults.
	cfg.Headers[0] = "mutated"
	cfg2 := DefaultRequestIDConfig()
	if cfg2.Headers[0] != "x-request-id" {
		t.Fatal("DefaultRequestIDConfig must return a copy")
	}
}

func TestValidRequestID(t *testing.T) {
	if got := ValidRequestID("abc-123"); got != "abc-123" {
		t.Fatalf("ValidRequestID(abc-123) = %q", got)
	}
	if got := ValidRequestID("bad\nvalue"); got != "" {
		t.Fatalf("ValidRequestID(bad newline) = %q, want empty", got)
	}
	if got := ValidRequestID("  trimmed  "); got != "trimmed" {
		t.Fatalf("ValidRequestID(trimmed) = %q", got)
	}
}

func TestHeaderValue(t *testing.T) {
	headers := map[string]string{"X-Request-Id": "id-1"}
	if got := HeaderValue(headers, "x-request-id"); got != "id-1" {
		t.Fatalf("HeaderValue case-insensitive = %q", got)
	}
}
