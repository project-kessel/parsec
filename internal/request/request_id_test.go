package request

import "testing"

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
