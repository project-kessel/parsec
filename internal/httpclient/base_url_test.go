package httpclient

import (
	"testing"
)

func TestParseBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "empty", raw: ""},
		{name: "origin", raw: "https://entitlements.example.com"},
		{name: "origin trailing slash", raw: "https://entitlements.example.com/"},
		{name: "missing scheme", raw: "entitlements.example.com", wantErr: true},
		{name: "http origin", raw: "http://entitlements.example.com"},
		{name: "ftp scheme", raw: "ftp://entitlements.example.com", wantErr: true},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: true},
		{name: "user info", raw: "https://user:password@entitlements.example.com", wantErr: true},
		{name: "username only", raw: "https://user@entitlements.example.com", wantErr: true},
		{name: "path prefix", raw: "https://entitlements.example.com/v1", wantErr: true},
		{name: "path prefix trailing slash", raw: "https://entitlements.example.com/v1/", wantErr: true},
		{name: "query", raw: "https://entitlements.example.com?x=1", wantErr: true},
		{name: "fragment", raw: "https://entitlements.example.com#frag", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseBaseURL(tt.raw)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
