package httpclient

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLuaClient_HTTPClient_NilUsesDefault(t *testing.T) {
	t.Parallel()

	var c LuaClient
	if c.HTTPClient() != http.DefaultClient {
		t.Fatal("expected http.DefaultClient when Client is nil")
	}
}

func TestRegistry_GetLua(t *testing.T) {
	t.Parallel()

	r := NewRegistry(nil)
	spec := ClientSpec{Timeout: 30 * time.Second, BaseURL: "https://entitlements.example"}
	if _, err := r.Register("entitlements", spec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.GetLua("entitlements")
	if err != nil {
		t.Fatalf("GetLua: %v", err)
	}
	if got.BaseURL != "https://entitlements.example" {
		t.Errorf("BaseURL = %q", got.BaseURL)
	}
	if got.HTTPClient() == nil {
		t.Fatal("expected non-nil HTTP client")
	}
}

func TestRegistry_GetLua_NotFound(t *testing.T) {
	t.Parallel()

	r := NewRegistry(nil)
	_, err := r.GetLua("missing")
	if err == nil {
		t.Fatal("expected error for unknown client")
	}
	if !strings.Contains(err.Error(), `client "missing" not found`) {
		t.Errorf("error = %q, want not found message", err)
	}
}

func TestRegistry_GetLua_EmptyBaseURL(t *testing.T) {
	t.Parallel()

	r := NewRegistry(nil)
	if _, err := r.Register("plain", ClientSpec{Timeout: 30 * time.Second}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.GetLua("plain")
	if err != nil {
		t.Fatalf("GetLua: %v", err)
	}
	if got.BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty", got.BaseURL)
	}
}

func TestRegistry_BuildLua(t *testing.T) {
	t.Parallel()

	r := NewRegistry(nil)
	got, err := r.BuildLua(ClientSpec{Timeout: 30 * time.Second, BaseURL: "https://inline.example"})
	if err != nil {
		t.Fatalf("BuildLua: %v", err)
	}
	if got.BaseURL != "https://inline.example" {
		t.Errorf("BaseURL = %q", got.BaseURL)
	}
	if got.HTTPClient() == nil {
		t.Fatal("expected non-nil HTTP client")
	}
}

func TestRegistry_BuildLua_EmptyBaseURL(t *testing.T) {
	t.Parallel()

	r := NewRegistry(nil)
	got, err := r.BuildLua(ClientSpec{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("BuildLua: %v", err)
	}
	if got.BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty", got.BaseURL)
	}
}

func TestRegistry_BuildLua_InvalidSpec(t *testing.T) {
	t.Parallel()

	r := NewRegistry(nil)
	_, err := r.BuildLua(ClientSpec{RootCAPath: "/no/such/ca.pem"})
	if err == nil {
		t.Fatal("expected error for invalid inline client spec")
	}
	if !strings.Contains(err.Error(), "failed to read CA cert") {
		t.Errorf("error = %q, want CA read failure", err)
	}
}
