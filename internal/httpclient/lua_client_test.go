package httpclient

import (
	"testing"
	"time"
)

func TestRegistry_GetLua(t *testing.T) {
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

func TestRegistry_BuildLua(t *testing.T) {
	r := NewRegistry(nil)
	got, err := r.BuildLua(ClientSpec{Timeout: 30 * time.Second, BaseURL: "https://inline.example"})
	if err != nil {
		t.Fatalf("BuildLua: %v", err)
	}
	if got.BaseURL != "https://inline.example" {
		t.Errorf("BaseURL = %q", got.BaseURL)
	}
}
