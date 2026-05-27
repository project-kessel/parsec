package datasource

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/project-kessel/parsec/internal/service"
)

func TestNewStaticDataSource(t *testing.T) {
	t.Parallel()

	t.Run("empty name", func(t *testing.T) {
		t.Parallel()
		_, err := NewStaticDataSource("", map[string]any{"k": "v"})
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("nil data", func(t *testing.T) {
		t.Parallel()
		_, err := NewStaticDataSource("policy", nil)
		if err == nil {
			t.Fatal("expected error for nil data")
		}
	})

	t.Run("returns configured data", func(t *testing.T) {
		t.Parallel()
		ds, err := NewStaticDataSource("identity-policy", map[string]any{
			"internal_idp_target":   "https://idp.example.com/internal",
			"role_fallback_enabled": true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := ds.Fetch(context.Background(), &service.DataSourceInput{})
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}

		var got map[string]any
		if err := json.Unmarshal(result.Data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["internal_idp_target"] != "https://idp.example.com/internal" {
			t.Fatalf("unexpected data: %v", got)
		}
		if got["role_fallback_enabled"] != true {
			t.Fatalf("unexpected role_fallback_enabled: %v", got["role_fallback_enabled"])
		}
	})

	t.Run("fetch returns independent copy", func(t *testing.T) {
		t.Parallel()
		ds, err := NewStaticDataSource("policy", map[string]any{"k": "v"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		first, err := ds.Fetch(context.Background(), &service.DataSourceInput{})
		if err != nil {
			t.Fatalf("first fetch: %v", err)
		}
		first.Data[0] = 'X'

		second, err := ds.Fetch(context.Background(), &service.DataSourceInput{})
		if err != nil {
			t.Fatalf("second fetch: %v", err)
		}
		if first.Data[0] == second.Data[0] {
			t.Fatal("expected fetch results to use independent byte slices")
		}
	})
}
