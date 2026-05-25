package datasource

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/project-kessel/parsec/internal/service"
)

func TestNewStaticDataSource(t *testing.T) {
	t.Parallel()

	t.Run("missing name", func(t *testing.T) {
		t.Parallel()
		_, err := NewStaticDataSource(StaticDataSourceConfig{Data: map[string]any{"k": "v"}})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
	})

	t.Run("missing data", func(t *testing.T) {
		t.Parallel()
		_, err := NewStaticDataSource(StaticDataSourceConfig{Name: "policy"})
		if err == nil {
			t.Fatal("expected error for missing data")
		}
	})

	t.Run("returns configured data", func(t *testing.T) {
		t.Parallel()
		ds, err := NewStaticDataSource(StaticDataSourceConfig{
			Name: "identity-policy",
			Data: map[string]any{
				"internal_idp_target":   "https://idp.example.com/internal",
				"role_fallback_enabled": true,
			},
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
}
