package config

import (
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/observer"
)

func testHTTPRegistry(t *testing.T) *httpclient.Registry {
	t.Helper()
	r, err := NewHTTPClientRegistry(nil, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry: %v", err)
	}
	return r
}

func TestNewDataSourceRegistry_Static(t *testing.T) {
	t.Parallel()

	reg, err := NewDataSourceRegistry([]DataSourceConfig{
		{
			Name: "identity-policy",
			Type: "static",
			Data: map[string]any{
				"internal_idp_target":   "https://idp.example.com/internal",
				"role_fallback_enabled": true,
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewDataSourceRegistry: %v", err)
	}

	ds := reg.Get("identity-policy")
	if ds == nil {
		t.Fatal("expected registered data source")
	}
	if _, ok := ds.(*datasource.StaticDataSource); !ok {
		t.Fatalf("got %T, want *datasource.StaticDataSource", ds)
	}
}

func TestNewDataSourceRegistry_CacheableLuaUsesObserver(t *testing.T) {
	const luaScript = `
function fetch(input)
  return {data = "{}", content_type = "application/json"}
end
function fetch_cache_key(input)
  return input
end
`
	obs := observer.NoOp()
	reg, err := NewDataSourceRegistry([]DataSourceConfig{
		{
			Name:   "with_cache_key",
			Type:   "lua",
			Script: luaScript,
			Caching: &CachingConfig{
				Type: "in_memory",
				TTL:  "10m",
			},
		},
	}, testHTTPRegistry(t), obs)
	if err != nil {
		t.Fatalf("NewDataSourceRegistry: %v", err)
	}
	ds := reg.Get("with_cache_key")
	if ds == nil {
		t.Fatal("expected registered data source")
	}
	if _, ok := ds.(*datasource.InMemoryCachingDataSource); !ok {
		t.Fatalf("got %T, want *datasource.InMemoryCachingDataSource", ds)
	}
}

func TestParseCacheTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *CachingConfig
		want    time.Duration
		wantErr bool
	}{
		{
			name: "nil config defaults",
			cfg:  nil,
			want: defaultCacheTTL,
		},
		{
			name: "empty TTL defaults",
			cfg:  &CachingConfig{Type: "in_memory"},
			want: defaultCacheTTL,
		},
		{
			name: "explicit zero means no expiry",
			cfg:  &CachingConfig{Type: "in_memory", TTL: "0s"},
			want: 0,
		},
		{
			name: "explicit value",
			cfg:  &CachingConfig{Type: "in_memory", TTL: "10m"},
			want: 10 * time.Minute,
		},
		{
			name:    "invalid duration",
			cfg:     &CachingConfig{Type: "in_memory", TTL: "bogus"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseCacheTTL(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDataSourceRegistry_InvalidCachingType(t *testing.T) {
	t.Parallel()

	const luaScript = `
function fetch(input)
  return {data = "{}", content_type = "application/json"}
end
`
	_, err := NewDataSourceRegistry([]DataSourceConfig{
		{
			Name:   "ds",
			Type:   "lua",
			Script: luaScript,
			Caching: &CachingConfig{
				Type: "redis",
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())

	if err == nil {
		t.Fatal("expected error for invalid caching type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown caching type") {
		t.Fatalf("expected 'unknown caching type' error, got: %v", err)
	}
}
