package datasource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/httpclient"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestLuaDataSource_ShippedExamplesRunInSandbox loads every example script and
// runs it end to end. It guards against examples relying on libraries the
// sandbox removes (os, io, ...) and checks untrusted subjects stay escaped.
func TestLuaDataSource_ShippedExamplesRunInSandbox(t *testing.T) {
	const subject = "../alice"
	const wantEscaped = "..%2Falice"

	tests := []struct {
		file     string
		useBase  bool
		config   map[string]any
		wantPath string
	}{
		{file: "user_data.lua", useBase: true, wantPath: "/users/" + wantEscaped},
		{file: "regional_data.lua", useBase: true, wantPath: "/us-east-1/users/" + wantEscaped},
		{file: "multi_source.lua", wantPath: "/users/" + wantEscaped},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			var gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.EscapedPath()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1"})
			}))
			defer server.Close()

			script, err := os.ReadFile(filepath.Join("examples", tt.file))
			if err != nil {
				t.Fatalf("read example: %v", err)
			}

			lc := httpclient.LuaClient{Client: server.Client()}
			cfg := map[string]any{"api_key": "test-key"}
			if tt.useBase {
				lc.BaseURL = server.URL
			} else {
				cfg["api_endpoint"] = server.URL
			}

			ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
				Name:         tt.file,
				Script:       string(script),
				ConfigSource: luaservices.NewMapConfigSource(cfg),
				HTTP:         lc,
			})
			if err != nil {
				t.Fatalf("NewCacheableLuaDataSource: %v", err)
			}

			result, err := ds.Fetch(context.Background(), &service.DataSourceInput{
				Subject: &trust.Result{
					Subject: subject,
					Issuer:  "https://issuer.example",
					Claims:  claims.Claims{"user_type": "standard"},
				},
			})
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if result == nil {
				t.Fatal("Fetch returned nil result")
			}
			if gotPath != tt.wantPath {
				t.Errorf("request path = %q, want %q", gotPath, tt.wantPath)
			}
		})
	}
}
