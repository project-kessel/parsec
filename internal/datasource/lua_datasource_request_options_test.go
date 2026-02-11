package datasource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestLuaDataSource_WithRequestOptions(t *testing.T) {
	// Create a test server that requires auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that auth header was added by RequestOptions
		auth := r.Header.Get("Authorization")
		if auth != "Bearer secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}

		// Return user data
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       123,
			"username": "alice",
			"email":    "alice@example.com",
		})
	}))
	defer server.Close()

	// Lua script that doesn't need to worry about auth
	script := `
function fetch(input)
	local subject = input.subject.subject
	local apiEndpoint = config.get("api_endpoint")
	
	-- No auth headers needed - RequestOptions handles it
	local response = http.get(apiEndpoint .. "/user/" .. subject)
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end
`

	// Create data source with RequestOptions that adds auth
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "user-data",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]interface{}{
			"api_endpoint": server.URL,
		}),
		HTTPConfig: &luaservices.HTTPServiceConfig{
			RequestOptions: func(req *http.Request) error {
				// Automatically add authentication
				req.Header.Set("Authorization", "Bearer secret-token")
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test fetch
	ctx := context.Background()
	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
		},
	}

	result, err := ds.Fetch(ctx, input)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify the data
	var data map[string]interface{}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["username"] != "alice" {
		t.Errorf("username = %v, want %q", data["username"], "alice")
	}

	if data["email"] != "alice@example.com" {
		t.Errorf("email = %v, want %q", data["email"], "alice@example.com")
	}
}

func TestLuaDataSource_RequestOptionsWithConfigSource(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for API key from config
		auth := r.Header.Get("X-API-Key")
		if auth != "config-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	script := `
function fetch(input)
	local apiEndpoint = config.get("api_endpoint")
	local response = http.get(apiEndpoint .. "/data")
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end
`

	// Create config source
	configSource := luaservices.NewMapConfigSource(map[string]interface{}{
		"api_endpoint": server.URL,
		"api_key":      "config-api-key",
	})

	// Create data source with RequestOptions that reads from config
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:         "test",
		Script:       script,
		ConfigSource: configSource,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			RequestOptions: func(req *http.Request) error {
				// Get API key from config
				apiKey, ok := configSource.Get("api_key")
				if !ok {
					return http.ErrNotSupported
				}
				req.Header.Set("X-API-Key", apiKey.(string))
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test fetch
	ctx := context.Background()
	result, err := ds.Fetch(ctx, &service.DataSourceInput{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]string
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["status"] != "ok" {
		t.Errorf("status = %q, want %q", data["status"], "ok")
	}
}

func TestLuaDataSource_RequestOptionsModifyURL(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for query params added by RequestOptions
		if r.URL.Query().Get("tenant") != "acme-corp" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"tenant": "acme-corp"})
	}))
	defer server.Close()

	script := `
function fetch(input)
	local apiEndpoint = config.get("api_endpoint")
	-- URL doesn't include tenant - RequestOptions will add it
	local response = http.get(apiEndpoint .. "/data")
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]interface{}{
			"api_endpoint": server.URL,
		}),
		HTTPConfig: &luaservices.HTTPServiceConfig{
			RequestOptions: func(req *http.Request) error {
				// Add tenant as query parameter
				q := req.URL.Query()
				q.Add("tenant", "acme-corp")
				req.URL.RawQuery = q.Encode()
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := ds.Fetch(ctx, &service.DataSourceInput{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]string
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["tenant"] != "acme-corp" {
		t.Errorf("tenant = %q, want %q", data["tenant"], "acme-corp")
	}
}
