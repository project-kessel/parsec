package datasource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewLuaDataSource(t *testing.T) {
	tests := []struct {
		name    string
		config  LuaDataSourceConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: LuaDataSourceConfig{
				Name:   "test",
				Script: "function fetch(input) return {data = '{}', content_type = 'application/json'} end",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			config: LuaDataSourceConfig{
				Script: "function fetch(input) return {} end",
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "missing script",
			config: LuaDataSourceConfig{
				Name: "test",
			},
			wantErr: true,
			errMsg:  "script is required",
		},
		{
			name: "invalid script syntax",
			config: LuaDataSourceConfig{
				Name:   "test",
				Script: "invalid lua syntax {{{",
			},
			wantErr: true,
			errMsg:  "failed to load script",
		},
		{
			name: "missing fetch function",
			config: LuaDataSourceConfig{
				Name:   "test",
				Script: "function other() return {} end",
			},
			wantErr: true,
			errMsg:  "must define a 'fetch' function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := NewLuaDataSource(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if ds == nil {
					t.Error("expected non-nil data source")
				}
			}
		})
	}
}

func TestLuaDataSource_Name(t *testing.T) {
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "my-datasource",
		Script: "function fetch(input) return {} end",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := ds.Name(); got != "my-datasource" {
		t.Errorf("Name() = %q, want %q", got, "my-datasource")
	}
}

func TestLuaDataSource_Fetch_SimpleReturn(t *testing.T) {
	script := `
function fetch(input)
	return {
		data = '{"result": "success"}',
		content_type = "application/json"
	}
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
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

	if string(result.Data) != `{"result": "success"}` {
		t.Errorf("result.Data = %q, want %q", string(result.Data), `{"result": "success"}`)
	}

	if result.ContentType != service.ContentTypeJSON {
		t.Errorf("result.ContentType = %q, want %q", result.ContentType, service.ContentTypeJSON)
	}
}

func TestLuaDataSource_Fetch_NilReturn(t *testing.T) {
	script := `
function fetch(input)
	return nil
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	result, err := ds.Fetch(ctx, &service.DataSourceInput{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

func TestLuaDataSource_Fetch_AccessInput(t *testing.T) {
	script := `
function fetch(input)
	local subject = input.subject.subject
	local issuer = input.subject.issuer
	
	return {
		data = '{"subject":"' .. subject .. '","issuer":"' .. issuer .. '"}',
		content_type = "application/json"
	}
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "user@example.com",
			Issuer:  "https://idp.example.com",
		},
	}

	result, err := ds.Fetch(ctx, input)
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

	if data["subject"] != "user@example.com" {
		t.Errorf("subject = %q, want %q", data["subject"], "user@example.com")
	}

	if data["issuer"] != "https://idp.example.com" {
		t.Errorf("issuer = %q, want %q", data["issuer"], "https://idp.example.com")
	}
}

func TestLuaDataSource_Fetch_JSONService(t *testing.T) {
	script := `
function fetch(input)
	local obj = {key = "value", num = 42}
	local jsonStr = json.encode(obj)
	
	local decoded = json.decode(jsonStr)
	
	return {
		data = json.encode(decoded),
		content_type = "application/json"
	}
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
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

	var data map[string]interface{}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["key"] != "value" {
		t.Errorf("key = %v, want %q", data["key"], "value")
	}

	if data["num"] != float64(42) {
		t.Errorf("num = %v, want %v", data["num"], 42)
	}
}

func TestLuaDataSource_Fetch_ConfigService(t *testing.T) {
	script := `
function fetch(input)
	local apiKey = config.get("api_key")
	local timeout = config.get("timeout", 30)
	local missing = config.get("missing", "default")
	
	local result = {
		api_key = apiKey,
		timeout = timeout,
		missing = missing
	}
	
	return {
		data = json.encode(result),
		content_type = "application/json"
	}
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]interface{}{
			"api_key": "secret123",
			"timeout": 60,
		}),
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

	var data map[string]interface{}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["api_key"] != "secret123" {
		t.Errorf("api_key = %v, want %q", data["api_key"], "secret123")
	}

	if data["timeout"] != float64(60) {
		t.Errorf("timeout = %v, want %v", data["timeout"], 60)
	}

	if data["missing"] != "default" {
		t.Errorf("missing = %v, want %q", data["missing"], "default")
	}
}

func TestLuaDataSource_Fetch_HTTPService(t *testing.T) {
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/alice" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"username": "alice",
				"email":    "alice@example.com",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	script := `
function fetch(input)
	local subject = input.subject.subject
	local response = http.get("` + server.URL + `/user/" .. subject)
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	else
		return nil
	end
end
`

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

	var data map[string]string
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["username"] != "alice" {
		t.Errorf("username = %q, want %q", data["username"], "alice")
	}

	if data["email"] != "alice@example.com" {
		t.Errorf("email = %q, want %q", data["email"], "alice@example.com")
	}
}

func TestCacheableLuaDataSource_New(t *testing.T) {
	tests := []struct {
		name    string
		config  CacheableLuaDataSourceConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: CacheableLuaDataSourceConfig{
				Name:         "test",
				Script:       "function fetch(input) return {} end\nfunction cache_key(input) return input end",
				CacheKeyFunc: "cache_key",
			},
			wantErr: false,
		},
		{
			name: "missing cache key function name",
			config: CacheableLuaDataSourceConfig{
				Name:   "test",
				Script: "function fetch(input) return {} end\nfunction cache_key(input) return input end",
			},
			wantErr: true,
			errMsg:  "cache_key function is required",
		},
		{
			name: "cache key function not defined in script",
			config: CacheableLuaDataSourceConfig{
				Name:         "test",
				Script:       "function fetch(input) return {} end",
				CacheKeyFunc: "missing_func",
			},
			wantErr: true,
			errMsg:  "must define a 'missing_func' function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := NewCacheableLuaDataSource(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if ds == nil {
					t.Error("expected non-nil data source")
				}
			}
		})
	}
}

func TestCacheableLuaDataSource_CacheKey(t *testing.T) {
	script := `
function fetch(input)
	return {data = '{}', content_type = 'application/json'}
end

function cache_key(input)
	return {
		subject = {
			subject = input.subject.subject
		}
	}
end
`

	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:         "test",
		Script:       script,
		CacheKeyFunc: "cache_key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "user@example.com",
			Issuer:  "https://idp.example.com",
		},
		RequestAttributes: &request.RequestAttributes{
			Method: "POST",
			Path:   "/api/resource",
		},
	}

	maskedInput := ds.CacheKey(input)

	// Check that only subject.subject is preserved
	if maskedInput.Subject == nil {
		t.Fatal("expected subject to be non-nil")
	}

	if maskedInput.Subject.Subject != "user@example.com" {
		t.Errorf("subject.subject = %q, want %q", maskedInput.Subject.Subject, "user@example.com")
	}

	// Issuer should be zeroed out by the cache_key function
	if maskedInput.Subject.Issuer != "" {
		t.Errorf("subject.issuer should be empty, got %q", maskedInput.Subject.Issuer)
	}

	// Request attributes should be zeroed out
	if maskedInput.RequestAttributes != nil {
		t.Errorf("request_attributes should be nil, got %+v", maskedInput.RequestAttributes)
	}
}

func TestCacheableLuaDataSource_CacheTTL(t *testing.T) {
	script := `
function fetch(input) return {} end
function cache_key(input) return input end
`

	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{
			name: "custom TTL",
			ttl:  10 * time.Minute,
			want: 10 * time.Minute,
		},
		{
			name: "default TTL",
			ttl:  0,
			want: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
				Name:         "test",
				Script:       script,
				CacheKeyFunc: "cache_key",
				CacheTTL:     tt.ttl,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := ds.CacheTTL(); got != tt.want {
				t.Errorf("CacheTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLuaDataSource_Fetch_ErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		wantErr bool
		errMsg  string
	}{
		{
			name: "runtime error in script",
			script: `
function fetch(input)
	error("something went wrong")
end
`,
			wantErr: true,
			errMsg:  "script execution failed",
		},
		{
			name: "invalid return type",
			script: `
function fetch(input)
	return "not a table"
end
`,
			wantErr: true,
			errMsg:  "must return a table or nil",
		},
		{
			name: "missing data field",
			script: `
function fetch(input)
	return {content_type = "application/json"}
end
`,
			wantErr: true,
			errMsg:  "must have a 'data' field",
		},
		{
			name: "invalid data field type",
			script: `
function fetch(input)
	return {data = 123, content_type = "application/json"}
end
`,
			wantErr: true,
			errMsg:  "'data' field must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := NewLuaDataSource(LuaDataSourceConfig{
				Name:   "test",
				Script: tt.script,
			})
			if err != nil {
				t.Fatalf("unexpected error creating data source: %v", err)
			}

			ctx := context.Background()
			_, err = ds.Fetch(ctx, &service.DataSourceInput{})
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLuaDataSource_Integration(t *testing.T) {
	// Create a test HTTP server that returns user data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    123,
			"roles": []string{"admin", "user"},
		})
	}))
	defer server.Close()

	script := `
function fetch(input)
	local subject = input.subject.subject
	local apiKey = config.get("api_key")
	
	-- Make HTTP request with custom header
	local headers = {["Authorization"] = "Bearer " .. apiKey}
	local response = http.get("` + server.URL + `/api/user/" .. subject, headers)
	
	if response.status == 200 then
		-- Parse JSON response
		local userData = json.decode(response.body)
		
		-- Add some extra data
		userData.fetched_at = os.time()
		userData.source = "lua-datasource"
		
		-- Return as JSON
		return {
			data = json.encode(userData),
			content_type = "application/json"
		}
	else
		return nil
	end
end

function cache_key(input)
	-- Only cache based on subject
	return {
		subject = {
			subject = input.subject.subject
		}
	}
end
`

	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:   "user-data",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]interface{}{
			"api_key": "test-key-123",
		}),
		CacheKeyFunc: "cache_key",
		CacheTTL:     10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test Name
	if ds.Name() != "user-data" {
		t.Errorf("Name() = %q, want %q", ds.Name(), "user-data")
	}

	// Test Fetch
	ctx := context.Background()
	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
			Issuer:  "https://idp.example.com",
		},
		RequestAttributes: &request.RequestAttributes{
			Method: "GET",
			Path:   "/token",
		},
	}

	result, err := ds.Fetch(ctx, input)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["id"] != float64(123) {
		t.Errorf("id = %v, want %v", data["id"], 123)
	}

	if data["source"] != "lua-datasource" {
		t.Errorf("source = %v, want %q", data["source"], "lua-datasource")
	}

	// Test CacheKey
	maskedInput := ds.CacheKey(input)
	if maskedInput.Subject.Subject != "alice" {
		t.Errorf("masked subject = %q, want %q", maskedInput.Subject.Subject, "alice")
	}
	if maskedInput.RequestAttributes != nil {
		t.Errorf("masked request_attributes should be nil")
	}

	// Test CacheTTL
	if ds.CacheTTL() != 10*time.Minute {
		t.Errorf("CacheTTL() = %v, want %v", ds.CacheTTL(), 10*time.Minute)
	}
}
