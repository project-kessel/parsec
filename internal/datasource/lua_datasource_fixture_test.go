package datasource

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestLuaDataSource_WithMapFixtureProvider(t *testing.T) {
	script := `
function fetch(input)
	local subject = input.subject.subject
	local response = http.get("https://api.example.com/user/" .. subject)
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end
`

	// Create fixture provider
	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET https://api.example.com/user/alice": {
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"username": "alice", "email": "alice@example.com"}`,
		},
		"GET https://api.example.com/user/bob": {
			StatusCode: 200,
			Body:       `{"username": "bob", "email": "bob@example.com"}`,
		},
	})

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			Timeout: 5 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
	})
	if err != nil {
		t.Fatalf("failed to create data source: %v", err)
	}

	// Test with alice
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

	// Test with bob
	input.Subject.Subject = "bob"
	result, err = ds.Fetch(ctx, input)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["username"] != "bob" {
		t.Errorf("username = %q, want %q", data["username"], "bob")
	}
}

func TestLuaDataSource_WithFuncFixtureProvider(t *testing.T) {
	script := `
function fetch(input)
	local subject = input.subject.subject
	local response = http.get("https://api.example.com/user/" .. subject)
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end
`

	// Create a dynamic fixture provider
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if strings.HasPrefix(req.URL.Path, "/user/") {
			userID := strings.TrimPrefix(req.URL.Path, "/user/")
			return &httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"id": "` + userID + `", "name": "User ` + userID + `"}`,
			}
		}
		return nil
	})

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			Timeout: 5 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
	})
	if err != nil {
		t.Fatalf("failed to create data source: %v", err)
	}

	ctx := context.Background()
	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "dynamicuser",
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

	if data["id"] != "dynamicuser" {
		t.Errorf("id = %q, want %q", data["id"], "dynamicuser")
	}

	if data["name"] != "User dynamicuser" {
		t.Errorf("name = %q, want %q", data["name"], "User dynamicuser")
	}
}

func TestLuaDataSource_WithRuleBasedFixtureProvider(t *testing.T) {
	script := `
function fetch(input)
	local subject = input.subject.subject
	local response = http.get("https://api.example.com/user/" .. subject)
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	elseif response.status == 404 then
		return nil
	end
	
	error("unexpected status: " .. response.status)
end
`

	// Create rule-based provider
	rules := []httpfixture.HTTPFixtureRule{
		{
			Request: httpfixture.FixtureRequest{
				Method: "GET",
				URL:    "https://api.example.com/user/alice",
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Body:       `{"username": "alice"}`,
			},
		},
		{
			Request: httpfixture.FixtureRequest{
				Method:  "GET",
				URL:     "https://api.example.com/user/.*",
				URLType: "pattern",
			},
			Response: httpfixture.Fixture{
				StatusCode: 404,
				Body:       `{"error": "not found"}`,
			},
		},
	}

	provider := httpfixture.NewRuleBasedProvider(rules)

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			Timeout: 5 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
	})
	if err != nil {
		t.Fatalf("failed to create data source: %v", err)
	}

	ctx := context.Background()

	// Test exact match (alice)
	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "alice"},
	}

	result, err := ds.Fetch(ctx, input)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result for alice")
	}

	var data map[string]string
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if data["username"] != "alice" {
		t.Errorf("username = %q, want %q", data["username"], "alice")
	}

	// Test pattern match (404)
	input.Subject.Subject = "bob"
	result, err = ds.Fetch(ctx, input)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result for bob (404), got %+v", result)
	}
}

func TestLuaDataSource_WithFileBasedFixtures(t *testing.T) {
	script := `
function fetch(input)
	local response = http.get("https://api.example.com/data")
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end
`

	// Create temporary fixture file
	tmpDir := t.TempDir()
	fixtureFile := filepath.Join(tmpDir, "fixtures.yaml")

	yamlContent := `fixtures:
  - request:
      method: GET
      url: https://api.example.com/data
    response:
      status: 200
      headers:
        Content-Type: application/json
      body: '{"result": "from file"}'
`

	if err := os.WriteFile(fixtureFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create fixture file: %v", err)
	}

	// Load fixtures from file
	provider, err := httpfixture.LoadFixturesFromFile(fixtureFile)
	if err != nil {
		t.Fatalf("failed to load fixtures: %v", err)
	}

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			Timeout: 5 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
	})
	if err != nil {
		t.Fatalf("failed to create data source: %v", err)
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

	if data["result"] != "from file" {
		t.Errorf("result = %q, want %q", data["result"], "from file")
	}
}

func TestLuaDataSource_WithoutFixtures(t *testing.T) {
	t.Skip("Skipping test that requires real HTTP - in practice, use fixtures for all tests")

	script := `
function fetch(input)
	local response = http.get("https://httpbin.org/status/200")
	return {
		data = '{"status": ' .. response.status .. '}',
		content_type = "application/json"
	}
end
`

	// Create data source without fixtures (uses real HTTP)
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "test",
		Script: script,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			Timeout: 5 * time.Second,
			// No FixtureProvider - will use real HTTP
		},
	})
	if err != nil {
		t.Fatalf("failed to create data source: %v", err)
	}

	// This test actually makes a real HTTP call
	// In a real test suite, you'd want to use fixtures for all tests
	ctx := context.Background()
	result, err := ds.Fetch(ctx, &service.DataSourceInput{})

	// We expect this to work, but handle potential network errors gracefully
	if err != nil {
		t.Logf("network error (expected for hermetic tests): %v", err)
		return
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Just verify we got some status back
	if _, ok := data["status"]; !ok {
		t.Error("expected status field in response")
	}
}

func TestCacheableLuaDataSource_WithFixtures(t *testing.T) {
	script := `
function fetch(input)
	local subject = input.subject.subject
	local response = http.get("https://api.example.com/user/" .. subject)
	
	if response.status == 200 then
		return {
			data = response.body,
			content_type = "application/json"
		}
	end
	
	return nil
end

function cache_key(input)
	return {
		subject = {
			subject = input.subject.subject
		}
	}
end
`

	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET https://api.example.com/user/alice": {
			StatusCode: 200,
			Body:       `{"username": "alice"}`,
		},
	})

	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:   "test",
		Script: script,
		HTTPConfig: &luaservices.HTTPServiceConfig{
			Timeout: 5 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
		CacheKeyFunc: "cache_key",
		CacheTTL:     10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create data source: %v", err)
	}

	ctx := context.Background()
	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "alice"},
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

	// Test cache key function
	maskedInput := ds.CacheKey(input)
	if maskedInput.Subject.Subject != "alice" {
		t.Errorf("cache key subject = %q, want %q", maskedInput.Subject.Subject, "alice")
	}
}
