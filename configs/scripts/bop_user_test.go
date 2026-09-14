package scripts_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func bopFixtureClient(provider httpfixture.FixtureProvider) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}
}

func bopLuaConfig() map[string]any {
	return map[string]any{
		"bop_url":    "https://backoffice-proxy.example.com",
		"users_path": "/v1/users",
		"bop_env":    "stage",
	}
}

func bopHappyResponse() string {
	users := []map[string]any{
		{
			"org_id":         12345,
			"id":             67890,
			"account_number": "540155",
			"email":          "testuser@redhat.com",
			"first_name":     "Test",
			"last_name":      "User",
			"is_org_admin":   true,
			"is_internal":    true,
			"is_active":      true,
			"locale":         "en_US",
			"username":       "testuser",
		},
	}
	b, _ := json.Marshal(users)
	return string(b)
}

func TestBOPUser_HappyPath(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method == "POST" && strings.Contains(req.URL.String(), "/v1/users") {
			return &httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       bopHappyResponse(),
			}
		}
		return nil
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "testuser",
			Issuer:  trust.UnsignedJSONTokenTypeURN,
		},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]any
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// org_id and user_id should be coerced to strings via tostring()
	if data["org_id"] != "12345" {
		t.Errorf("org_id=%v, want \"12345\"", data["org_id"])
	}
	if data["user_id"] != "67890" {
		t.Errorf("user_id=%v, want \"67890\"", data["user_id"])
	}
	if data["account_number"] != "540155" {
		t.Errorf("account_number=%v, want \"540155\"", data["account_number"])
	}
	if data["email"] != "testuser@redhat.com" {
		t.Errorf("email=%v, want testuser@redhat.com", data["email"])
	}
	if data["first_name"] != "Test" {
		t.Errorf("first_name=%v, want Test", data["first_name"])
	}
	if data["last_name"] != "User" {
		t.Errorf("last_name=%v, want User", data["last_name"])
	}
	if data["is_org_admin"] != true {
		t.Errorf("is_org_admin=%v, want true", data["is_org_admin"])
	}
	if data["is_internal"] != true {
		t.Errorf("is_internal=%v, want true", data["is_internal"])
	}
	if data["is_active"] != true {
		t.Errorf("is_active=%v, want true", data["is_active"])
	}
	if data["locale"] != "en_US" {
		t.Errorf("locale=%v, want en_US", data["locale"])
	}
	if data["username"] != "testuser" {
		t.Errorf("username=%v, want testuser", data["username"])
	}

	if result.ContentType != service.ContentTypeJSON {
		t.Errorf("ContentType=%q, want application/json", result.ContentType)
	}
}

func TestBOPUser_EmptyUsername(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "", Issuer: trust.UnsignedJSONTokenTypeURN},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for empty username, got %+v", result)
	}
}

func TestBOPUser_Non200Response(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		return &httpfixture.Fixture{StatusCode: 500, Body: "internal error"}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "testuser"},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for 500 response, got %+v", result)
	}
}

func TestBOPUser_EmptyArray(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       "[]",
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "nobody"},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected error sentinel result for empty array, got nil")
	}
	if !strings.Contains(string(result.Data), `"error":"user_not_found"`) {
		t.Fatalf("expected user_not_found error sentinel, got %s", string(result.Data))
	}
}

func TestBOPUser_MultipleUsers(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `[{"org_id":"1","id":"2"},{"org_id":"3","id":"4"}]`,
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "ambiguous"},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for multiple users, got %+v", result)
	}
}

func TestBOPUser_MissingOrgId(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `[{"id":"67890","email":"user@test.com"}]`,
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "testuser"},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected error sentinel result when org_id is missing, got nil")
	}
	if !strings.Contains(string(result.Data), `"error":"user_not_found"`) {
		t.Fatalf("expected user_not_found error sentinel, got %s", string(result.Data))
	}
}

func TestBOPUser_MissingId(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `[{"org_id":"12345","email":"user@test.com"}]`,
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "testuser"},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected error sentinel result when id is missing, got nil")
	}
	if !strings.Contains(string(result.Data), `"error":"user_not_found"`) {
		t.Fatalf("expected user_not_found error sentinel, got %s", string(result.Data))
	}
}

func TestBOPUser_VerifiesRequestHeaders(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	var capturedHeaders http.Header
	var capturedMethod string
	var capturedURL string
	var capturedBody string

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		capturedHeaders = req.Header
		capturedMethod = req.Method
		capturedURL = req.URL.String()
		if req.Body != nil {
			bodyBytes := make([]byte, 1024)
			n, _ := req.Body.Read(bodyBytes)
			capturedBody = string(bodyBytes[:n])
		}
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       bopHappyResponse(),
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:   "bop-user",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"bop_url":    "https://backoffice-proxy.example.com",
			"users_path": "/v1/users",
			"bop_env":    "prod",
		}),
		HTTP: httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "jdoe"},
	}

	_, err = ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if capturedMethod != "POST" {
		t.Errorf("Method=%q, want POST", capturedMethod)
	}

	if !strings.Contains(capturedURL, "/v1/users") {
		t.Errorf("URL=%q, want containing /v1/users", capturedURL)
	}
	if !strings.Contains(capturedURL, "queryBy=userId") {
		t.Errorf("URL=%q, want containing queryBy=userId", capturedURL)
	}

	if capturedHeaders.Get("x-rh-apitoken") != "" {
		t.Errorf("x-rh-apitoken=%q, want empty (injected by HTTP client, not Lua)", capturedHeaders.Get("x-rh-apitoken"))
	}
	if capturedHeaders.Get("x-rh-clientid") != "" {
		t.Errorf("x-rh-clientid=%q, want empty (injected by HTTP client, not Lua)", capturedHeaders.Get("x-rh-clientid"))
	}
	if capturedHeaders.Get("x-rh-insights-env") != "prod" {
		t.Errorf("x-rh-insights-env=%q, want prod", capturedHeaders.Get("x-rh-insights-env"))
	}
	if capturedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", capturedHeaders.Get("Content-Type"))
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(capturedBody), &body); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}
	users, ok := body["users"].([]any)
	if !ok || len(users) != 1 || users[0] != "jdoe" {
		t.Errorf("request body users=%v, want [\"jdoe\"]", body["users"])
	}
}

func TestBOPUser_HTTPClientInjectsAuthHeaders(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	var capturedHeaders http.Header
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		capturedHeaders = req.Header.Clone()
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       bopHappyResponse(),
		}
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &httpclient.HeadersTransport{
			Headers: map[string]string{
				"x-rh-clientid": "my-client-id",
				"x-rh-apitoken": "my-api-token",
			},
			Base: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
	}

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: client},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "jdoe", Issuer: trust.UnsignedJSONTokenTypeURN},
	}
	if _, err := ds.Fetch(context.Background(), input); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if capturedHeaders.Get("x-rh-apitoken") != "my-api-token" {
		t.Errorf("x-rh-apitoken=%q, want my-api-token", capturedHeaders.Get("x-rh-apitoken"))
	}
	if capturedHeaders.Get("x-rh-clientid") != "my-client-id" {
		t.Errorf("x-rh-clientid=%q, want my-client-id", capturedHeaders.Get("x-rh-clientid"))
	}
	if capturedHeaders.Get("x-rh-insights-env") != "stage" {
		t.Errorf("x-rh-insights-env=%q, want stage", capturedHeaders.Get("x-rh-insights-env"))
	}
}

func TestBOPUser_StripsSSOPrefix(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	var capturedBody string
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Body != nil {
			bodyBytes := make([]byte, 1024)
			n, _ := req.Body.Read(bodyBytes)
			capturedBody = string(bodyBytes[:n])
		}
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       bopHappyResponse(),
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "redhat:user:sso:98765",
			Issuer:  trust.UnsignedJSONTokenTypeURN,
		},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(capturedBody), &body); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}
	users, ok := body["users"].([]any)
	if !ok || len(users) != 1 || users[0] != "98765" {
		t.Errorf("request body users=%v, want [\"98765\"]", body["users"])
	}
}

func TestBOPUser_EmptyPrefixRemainder(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "redhat:user:sso:",
			Issuer:  trust.UnsignedJSONTokenTypeURN,
		},
	}

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for empty prefix remainder, got %+v", result)
	}
}

func TestBOPUser_CacheKey(t *testing.T) {
	script := loadScript(t, "bop_user.lua")

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       bopHappyResponse(),
		}
	})

	ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
		Name:         "bop-user",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(bopLuaConfig()),
		HTTP:         httpclient.LuaClient{Client: bopFixtureClient(provider)},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "cacheuser",
			Issuer:  trust.UnsignedJSONTokenTypeURN,
		},
	}

	masked, useCache := ds.CacheKey(input)
	if !useCache {
		t.Fatal("expected cacheable key for username")
	}
	if masked.Subject == nil {
		t.Fatal("expected non-nil subject in cache key")
	}
	if masked.Subject.Subject != "cacheuser" {
		t.Errorf("cache key subject=%q, want cacheuser", masked.Subject.Subject)
	}
	// Issuer should be stripped by the cache key function
	if masked.Subject.Issuer != "" {
		t.Errorf("cache key issuer should be empty, got %q", masked.Subject.Issuer)
	}
}
