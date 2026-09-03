package datasource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const (
	crossAccountRBACAPI  = "https://rbac.example.internal"
	crossAccountRBACPath = "/api/rbac/v1/cross-account-requests/"
)

func loadCrossAccountScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "configs", "scripts", "cross_account.lua")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cross_account.lua: %v", err)
	}
	return string(b)
}

func defaultCrossAccountConfig() map[string]any {
	return map[string]any{
		"rbac_api":              crossAccountRBACAPI,
		"requests_path":         crossAccountRBACPath,
		"query_by":              "account",
		"internal_email_suffix": "@redhat.com",
		"bypass_is_internal":    false,
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
	}
}

func internalEmployeeInput(cookieHeader string) *service.DataSourceInput {
	return &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
			Claims: map[string]any{
				"email":              "alice@redhat.com",
				"is_internal":        true,
				"preferred_username": "alice",
				"organization": map[string]any{
					"id":             "emp-org",
					"account_number": "11111",
				},
			},
		},
		RequestAttributes: &request.RequestAttributes{
			Headers: map[string]string{"cookie": cookieHeader},
		},
	}
}

func newCrossAccountDS(t *testing.T, script string, client *http.Client, cfg map[string]any) *LuaDataSource {
	t.Helper()
	if cfg == nil {
		cfg = defaultCrossAccountConfig()
	}
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:         "cross_account",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(cfg),
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}
	return ds
}

func newCacheableCrossAccountDS(t *testing.T, script string, client *http.Client, cfg map[string]any) *CacheableLuaDataSource {
	t.Helper()
	if cfg == nil {
		cfg = defaultCrossAccountConfig()
	}
	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:         "cross_account",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(cfg),
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}
	return ds
}

func strictClient(provider httpfixture.FixtureProvider) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}
}

func fetchStatus(t *testing.T, ds *LuaDataSource, input *service.DataSourceInput) map[string]any {
	t.Helper()
	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return data
}

func TestCrossAccountLua_NoCookies_ReturnsNil(t *testing.T) {
	script := loadCrossAccountScript(t)
	var calls int
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		calls++
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[]}`}
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), nil)

	result, err := ds.Fetch(context.Background(), internalEmployeeInput(""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result with no cookies, got %s", result.Data)
	}
	if calls != 0 {
		t.Fatalf("expected no RBAC HTTP calls, got %d", calls)
	}
}

func TestCrossAccountLua_NonInternal_Forbidden(t *testing.T) {
	script := loadCrossAccountScript(t)
	var calls int
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		calls++
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"uuid":"x"}]}`}
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), nil)

	input := internalEmployeeInput("cross_access_account_number=540155")
	input.Subject.Claims["is_internal"] = false
	input.Subject.Claims["email"] = "bob@example.com"

	data := fetchStatus(t, ds, input)
	if data["status"] != "forbidden" {
		t.Errorf("status=%v, want forbidden", data["status"])
	}
	if calls != 0 {
		t.Fatalf("expected no RBAC HTTP calls, got %d", calls)
	}
}

func TestCrossAccountLua_BypassIsInternal_StillRequiresEmail(t *testing.T) {
	script := loadCrossAccountScript(t)
	cfg := defaultCrossAccountConfig()
	cfg["bypass_is_internal"] = true
	var calls int
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		calls++
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"uuid":"x"}]}`}
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), cfg)

	input := internalEmployeeInput("cross_access_account_number=540155")
	input.Subject.Claims["is_internal"] = false
	input.Subject.Claims["email"] = "tam@example.com"

	data := fetchStatus(t, ds, input)
	if data["status"] != "forbidden" {
		t.Errorf("status=%v, want forbidden", data["status"])
	}
	if calls != 0 {
		t.Fatalf("expected no RBAC HTTP calls, got %d", calls)
	}
}

func TestCrossAccountLua_Approved_ReturnsTargets(t *testing.T) {
	script := loadCrossAccountScript(t)
	wantURL := crossAccountRBACAPI + crossAccountRBACPath + "?query_by=user_id&account=540155&approved_only=true"
	var gotURL, gotIdentity string
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		gotURL = req.URL.String()
		gotIdentity = req.Header.Get("x-rh-identity")
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"data":[{"status":"approved"}]}`,
		}
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), nil)

	data := fetchStatus(t, ds, internalEmployeeInput("cross_access_account_number=540155; cross_access_org_id=target-org"))
	if data["status"] != "allowed" {
		t.Fatalf("status=%v, want allowed", data["status"])
	}
	if data["target_account_number"] != "540155" {
		t.Errorf("target_account_number=%v, want 540155", data["target_account_number"])
	}
	if data["target_org_id"] != "target-org" {
		t.Errorf("target_org_id=%v, want target-org", data["target_org_id"])
	}
	if data["employee_account_number"] != "11111" {
		t.Errorf("employee_account_number=%v, want 11111", data["employee_account_number"])
	}
	if data["employee_org_id"] != "emp-org" {
		t.Errorf("employee_org_id=%v, want emp-org", data["employee_org_id"])
	}
	if gotURL != wantURL {
		t.Errorf("RBAC URL=%q, want %q", gotURL, wantURL)
	}
	if gotIdentity == "" {
		t.Fatal("expected x-rh-identity header")
	}
	raw, err := base64.StdEncoding.DecodeString(gotIdentity)
	if err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal identity: %v", err)
	}
	identity, _ := envelope["identity"].(map[string]any)
	if identity["account_number"] != "11111" {
		t.Errorf("outbound identity account_number=%v, want employee 11111", identity["account_number"])
	}
}

func TestCrossAccountLua_EmptyRBAC_Denied(t *testing.T) {
	script := loadCrossAccountScript(t)
	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET " + crossAccountRBACAPI + crossAccountRBACPath + "?query_by=user_id&account=540155&approved_only=true": {
			StatusCode: 200,
			Body:       `{"data":[]}`,
		},
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), nil)
	data := fetchStatus(t, ds, internalEmployeeInput("cross_access_account_number=540155"))
	if data["status"] != "denied" {
		t.Errorf("status=%v, want denied", data["status"])
	}
}

func TestCrossAccountLua_RBACUnavailable_FetchError(t *testing.T) {
	script := loadCrossAccountScript(t)
	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET " + crossAccountRBACAPI + crossAccountRBACPath + "?query_by=user_id&account=540155&approved_only=true": {
			StatusCode: 503,
			Body:       `{"error":"unavailable"}`,
		},
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), nil)
	_, err := ds.Fetch(context.Background(), internalEmployeeInput("cross_access_account_number=540155"))
	if err == nil {
		t.Fatal("expected Fetch error on RBAC 503")
	}
	if !strings.Contains(err.Error(), "script execution failed") {
		t.Errorf("error=%v, want script execution failed", err)
	}
}

func TestCrossAccountLua_QueryByOrgID(t *testing.T) {
	script := loadCrossAccountScript(t)
	cfg := defaultCrossAccountConfig()
	cfg["query_by"] = "org_id"
	wantURL := crossAccountRBACAPI + crossAccountRBACPath + "?query_by=target_org&org_id=target-org&approved_only=true"
	var gotURL string
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		gotURL = req.URL.String()
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"status":"approved"}]}`}
	})
	ds := newCrossAccountDS(t, script, strictClient(provider), cfg)
	data := fetchStatus(t, ds, internalEmployeeInput("cross_access_org_id=target-org"))
	if data["status"] != "allowed" {
		t.Fatalf("status=%v, want allowed", data["status"])
	}
	if gotURL != wantURL {
		t.Errorf("RBAC URL=%q, want %q", gotURL, wantURL)
	}
}

func TestCrossAccountLua_CacheKey_NoCookiesSkipsCache(t *testing.T) {
	script := loadCrossAccountScript(t)
	ds := newCacheableCrossAccountDS(t, script, http.DefaultClient, nil)
	_, useCache := ds.CacheKey(internalEmployeeInput(""))
	if useCache {
		t.Fatal("expected cache skip when no cross-account cookies")
	}
}

func TestCrossAccountLua_CacheKey_EmployeeAndCookies(t *testing.T) {
	script := loadCrossAccountScript(t)
	var calls int
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		calls++
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"status":"approved"}]}`}
	})
	inner := newCacheableCrossAccountDS(t, script, strictClient(provider), nil)
	cached := NewInMemoryCachingDataSource(inner, NoOpDataSourceObserver{}, WithCacheTTL(5*time.Minute))

	input := internalEmployeeInput("cross_access_account_number=540155")
	if _, err := cached.Fetch(context.Background(), input); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if _, err := cached.Fetch(context.Background(), input); err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 RBAC HTTP call (cache hit), got %d", calls)
	}

	masked, useCache := inner.CacheKey(input)
	if !useCache {
		t.Fatal("expected cacheable key when cookies present")
	}
	if masked.Subject == nil || masked.Subject.Subject != "alice" {
		t.Errorf("cache key subject=%v, want alice", masked.Subject)
	}
}
