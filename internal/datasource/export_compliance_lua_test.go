package datasource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const complianceAPIURL = "https://export-compliance.example.internal/v1/compliance"

func loadExportComplianceScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "configs", "scripts", "export_compliance.lua")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export_compliance.lua: %v", err)
	}
	return string(b)
}

func consoleSubjectForCompliance() *service.DataSourceInput {
	return &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
			Claims: map[string]any{
				"preferred_username": "alice",
				"organization": map[string]any{
					"id":             "org-1",
					"account_number": "12345",
				},
			},
		},
	}
}

func newComplianceDS(t *testing.T, script string, client *http.Client) *LuaDataSource {
	t.Helper()
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "export_compliance",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"compliance_api": complianceAPIURL,
		}),
		HTTP: httpclient.LuaClient{Client: client},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}
	return ds
}

func newCacheableComplianceDS(t *testing.T, script string, client *http.Client) *CacheableLuaDataSource {
	t.Helper()
	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:   "export_compliance",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"compliance_api": complianceAPIURL,
		}),
		HTTP: httpclient.LuaClient{Client: client},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}
	return ds
}

func assertFailOpenNil(t *testing.T, result *service.DataSourceResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("fail-open should not error, got %v", err)
	}
	if result != nil {
		t.Fatalf("fail-open should return nil result (uncached), got %+v", result)
	}
}

// TestExportComplianceLua_Fetch_Pass verifies a 200 + passing result code → synthetic=false
func TestExportComplianceLua_Fetch_Pass(t *testing.T) {
	script := loadExportComplianceScript(t)
	var gotIdentityHeader, gotAcceptHeader string

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method != http.MethodGet || req.URL.String() != complianceAPIURL {
			return nil
		}
		gotIdentityHeader = req.Header.Get("x-rh-identity")
		gotAcceptHeader = req.Header.Get("Accept")
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"result_code":"","synthetic":false}`,
		}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds := newComplianceDS(t, script, client)
	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]any
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if data["synthetic"] != false {
		t.Errorf("synthetic = %v, want false", data["synthetic"])
	}
	if data["result_code"] != "" {
		t.Errorf("result_code = %v, want empty", data["result_code"])
	}

	// AC2: only x-rh-identity and Accept headers are sent
	if gotIdentityHeader == "" {
		t.Fatal("expected x-rh-identity header on compliance request")
	}
	if gotAcceptHeader != "application/json;charset=UTF-8" {
		t.Errorf("Accept = %q, want application/json;charset=UTF-8", gotAcceptHeader)
	}
}

func TestExportComplianceLua_Fetch_PathWithBaseURL(t *testing.T) {
	script := loadExportComplianceScript(t)

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method != http.MethodGet || req.URL.String() != complianceAPIURL {
			return nil
		}
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"result_code":"","synthetic":false}`,
		}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "export_compliance",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"compliance_api": "/v1/compliance",
		}),
		HTTP: httpclient.LuaClient{Client: client, BaseURL: "https://export-compliance.example.internal"},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var data map[string]any
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if data["synthetic"] != false {
		t.Errorf("synthetic = %v, want false", data["synthetic"])
	}
}

// TestExportComplianceLua_Header_XRhIdentity verifies the outbound identity header contents (AC2)
func TestExportComplianceLua_Header_XRhIdentity(t *testing.T) {
	script := loadExportComplianceScript(t)
	var gotIdentityHeader string

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method != http.MethodGet || req.URL.String() != complianceAPIURL {
			return nil
		}
		gotIdentityHeader = req.Header.Get("x-rh-identity")
		// Verify no extra headers (Authorization) are sent (AC2)
		if req.Header.Get("Authorization") != "" {
			t.Error("expected no Authorization header on compliance request")
		}
		return &httpfixture.Fixture{
			StatusCode: 200,
			Body:       `{"result_code":""}`,
		}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds := newComplianceDS(t, script, client)
	_, _ = ds.Fetch(context.Background(), consoleSubjectForCompliance())

	decoded, err := base64.StdEncoding.DecodeString(gotIdentityHeader)
	if err != nil {
		t.Fatalf("decode x-rh-identity: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		t.Fatalf("parse identity envelope: %v", err)
	}
	identity, ok := envelope["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity in outbound envelope, got %v", envelope)
	}
	user, _ := identity["user"].(map[string]any)
	if user == nil || user["username"] != "alice" {
		t.Errorf("user.username = %v, want alice", user)
	}
	if identity["org_id"] != "org-1" {
		t.Errorf("org_id = %v, want org-1", identity["org_id"])
	}
}

// TestExportComplianceLua_Fetch_FailOpen_Non200 verifies non-200 → synthetic=true (AC3)
func TestExportComplianceLua_Fetch_FailOpen_Non200(t *testing.T) {
	script := loadExportComplianceScript(t)
	cases := []int{500, 403, 503, 429}

	for _, status := range cases {
		t.Run("status_"+http.StatusText(status), func(t *testing.T) {
			provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
				"GET " + complianceAPIURL: {StatusCode: status, Body: `{"error":"boom"}`},
			})
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
					Provider: provider,
					Strict:   true,
				}),
			}
			ds := newComplianceDS(t, script, client)
			result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
			assertFailOpenNil(t, result, err)
		})
	}
}

// TestExportComplianceLua_Fetch_FailOpen_TransportError verifies transport errors → synthetic=true (AC3)
func TestExportComplianceLua_Fetch_FailOpen_TransportError(t *testing.T) {
	script := loadExportComplianceScript(t)
	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET https://other.example/": {StatusCode: 200, Body: `{}`},
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds := newComplianceDS(t, script, client)
	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	assertFailOpenNil(t, result, err)
}

// TestExportComplianceLua_Fetch_FailOpen_MissingUsername verifies no username → synthetic=true (AC3)
func TestExportComplianceLua_Fetch_FailOpen_MissingUsername(t *testing.T) {
	script := loadExportComplianceScript(t)
	input := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "", // empty subject — no username anywhere
			Claims:  map[string]any{},
		},
	}

	ds := newComplianceDS(t, script, &http.Client{})
	result, err := ds.Fetch(context.Background(), input)
	assertFailOpenNil(t, result, err)
}

// TestExportComplianceLua_Fetch_BlockedResultCode verifies a blocking error code is preserved
func TestExportComplianceLua_Fetch_BlockedResultCode(t *testing.T) {
	script := loadExportComplianceScript(t)
	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET " + complianceAPIURL: {
			StatusCode: 200,
			Body:       `{"result_code":"ERROR_T5"}`,
		},
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds := newComplianceDS(t, script, client)
	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	var data map[string]any
	if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if data["result_code"] != "ERROR_T5" {
		t.Errorf("result_code = %v, want ERROR_T5", data["result_code"])
	}
	if data["synthetic"] != false {
		t.Errorf("synthetic = %v, want false for real response", data["synthetic"])
	}
}

// TestExportComplianceLua_CacheKey_Username verifies that username present → cache key contains username (AC6)
func TestExportComplianceLua_CacheKey_Username(t *testing.T) {
	script := loadExportComplianceScript(t)
	ds := newCacheableComplianceDS(t, script, http.DefaultClient)

	masked, useCache := ds.CacheKey(consoleSubjectForCompliance())
	if !useCache {
		t.Fatal("expected cacheable key for username")
	}
	if masked.Subject == nil || masked.Subject.Claims == nil {
		t.Fatalf("expected masked subject claims, got %+v", masked)
	}
	if masked.Subject.Claims["preferred_username"] != "alice" {
		t.Errorf("cache key preferred_username = %v, want alice", masked.Subject.Claims["preferred_username"])
	}
	// Should not include org/account in key (compliance is per-user)
	if _, hasOrg := masked.Subject.Claims["org_id"]; hasOrg {
		t.Error("cache key should not include org_id; compliance is per-user")
	}
}

// TestExportComplianceLua_CacheKey_NilForSynthetic verifies that no username skips the cache (AC7).
func TestExportComplianceLua_CacheKey_NilForSynthetic(t *testing.T) {
	script := loadExportComplianceScript(t)
	ds := newCacheableComplianceDS(t, script, http.DefaultClient)

	noUserInput := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "",
			Claims:  map[string]any{},
		},
	}

	_, useCache := ds.CacheKey(noUserInput)
	if useCache {
		t.Fatal("empty username must skip cache")
	}
}

// TestExportComplianceLua_CacheKey_NilForBypassHeader verifies bypass header "0" skips the cache (AC8).
func TestExportComplianceLua_CacheKey_NilForBypassHeader(t *testing.T) {
	script := loadExportComplianceScript(t)
	ds := newCacheableComplianceDS(t, script, http.DefaultClient)

	bypassInput := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
			Claims: map[string]any{
				"preferred_username": "alice",
			},
		},
		RequestAttributes: &request.RequestAttributes{
			Headers: map[string]string{
				"x-rh-insights-gateway-use-compliance-cache": "0",
			},
		},
	}
	normalInput := consoleSubjectForCompliance()

	_, bypassCache := ds.CacheKey(bypassInput)
	normalKey, normalCache := ds.CacheKey(normalInput)

	if bypassCache {
		t.Fatal("bypass header must skip cache")
	}
	if !normalCache {
		t.Fatal("normal request must be cacheable")
	}

	// Normal key has no bypass header
	if normalKey.RequestAttributes != nil && normalKey.RequestAttributes.Headers != nil {
		if _, hasBypass := normalKey.RequestAttributes.Headers["x-rh-insights-gateway-use-compliance-cache"]; hasBypass {
			t.Error("normal CacheKey should not include bypass header")
		}
	}
}

// TestExportComplianceLua_DifferentUsers verifies that two different users get different cache keys (AC6)
func TestExportComplianceLua_DifferentUsers(t *testing.T) {
	script := loadExportComplianceScript(t)
	ds := newCacheableComplianceDS(t, script, http.DefaultClient)

	inputAlice := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
			Claims: map[string]any{
				"preferred_username": "alice",
				"organization": map[string]any{
					"id": "org-1",
				},
			},
		},
	}
	inputBob := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "bob",
			Claims: map[string]any{
				"preferred_username": "bob",
				"organization": map[string]any{
					"id": "org-1", // same org
				},
			},
		},
	}

	aliceKey, aliceCache := ds.CacheKey(inputAlice)
	bobKey, bobCache := ds.CacheKey(inputBob)
	if !aliceCache || !bobCache {
		t.Fatal("expected cacheable keys for named users")
	}

	if aliceKey.Subject == nil || bobKey.Subject == nil {
		t.Fatal("expected non-nil subjects in cache keys")
	}
	aliceUsername := aliceKey.Subject.Claims["preferred_username"]
	bobUsername := bobKey.Subject.Claims["preferred_username"]
	if aliceUsername == bobUsername {
		t.Errorf("users from same org must have distinct cache keys: both got %v", aliceUsername)
	}
}

// TestExportComplianceLua_MissingConfig verifies that absent compliance_api → fail-open
func TestExportComplianceLua_MissingConfig(t *testing.T) {
	script := loadExportComplianceScript(t)
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:         "export_compliance",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(nil),
		HTTP: httpclient.LuaClient{Client: http.DefaultClient},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	assertFailOpenNil(t, result, err)
}

func TestExportComplianceLua_Fetch_FullComplianceAPIOverridesPath(t *testing.T) {
	script := loadExportComplianceScript(t)

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method != http.MethodGet || req.URL.String() != complianceAPIURL {
			return nil
		}
		return &httpfixture.Fixture{
			StatusCode: 200,
			Body:       `{"result_code":""}`,
		}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "export_compliance",
		Script: script,
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"compliance_api": complianceAPIURL,
		}),
		HTTP: httpclient.LuaClient{Client: client, BaseURL: "https://unused.example"},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result from absolute compliance_api")
	}
}

// TestExportComplianceLua_RHSMTokenShape verifies rhsm-style claims (sub, org_id) are supported
func TestExportComplianceLua_RHSMTokenShape(t *testing.T) {
	script := loadExportComplianceScript(t)
	var gotIdentityHeader string

	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method != http.MethodGet || req.URL.String() != complianceAPIURL {
			return nil
		}
		gotIdentityHeader = req.Header.Get("x-rh-identity")
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"result_code":""}`}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	// RHSM-style: username in "sub", org in "org_id"
	rhsmInput := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "rhsm-user",
			Claims: map[string]any{
				"sub":    "rhsm-user",
				"org_id": "rhsm-org",
			},
		},
	}

	ds := newComplianceDS(t, script, client)
	result, err := ds.Fetch(context.Background(), rhsmInput)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(gotIdentityHeader)
	if err != nil {
		t.Fatalf("decode x-rh-identity: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		t.Fatalf("parse identity envelope: %v", err)
	}
	identity, ok := envelope["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity in outbound envelope")
	}
	user, _ := identity["user"].(map[string]any)
	if user == nil || user["username"] != "rhsm-user" {
		t.Errorf("user.username = %v, want rhsm-user", user)
	}

	var data map[string]any
	if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
		t.Fatalf("unmarshal result: %v", unmarshalErr)
	}
	if data["synthetic"] == true {
		t.Error("RHSM token shape should yield real response, not synthetic")
	}

	// Cache key should use "sub" as username
	cacheDs := newCacheableComplianceDS(t, script, client)
	masked, useCache := cacheDs.CacheKey(rhsmInput)
	if !useCache {
		t.Fatal("RHSM shape should be cacheable")
	}
	if masked.Subject == nil || masked.Subject.Claims["preferred_username"] != "rhsm-user" {
		t.Errorf("cache key for RHSM: expected preferred_username=rhsm-user, got %v", masked.Subject)
	}
}

// TestExportComplianceLua_Fetch_FailOpen_MalformedJSON verifies malformed JSON response → synthetic=true (AC3)
func TestExportComplianceLua_Fetch_FailOpen_MalformedJSON(t *testing.T) {
	script := loadExportComplianceScript(t)
	provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
		"GET " + complianceAPIURL: {StatusCode: 200, Body: `{not-json`},
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}

	ds := newComplianceDS(t, script, client)
	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	assertFailOpenNil(t, result, err)
}

func TestExportComplianceLua_Cached_SyntheticNotStored(t *testing.T) {
	script := loadExportComplianceScript(t)
	status := 503
	body := `{"error":"unavailable"}`
	var calls int
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.URL.String() != complianceAPIURL {
			return nil
		}
		calls++
		return &httpfixture.Fixture{StatusCode: status, Body: body}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}
	inner := newCacheableComplianceDS(t, script, client)
	cached := NewInMemoryCachingDataSource(inner, NoOpDataSourceObserver{}, WithCacheTTL(24*time.Hour))

	first, err := cached.Fetch(context.Background(), consoleSubjectForCompliance())
	assertFailOpenNil(t, first, err)

	status = 200
	body = `{"result_code":"ERROR_T5"}`
	second, err := cached.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if second == nil {
		t.Fatal("expected blocked result after service recovery, not cached fail-open")
	}
	var data map[string]any
	if err := json.Unmarshal(second.Data, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if data["result_code"] != "ERROR_T5" {
		t.Errorf("result_code = %v, want ERROR_T5", data["result_code"])
	}
	if calls != 2 {
		t.Fatalf("expected 2 compliance HTTP calls, got %d", calls)
	}
}

func TestExportComplianceLua_Cached_BypassSkipsReadAndWrite(t *testing.T) {
	script := loadExportComplianceScript(t)
	var calls int
	var resultCode string
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.URL.String() != complianceAPIURL {
			return nil
		}
		calls++
		return &httpfixture.Fixture{StatusCode: 200, Body: `{"result_code":"` + resultCode + `"}`}
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}
	inner := newCacheableComplianceDS(t, script, client)
	cached := NewInMemoryCachingDataSource(inner, NoOpDataSourceObserver{}, WithCacheTTL(24*time.Hour))

	resultCode = ""
	if _, err := cached.Fetch(context.Background(), consoleSubjectForCompliance()); err != nil {
		t.Fatalf("seed Fetch: %v", err)
	}

	bypassInput := consoleSubjectForCompliance()
	bypassInput.RequestAttributes = &request.RequestAttributes{
		Headers: map[string]string{
			"x-rh-insights-gateway-use-compliance-cache": "0",
		},
	}
	resultCode = "ERROR_T5"
	if _, err := cached.Fetch(context.Background(), bypassInput); err != nil {
		t.Fatalf("bypass Fetch: %v", err)
	}

	cachedAgain, err := cached.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("third Fetch: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(cachedAgain.Data, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if data["result_code"] != "" {
		t.Errorf("normal cache must not be overwritten by bypass, got result_code=%v", data["result_code"])
	}
	if calls != 2 {
		t.Fatalf("expected 2 HTTP calls (seed + bypass; third is cache hit), got %d", calls)
	}
}
