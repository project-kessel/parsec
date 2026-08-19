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
		HTTPClient: client,
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
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}
	return ds
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
			if err != nil {
				t.Fatalf("Fetch returned error (want fail-open): %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil fail-open result")
			}
			var data map[string]any
			if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
				t.Fatalf("unmarshal: %v", unmarshalErr)
			}
			if data["synthetic"] != true {
				t.Errorf("synthetic = %v, want true for non-200 response", data["synthetic"])
			}
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
	if err != nil {
		t.Fatalf("Fetch returned error (want fail-open): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil fail-open result")
	}
	var data map[string]any
	if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if data["synthetic"] != true {
		t.Errorf("synthetic = %v, want true for transport error", data["synthetic"])
	}
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
	if err != nil {
		t.Fatalf("Fetch returned error (want fail-open): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil fail-open result")
	}
	var data map[string]any
	if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if data["synthetic"] != true {
		t.Errorf("synthetic = %v, want true for missing username", data["synthetic"])
	}
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

	masked := ds.CacheKey(consoleSubjectForCompliance())
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

// TestExportComplianceLua_CacheKey_NilForSynthetic verifies that no username → full input key (AC7)
// When fetch_cache_key returns nil, CacheKey falls back to the full input.
func TestExportComplianceLua_CacheKey_NilForSynthetic(t *testing.T) {
	script := loadExportComplianceScript(t)
	ds := newCacheableComplianceDS(t, script, http.DefaultClient)

	noUserInput := &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "",
			Claims:  map[string]any{},
		},
	}

	masked := ds.CacheKey(noUserInput)
	// When fetch_cache_key returns nil, CacheKey returns the full input.
	// Verify the result is the full input (not a username-masked subset).
	if masked.Subject != nil && len(masked.Subject.Claims) != 0 {
		// The only valid "full input" behavior for an empty-claims subject:
		// the masked key should also have empty claims (not a username key).
		if _, hasUsername := masked.Subject.Claims["preferred_username"]; hasUsername {
			t.Error("nil cache key: full input should not have a username-masked key")
		}
	}
}

// TestExportComplianceLua_CacheKey_NilForBypassHeader verifies bypass header "0" → full input key (AC8)
// When fetch_cache_key returns nil (bypass), CacheKey falls back to the full input,
// which includes the bypass header — so bypass and normal requests never share a cache slot.
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

	bypassKey := ds.CacheKey(bypassInput)
	normalKey := ds.CacheKey(normalInput)

	// Bypass key must include the bypass header (from the full input fallback)
	// and must differ from the normal username-based key.
	if bypassKey.RequestAttributes == nil || bypassKey.RequestAttributes.Headers == nil {
		t.Fatal("bypass CacheKey should include request_attributes with bypass header")
	}
	if bypassKey.RequestAttributes.Headers["x-rh-insights-gateway-use-compliance-cache"] != "0" {
		t.Errorf("bypass CacheKey missing bypass header, got: %v", bypassKey.RequestAttributes.Headers)
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

	aliceKey := ds.CacheKey(inputAlice)
	bobKey := ds.CacheKey(inputBob)

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
		HTTPClient:   http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	result, err := ds.Fetch(context.Background(), consoleSubjectForCompliance())
	if err != nil {
		t.Fatalf("Fetch returned error (want fail-open for missing config): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil fail-open result")
	}
	var data map[string]any
	if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if data["synthetic"] != true {
		t.Errorf("synthetic = %v, want true for missing config", data["synthetic"])
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
	masked := cacheDs.CacheKey(rhsmInput)
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
	if err != nil {
		t.Fatalf("Fetch returned error (want fail-open): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil fail-open result")
	}
	var data map[string]any
	if unmarshalErr := json.Unmarshal(result.Data, &data); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if data["synthetic"] != true {
		t.Errorf("synthetic = %v, want true for malformed JSON", data["synthetic"])
	}
	if !strings.Contains(string(result.Data), "result_code") {
		t.Errorf("fail-open result must contain result_code field, got: %s", result.Data)
	}
}
