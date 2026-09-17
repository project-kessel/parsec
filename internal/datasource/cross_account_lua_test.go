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

	auditctx "github.com/project-kessel/parsec/internal/audit"
	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const rbacBaseURL = "https://rbac.example.internal"
const rbacListPath = "/api/rbac/v1/cross-account-requests/"

// httpClientWithBaseURL wraps an httpfixture transport and prepends baseURL to relative paths
func httpClientWithBaseURL(transport *httpfixture.Transport, baseURL string) *http.Client {
	return &http.Client{
		Transport: &baseURLTransport{base: baseURL, rt: transport},
	}
}

type baseURLTransport struct {
	base string
	rt   http.RoundTripper
}

func (t *baseURLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.String(), "http://") && !strings.HasPrefix(req.URL.String(), "https://") {
		req.URL.Scheme = "https"
		req.URL.Host = strings.TrimPrefix(t.base, "https://")
	}
	return t.rt.RoundTrip(req)
}

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
		"rbac_path":                       rbacListPath,
		"approved_only":                   "true",
		"internal_idp_target":             "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled":           false,
		"cross_access_bypass_is_internal": false,
		"cross_access_query_by":           "account",
		"employee_email_suffix":           "@redhat.com",
	}
}

func internalEmployeeSubject() *service.DataSourceInput {
	return &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "emp-1",
			Claims: map[string]any{
				"sub":                "emp-1",
				"user_id":            "emp-1",
				"preferred_username": "tam@redhat.com",
				"email":              "tam@redhat.com",
				"idp":                "https://sso.redhat.com/auth/realms/internal",
				"organization": map[string]any{
					"id":             "emp-org",
					"account_number": "111111",
				},
			},
		},
		RequestAttributes: &request.RequestAttributes{
			Headers: map[string]string{
				"cookie": "cross_access_account_number=999999; cross_access_org_id=target-org",
			},
		},
	}
}

func newCrossAccountDSWithCollector(t *testing.T, script string, client *http.Client, cfg map[string]any, ctx context.Context) *LuaDataSource {
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

func newCrossAccountDS(t *testing.T, script string, client *http.Client, cfg map[string]any) *LuaDataSource {
	return newCrossAccountDSWithCollector(t, script, client, cfg, context.Background())
}

func decodeCrossAccountResult(t *testing.T, result *service.DataSourceResult) map[string]any {
	t.Helper()
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	var payload map[string]any
	if err := json.Unmarshal(result.Data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return payload
}

func TestCrossAccountLua_NoCookies(t *testing.T) {
	script := loadCrossAccountScript(t)
	ds := newCrossAccountDS(t, script, &http.Client{Timeout: 5 * time.Second}, nil)

	input := internalEmployeeSubject()
	input.RequestAttributes.Headers["cookie"] = ""

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["active"] != false {
		t.Fatalf("active=%v, want false", payload["active"])
	}
}

func TestCrossAccountLua_NonInternalForbidden(t *testing.T) {
	script := loadCrossAccountScript(t)
	// Create context with audit collector
	collector := &auditctx.Collector{}
	ctx := auditctx.WithReporter(context.Background(), collector)

	ds := newCrossAccountDS(t, script, &http.Client{Timeout: 5 * time.Second}, nil)

	input := internalEmployeeSubject()
	input.Subject.Claims["idp"] = "https://sso.redhat.com/auth/realms/redhat-external"
	input.Subject.Claims["is_internal"] = false

	result, err := ds.Fetch(ctx, input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "forbidden" {
		t.Fatalf("error=%v, want forbidden", payload["error"])
	}

	// Verify audit signal was recorded
	signals := collector.Signals()
	if len(signals) == 0 {
		t.Fatal("expected audit signal for forbidden access")
	}
	signal := signals[0]
	if signal.Operation != "cross_account_access" {
		t.Fatalf("signal.Operation=%v, want cross_account_access", signal.Operation)
	}
	if signal.Outcome != "denied" {
		t.Fatalf("signal.Outcome=%v, want denied", signal.Outcome)
	}
	if signal.ReasonCode != "cross_account_denied" {
		t.Fatalf("signal.ReasonCode=%v, want cross_account_denied", signal.ReasonCode)
	}
}

func TestCrossAccountLua_RBACApproved(t *testing.T) {
	script := loadCrossAccountScript(t)
	// Create context with audit collector
	collector := &auditctx.Collector{}
	ctx := auditctx.WithReporter(context.Background(), collector)

	client := httpClientWithBaseURL(
		httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, rbacListPath) {
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       `{"data":[{"status":"approved"}]}`,
					}
				}
				return nil
			}),
			Strict: true,
		}),
		rbacBaseURL,
	)
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(ctx, internalEmployeeSubject())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["active"] != true {
		t.Fatalf("active=%v, want true", payload["active"])
	}
	if payload["target_account_number"] != "999999" {
		t.Fatalf("target_account_number=%v", payload["target_account_number"])
	}
	if payload["target_org_id"] != "target-org" {
		t.Fatalf("target_org_id=%v", payload["target_org_id"])
	}

	// Verify audit signal was recorded for successful access
	signals := collector.Signals()
	if len(signals) == 0 {
		t.Fatal("expected audit signal for approved access")
	}
	signal := signals[0]
	if signal.Operation != "cross_account_access" {
		t.Fatalf("signal.Operation=%v, want cross_account_access", signal.Operation)
	}
	if signal.Outcome != "success" {
		t.Fatalf("signal.Outcome=%v, want success", signal.Outcome)
	}
	if signal.Metadata["target_account_number"] != "999999" {
		t.Fatalf("signal.Metadata[target_account_number]=%v, want 999999", signal.Metadata["target_account_number"])
	}
}

func TestCrossAccountLua_RBACUnavailable(t *testing.T) {
	script := loadCrossAccountScript(t)
	// Create context with audit collector
	collector := &auditctx.Collector{}
	ctx := auditctx.WithReporter(context.Background(), collector)

	client := httpClientWithBaseURL(
		httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, rbacListPath) {
					return &httpfixture.Fixture{StatusCode: 503, Body: "unavailable"}
				}
				return nil
			}),
			Strict: true,
		}),
		rbacBaseURL,
	)
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(ctx, internalEmployeeSubject())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "infra" {
		t.Fatalf("error=%v, want infra", payload["error"])
	}

	// Verify audit signal was recorded for infrastructure failure
	signals := collector.Signals()
	if len(signals) == 0 {
		t.Fatal("expected audit signal for infra failure")
	}
	signal := signals[0]
	if signal.Operation != "cross_account_access" {
		t.Fatalf("signal.Operation=%v, want cross_account_access", signal.Operation)
	}
	if signal.Outcome != "failure" {
		t.Fatalf("signal.Outcome=%v, want failure", signal.Outcome)
	}
	if signal.ReasonCode != "dependency_failure" {
		t.Fatalf("signal.ReasonCode=%v, want dependency_failure", signal.ReasonCode)
	}
}
