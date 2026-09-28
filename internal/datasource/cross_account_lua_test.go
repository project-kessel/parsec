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

	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const rbacBaseURL = "https://rbac.example.internal"
const rbacListPath = "/api/rbac/v1/cross-account-requests/"
const rbacApprovedBody = `{"data":[{"status":"approved","target_account":"999999","target_org":"target-org"}]}`

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

func newCrossAccountDS(t *testing.T, script string, client *http.Client, cfg map[string]any) *LuaDataSource {
	t.Helper()
	if cfg == nil {
		cfg = defaultCrossAccountConfig()
	}
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:         "cross_account",
		Script:       script,
		ConfigSource: luaservices.NewMapConfigSource(cfg),
		HTTP:         httpclient.LuaClient{Client: client, BaseURL: rbacBaseURL},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}
	return ds
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
	ds := newCrossAccountDS(t, script, &http.Client{Timeout: 5 * time.Second}, nil)

	input := internalEmployeeSubject()
	input.Subject.Claims["idp"] = "https://sso.redhat.com/auth/realms/redhat-external"
	input.Subject.Claims["is_internal"] = false

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "forbidden" {
		t.Fatalf("error=%v, want forbidden", payload["error"])
	}
}

func TestCrossAccountLua_NonRedhatEmailForbidden(t *testing.T) {
	script := loadCrossAccountScript(t)
	ds := newCrossAccountDS(t, script, &http.Client{Timeout: 5 * time.Second}, nil)

	input := internalEmployeeSubject()
	input.Subject.Claims["email"] = "tam@example.com"

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "forbidden" {
		t.Fatalf("error=%v, want forbidden", payload["error"])
	}
}

func TestCrossAccountLua_RBACDenied(t *testing.T) {
	script := loadCrossAccountScript(t)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       `{"data":[]}`,
					}
				}
				return nil
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(context.Background(), internalEmployeeSubject())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "rbac_denied" {
		t.Fatalf("error=%v, want rbac_denied", payload["error"])
	}
}

func TestCrossAccountLua_RBACApproved(t *testing.T) {
	script := loadCrossAccountScript(t)
	var gotURL string
	var gotIdentityHeader string
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					gotURL = req.URL.String()
					gotIdentityHeader = req.Header.Get("x-rh-identity")
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       rbacApprovedBody,
					}
				}
				return nil
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(context.Background(), internalEmployeeSubject())
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
	if payload["employee_account_number"] != "111111" {
		t.Fatalf("employee_account_number=%v", payload["employee_account_number"])
	}
	if payload["employee_org_id"] != "emp-org" {
		t.Fatalf("employee_org_id=%v", payload["employee_org_id"])
	}
	if !strings.Contains(gotURL, "query_by=user_id") || !strings.Contains(gotURL, "org_id=target-org") {
		t.Fatalf("unexpected RBAC URL: %s", gotURL)
	}
	if gotIdentityHeader == "" {
		t.Fatal("expected x-rh-identity header on RBAC request")
	}
	raw, err := base64.StdEncoding.DecodeString(gotIdentityHeader)
	if err != nil {
		t.Fatalf("decode x-rh-identity: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal identity envelope: %v", err)
	}
	identity, ok := envelope["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity envelope missing identity: %+v", envelope)
	}
	if identity["account_number"] != "111111" {
		t.Fatalf("unexpected account_number in identity envelope: %+v", identity)
	}
	user, ok := identity["user"].(map[string]any)
	if !ok || user["username"] != "tam@redhat.com" {
		t.Fatalf("unexpected user in identity envelope: %+v", identity)
	}
	if user["user_id"] != "emp-1" {
		t.Fatalf("unexpected user_id in identity envelope: %+v", identity)
	}
}

func TestCrossAccountLua_RHSMIdentityHeaderUsesCanonicalClaims(t *testing.T) {
	script := loadCrossAccountScript(t)
	var gotIdentityHeader string
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				gotIdentityHeader = req.Header.Get("x-rh-identity")
				return &httpfixture.Fixture{StatusCode: 200, Body: rbacApprovedBody}
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	input := internalEmployeeSubject()
	input.Subject.Claims["sub"] = "f:federated-id:rhsm-user"
	input.Subject.Claims["user_id"] = "58962552"
	delete(input.Subject.Claims, "preferred_username")
	input.Subject.Claims["account_number"] = "222222"
	input.Subject.Claims["account_id"] = "employee-org"

	if _, err := ds.Fetch(context.Background(), input); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(gotIdentityHeader)
	if err != nil {
		t.Fatalf("decode x-rh-identity: %v", err)
	}
	var envelope struct {
		Identity struct {
			AccountNumber string `json:"account_number"`
			OrgID         string `json:"org_id"`
			User          struct {
				Username string `json:"username"`
				UserID   string `json:"user_id"`
			} `json:"user"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal identity envelope: %v", err)
	}
	if envelope.Identity.AccountNumber != "222222" {
		t.Errorf("account_number=%q, want JWT account_number", envelope.Identity.AccountNumber)
	}
	if envelope.Identity.OrgID != "employee-org" {
		t.Errorf("org_id=%q, want JWT account_id", envelope.Identity.OrgID)
	}
	if envelope.Identity.User.UserID != "58962552" {
		t.Errorf("user_id=%q, want JWT user_id", envelope.Identity.User.UserID)
	}
	if envelope.Identity.User.Username != "" {
		t.Errorf("username=%q, want empty without a username claim", envelope.Identity.User.Username)
	}
}

func TestCrossAccountLua_MissingUserIDDoesNotUseSubject(t *testing.T) {
	script := loadCrossAccountScript(t)
	var calls int
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				calls++
				return &httpfixture.Fixture{StatusCode: 200, Body: rbacApprovedBody}
			}),
			Strict: true,
		}),
	}
	input := internalEmployeeSubject()
	input.Subject.Claims["sub"] = "f:federated-id:rhsm-user"
	delete(input.Subject.Claims, "user_id")

	result, err := newCrossAccountDS(t, script, client, nil).Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "infra" {
		t.Fatalf("error=%v, want infra without JWT user_id", payload["error"])
	}
	if calls != 0 {
		t.Fatalf("RBAC calls=%d, want 0 without JWT user_id", calls)
	}
}

func TestCrossAccountLua_RBACUnavailable(t *testing.T) {
	script := loadCrossAccountScript(t)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					return &httpfixture.Fixture{StatusCode: 503, Body: "unavailable"}
				}
				return nil
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(context.Background(), internalEmployeeSubject())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "infra" {
		t.Fatalf("error=%v, want infra", payload["error"])
	}
}

func TestCrossAccountLua_BypassIsInternalWithRedhatEmail(t *testing.T) {
	script := loadCrossAccountScript(t)
	cfg := defaultCrossAccountConfig()
	cfg["cross_access_bypass_is_internal"] = true

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       rbacApprovedBody,
					}
				}
				return nil
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, cfg)

	input := internalEmployeeSubject()
	input.Subject.Claims["idp"] = "https://sso.redhat.com/auth/realms/redhat-external"
	input.Subject.Claims["is_internal"] = false

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["active"] != true {
		t.Fatalf("active=%v, want true with bypass", payload["active"])
	}
}

func TestCrossAccountLua_AccountCookieOnlyEmptyOrg(t *testing.T) {
	script := loadCrossAccountScript(t)
	var rbacCalls int
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					rbacCalls++
				}
				return nil
			}),
			Strict: false,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	input := internalEmployeeSubject()
	input.RequestAttributes.Headers["cookie"] = "cross_access_account_number=999999"

	result, err := ds.Fetch(context.Background(), input)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "rbac_denied" {
		t.Fatalf("error=%v, want rbac_denied", payload["error"])
	}
	if rbacCalls != 0 {
		t.Fatalf("RBAC called %d times, want 0 when org cookie missing", rbacCalls)
	}
}

func TestCrossAccountLua_RBACRecordNotApproved(t *testing.T) {
	script := loadCrossAccountScript(t)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       `{"data":[{"status":"pending","target_account":"999999","target_org":"target-org"}]}`,
					}
				}
				return nil
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(context.Background(), internalEmployeeSubject())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "rbac_denied" {
		t.Fatalf("error=%v, want rbac_denied when RBAC record status is not approved", payload["error"])
	}
}

func TestCrossAccountLua_RBACRecordMismatch(t *testing.T) {
	script := loadCrossAccountScript(t)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), rbacBaseURL+rbacListPath) {
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       `{"data":[{"status":"approved","target_account":"999999","target_org":"wrong-org"}]}`,
					}
				}
				return nil
			}),
			Strict: true,
		}),
	}
	ds := newCrossAccountDS(t, script, client, nil)

	result, err := ds.Fetch(context.Background(), internalEmployeeSubject())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	payload := decodeCrossAccountResult(t, result)
	if payload["error"] != "rbac_denied" {
		t.Fatalf("error=%v, want rbac_denied when cookie org differs from RBAC record", payload["error"])
	}
}
