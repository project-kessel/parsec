package scripts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestRedHatIdentityCEL_Compiles(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	if _, err := mapper.NewCELMapper(script); err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}
}

func TestRedHatIdentityCEL_UnsignedJSONSSO(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	bop, err := datasource.NewStaticDataSource("bop-user", map[string]any{
		"account_number": "540155",
		"org_id":         "54321",
		"username":       "testuser",
		"email":          "testuser@redhat.com",
		"first_name":     "Test",
		"last_name":      "User",
		"is_active":      true,
		"is_org_admin":   true,
		"is_internal":    false,
		"locale":         "en_US",
		"user_id":        "98765",
	})
	if err != nil {
		t.Fatalf("NewStaticDataSource: %v", err)
	}

	registry := service.NewDataSourceRegistry()
	registry.Register(bop)

	subject := &trust.Result{
		Subject: "redhat:user:sso:98765",
		Issuer:  trust.UnsignedJSONTokenTypeURN,
	}
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("Decision=%+v, want Allow", result.Decision)
	}

	identity, ok := result.Claims["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity=%T, want map", result.Claims["identity"])
	}
	user, ok := identity["user"].(map[string]any)
	if !ok {
		t.Fatalf("identity.user=%T, want map", identity["user"])
	}
	if user["user_id"] != "98765" {
		t.Errorf("user_id=%v, want 98765", user["user_id"])
	}
	if user["username"] != "testuser" {
		t.Errorf("username=%v, want testuser", user["username"])
	}
	if identity["org_id"] != "54321" {
		t.Errorf("org_id=%v, want 54321", identity["org_id"])
	}

	if _, ok := result.Claims["entitlements"]; !ok {
		t.Error("missing entitlements key in unsigned JSON envelope")
	}
}

func TestRedHatIdentityCEL_UnsignedJSONUnsupportedNamespace(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := &trust.Result{
		Subject: "redhat:system:cn-example",
		Issuer:  trust.UnsignedJSONTokenTypeURN,
	}
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject: subject,
		Actor:   trust.AnonymousResult(),
		DataSourceInput: &service.DataSourceInput{
			Subject: subject,
		},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("Action=%q, want deny", result.Decision.Action)
	}
	if result.Decision.ExchangeError == nil {
		t.Fatal("expected ExchangeError")
	}
	if result.Decision.Reason != service.AbortReasonInvalidSubject {
		t.Errorf("Reason=%q, want %q", result.Decision.Reason, service.AbortReasonInvalidSubject)
	}
	if result.Decision.Message != "unsupported unsigned_json subject namespace" {
		t.Errorf("Message=%q", result.Decision.Message)
	}
}

func TestRedHatIdentityCEL_UnsignedJSONUserNotFound(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	bop, err := datasource.NewStaticDataSource("bop-user", map[string]any{
		"error": "user_not_found",
	})
	if err != nil {
		t.Fatalf("NewStaticDataSource: %v", err)
	}

	registry := service.NewDataSourceRegistry()
	registry.Register(bop)

	subject := &trust.Result{
		Subject: "redhat:user:sso:99999",
		Issuer:  trust.UnsignedJSONTokenTypeURN,
	}
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("Action=%q, want deny", result.Decision.Action)
	}
	if result.Decision.ExchangeError == nil {
		t.Fatal("expected ExchangeError")
	}
	if result.Decision.Reason != service.AbortReasonInvalidSubject {
		t.Errorf("Reason=%q, want %q", result.Decision.Reason, service.AbortReasonInvalidSubject)
	}
	if result.Decision.Message != "user_not_found" {
		t.Errorf("Message=%q, want user_not_found", result.Decision.Message)
	}
}

func TestRedHatIdentityCEL_UnsignedJSONBOPError(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	// No "bop-user" datasource registered — simulates BOP infrastructure failure
	registry := service.NewDataSourceRegistry()

	subject := &trust.Result{
		Subject: "redhat:user:sso:12345",
		Issuer:  trust.UnsignedJSONTokenTypeURN,
	}
	_, err = m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err == nil {
		t.Fatal("expected error from fail(), got nil")
	}
	var mf *service.MappingFailure
	if !errors.As(err, &mf) {
		t.Fatalf("expected MappingFailure, got %T: %v", err, err)
	}
	if mf.Message != "bop_enrichment_failed" {
		t.Errorf("Message=%q, want bop_enrichment_failed", mf.Message)
	}
}

func consoleJWTSubject() *trust.Result {
	return &trust.Result{
		Subject:  "user-1",
		Audience: []string{"api.console"},
		Claims: map[string]any{
			"sub":                "user-1",
			"preferred_username": "alice",
			"email":              "alice@redhat.com",
			"scope":              "api.console openid",
			"idp":                "https://sso.redhat.com/auth/realms/internal",
			"user_id":            "user-1",
			"organization": map[string]any{
				"id":             "org-1",
				"account_number": "111111",
			},
			"realm_access": map[string]any{
				"roles": []any{"admin:org:all"},
			},
		},
	}
}

func crossAccountRegistry(crossAccount map[string]any) *service.DataSourceRegistry {
	registry := service.NewDataSourceRegistry()
	policy, err := datasource.NewStaticDataSource("identity-policy", map[string]any{
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
		"enforce_idp_auth":      false,
	})
	if err != nil {
		panic(err)
	}
	registry.Register(policy)
	if crossAccount != nil {
		ds, err := datasource.NewStaticDataSource("cross_account", crossAccount)
		if err != nil {
			panic(err)
		}
		registry.Register(ds)
	}
	return registry
}

func TestRedHatIdentityCEL_CrossAccountForbidden(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := consoleJWTSubject()
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: crossAccountRegistry(map[string]any{"error": "forbidden"}),
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("Action=%q, want deny", result.Decision.Action)
	}
	if result.Decision.Message != "Cross account access is forbidden." {
		t.Errorf("Message=%q", result.Decision.Message)
	}
}

func TestRedHatIdentityCEL_CrossAccountRBACDenied(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := consoleJWTSubject()
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: crossAccountRegistry(map[string]any{"error": "rbac_denied"}),
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("Action=%q, want deny", result.Decision.Action)
	}
	if result.Decision.Message != "Access denied from RBAC on cross-access check." {
		t.Errorf("Message=%q", result.Decision.Message)
	}
}

func TestRedHatIdentityCEL_CrossAccountInfraFailure(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := consoleJWTSubject()
	_, err = m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: crossAccountRegistry(map[string]any{"error": "infra"}),
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err == nil {
		t.Fatal("expected fail() error")
	}
	var mf *service.MappingFailure
	if !errors.As(err, &mf) {
		t.Fatalf("expected MappingFailure, got %T: %v", err, err)
	}
	if mf.Message != "cross_account_check_failed" {
		t.Errorf("Message=%q", mf.Message)
	}
}

func TestRedHatIdentityCEL_CrossAccountActiveSwap(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := consoleJWTSubject()
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject: subject,
		Actor:   trust.AnonymousResult(),
		DataSourceRegistry: crossAccountRegistry(map[string]any{
			"active":                  true,
			"target_account_number":   "999999",
			"target_org_id":           "target-org",
			"employee_account_number": "111111",
			"employee_org_id":         "org-1",
		}),
		DataSourceInput: &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("Decision=%+v, want Allow", result.Decision)
	}

	identity, ok := result.Claims["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity=%T", result.Claims["identity"])
	}
	if identity["account_number"] != "999999" {
		t.Errorf("account_number=%v", identity["account_number"])
	}
	if identity["employee_account_number"] != "111111" {
		t.Errorf("employee_account_number=%v", identity["employee_account_number"])
	}
	internal, ok := identity["internal"].(map[string]any)
	if !ok {
		t.Fatalf("internal=%T", identity["internal"])
	}
	if internal["cross_access"] != true {
		t.Errorf("cross_access=%v", internal["cross_access"])
	}
	user, ok := identity["user"].(map[string]any)
	if !ok {
		t.Fatalf("user=%T", identity["user"])
	}
	if user["is_org_admin"] != false {
		t.Errorf("is_org_admin=%v", user["is_org_admin"])
	}
}

func TestRedHatIdentityCEL_CrossAccountInactiveNoEmployeeFields(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := consoleJWTSubject()
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: crossAccountRegistry(map[string]any{"active": false}),
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	identity, ok := result.Claims["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity=%T", result.Claims["identity"])
	}
	if _, ok := identity["employee_account_number"]; ok {
		t.Error("expected no employee_account_number when inactive")
	}
	internal, ok := identity["internal"].(map[string]any)
	if !ok {
		t.Fatalf("internal=%T", identity["internal"])
	}
	if internal["cross_access"] != false {
		t.Errorf("cross_access=%v", internal["cross_access"])
	}
}
