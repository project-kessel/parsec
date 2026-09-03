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

func identityPolicyDS(t *testing.T) service.DataSource {
	t.Helper()
	ds, err := datasource.NewStaticDataSource("identity-policy", map[string]any{
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
		"enforce_idp_auth":      false,
	})
	if err != nil {
		t.Fatalf("identity-policy: %v", err)
	}
	return ds
}

func consoleUserSubject() *trust.Result {
	return &trust.Result{
		Subject: "alice",
		Claims: map[string]any{
			"scope":              "api.console openid",
			"preferred_username": "alice",
			"email":              "alice@redhat.com",
			"given_name":         "Alice",
			"family_name":        "User",
			"is_internal":        true,
			"organization": map[string]any{
				"id":             "emp-org",
				"account_number": "11111",
			},
		},
	}
}

func mapConsole(t *testing.T, extra ...service.DataSource) (service.MappingResult, error) {
	t.Helper()
	m, err := mapper.NewCELMapper(loadScript(t, "redhat_identity.cel"))
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}
	registry := service.NewDataSourceRegistry()
	registry.Register(identityPolicyDS(t))
	for _, ds := range extra {
		registry.Register(ds)
	}
	subject := consoleUserSubject()
	return m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
}

func TestRedHatIdentityCEL_CrossAccountAllowed(t *testing.T) {
	ca, err := datasource.NewStaticDataSource("cross_account", map[string]any{
		"status":                  "allowed",
		"target_account_number":   "540155",
		"target_org_id":           "target-org",
		"employee_account_number": "11111",
		"employee_org_id":         "emp-org",
	})
	if err != nil {
		t.Fatalf("cross_account: %v", err)
	}
	result, err := mapConsole(t, ca)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("Decision=%+v, want Allow", result.Decision)
	}
	identity := result.Claims["identity"].(map[string]any)
	if identity["account_number"] != "540155" {
		t.Errorf("account_number=%v, want 540155", identity["account_number"])
	}
	if identity["org_id"] != "target-org" {
		t.Errorf("org_id=%v, want target-org", identity["org_id"])
	}
	if identity["employee_account_number"] != "11111" {
		t.Errorf("employee_account_number=%v", identity["employee_account_number"])
	}
	if identity["employee_org_id"] != "emp-org" {
		t.Errorf("employee_org_id=%v", identity["employee_org_id"])
	}
	user := identity["user"].(map[string]any)
	if user["is_org_admin"] != false {
		t.Errorf("is_org_admin=%v, want false", user["is_org_admin"])
	}
	internal := identity["internal"].(map[string]any)
	if internal["cross_access"] != true {
		t.Errorf("cross_access=%v, want true", internal["cross_access"])
	}
}

func TestRedHatIdentityCEL_CrossAccountForbidden(t *testing.T) {
	ca, err := datasource.NewStaticDataSource("cross_account", map[string]any{
		"status": "forbidden",
	})
	if err != nil {
		t.Fatalf("cross_account: %v", err)
	}
	result, err := mapConsole(t, ca)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("Action=%q, want deny", result.Decision.Action)
	}
	if result.Decision.OAuthError != service.OAuthAccessDenied {
		t.Errorf("OAuthError=%q, want access_denied", result.Decision.OAuthError)
	}
	if result.Decision.Message != "Cross account access is forbidden." {
		t.Errorf("Message=%q", result.Decision.Message)
	}
}

func TestRedHatIdentityCEL_CrossAccountDenied(t *testing.T) {
	ca, err := datasource.NewStaticDataSource("cross_account", map[string]any{
		"status": "denied",
	})
	if err != nil {
		t.Fatalf("cross_account: %v", err)
	}
	result, err := mapConsole(t, ca)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.OAuthError != service.OAuthAccessDenied {
		t.Errorf("OAuthError=%q, want access_denied", result.Decision.OAuthError)
	}
	if result.Decision.Message != "Access denied from RBAC on cross-access check." {
		t.Errorf("Message=%q", result.Decision.Message)
	}
}

func TestRedHatIdentityCEL_NoCookiesUnchanged(t *testing.T) {
	result, err := mapConsole(t)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("Decision=%+v, want Allow", result.Decision)
	}
	identity := result.Claims["identity"].(map[string]any)
	if identity["account_number"] != "11111" {
		t.Errorf("account_number=%v, want 11111", identity["account_number"])
	}
	if _, ok := identity["employee_account_number"]; ok {
		t.Errorf("employee_account_number present without cross-account: %v", identity["employee_account_number"])
	}
	internal := identity["internal"].(map[string]any)
	if internal["cross_access"] != false {
		t.Errorf("cross_access=%v, want false", internal["cross_access"])
	}
}

type fatalDataSource struct{ name string }

func (d fatalDataSource) Name() string { return d.name }
func (d fatalDataSource) Fetch(context.Context, *service.DataSourceInput) (*service.DataSourceResult, error) {
	return nil, errors.New("rbac down")
}

func TestRedHatIdentityCEL_RBACErrorIsInternal(t *testing.T) {
	_, err := mapConsole(t, fatalDataSource{name: "cross_account"})
	if err == nil {
		t.Fatal("expected error from RBAC fetch failure")
	}
}

func TestRedHatIdentityCEL_CertAuthDoesNotCallDS(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}
	registry := service.NewDataSourceRegistry()
	registry.Register(fatalDataSource{name: "cross_account"})
	subject := &trust.Result{
		Issuer: "x509://cn=test",
		Claims: map[string]any{
			"account_number": "1",
			"org_id":         "2",
			"cn":             "test",
			"cert_type":      "system",
		},
	}
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("cert-auth Map should not call cross_account: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("Decision=%+v, want Allow", result.Decision)
	}
}

func TestRedHatIdentityCEL_MissingDS_Skip(t *testing.T) {
	result, err := mapConsole(t)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("missing DS should skip, got %+v", result.Decision)
	}
}
