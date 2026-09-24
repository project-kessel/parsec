package mapper

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func identityPolicyDS() service.DataSource {
	ds, _ := newStaticDS("identity-policy", map[string]any{
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
	})
	return ds
}

func registryWithIdentityPolicy() *service.DataSourceRegistry {
	reg := service.NewDataSourceRegistry()
	reg.Register(identityPolicyDS())
	return reg
}

func newStaticDS(name string, data map[string]any) (service.DataSource, error) {
	marshaled, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &staticDS{name: name, data: marshaled}, nil
}

type staticDS struct {
	name string
	data []byte
}

func (s *staticDS) Name() string { return s.name }
func (s *staticDS) Fetch(context.Context, *service.DataSourceInput) (*service.DataSourceResult, error) {
	return &service.DataSourceResult{Data: s.data, ContentType: service.ContentTypeJSON}, nil
}

func TestRedHatIdentityMapper_NilInput(t *testing.T) {
	m := NewRedHatIdentityMapper()
	_, err := m.Map(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestRedHatIdentityMapper_Impersonation(t *testing.T) {
	m := NewRedHatIdentityMapper()
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject: &trust.Result{
			Claims: claims.Claims{"impersonated": true},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeny(t, result, service.AbortReasonInvalidSubject, "impersonated tokens are not accepted")
}

func TestRedHatIdentityMapper_RegistryAuth(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	m := NewRedHatIdentityMapper(WithRedHatIdentityClock(clk))

	t.Run("with org_id", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Subject: "testuser",
				Issuer:  "https://container-registry-authorizer.api.redhat.com",
				Claims:  claims.Claims{"org_id": "org-123"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["auth_type"] != "registry-auth" {
			t.Errorf("expected auth_type=registry-auth, got %v", identity["auth_type"])
		}
		if identity["org_id"] != "org-123" {
			t.Errorf("expected org_id=org-123, got %v", identity["org_id"])
		}
		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}

		user := mustNestedMap(t, identity, "user")
		if user["username"] != "testuser" {
			t.Errorf("expected username=testuser, got %v", user["username"])
		}

		internal := mustNestedMap(t, identity, "internal")
		if internal["auth_time"] != fixedTime.UnixMilli() {
			t.Errorf("expected auth_time=%d, got %v", fixedTime.UnixMilli(), internal["auth_time"])
		}
	})

	t.Run("without org_id", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Subject: "testuser",
				Issuer:  "https://container-registry-authorizer.api.redhat.com",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["org_id"] != nil {
			t.Errorf("expected org_id=nil, got %v", identity["org_id"])
		}
	})

	t.Run("stage issuer", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Subject: "testuser",
				Issuer:  "https://container-registry-authorizer.stage.api.redhat.com",
				Claims:  claims.Claims{"org_id": "org-stage"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["auth_type"] != "registry-auth" {
			t.Errorf("expected auth_type=registry-auth, got %v", identity["auth_type"])
		}
	})
}

func TestRedHatIdentityMapper_ServiceAccount(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)
	m := NewRedHatIdentityMapper(WithRedHatIdentityClock(clk))

	t.Run("valid", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"client_id":          "myapp",
					"sub":                "abc-123",
					"scope":              "api.console openid",
					"organization": map[string]any{
						"id":             "org-1",
						"account_number": "12345",
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["type"] != "ServiceAccount" {
			t.Errorf("expected type=ServiceAccount, got %v", identity["type"])
		}
		if identity["org_id"] != "org-1" {
			t.Errorf("expected org_id=org-1, got %v", identity["org_id"])
		}
		if identity["account_number"] != "12345" {
			t.Errorf("expected account_number=12345, got %v", identity["account_number"])
		}

		sa := mustNestedMap(t, identity, "service_account")
		if sa["client_id"] != "myapp" {
			t.Errorf("expected client_id=myapp, got %v", sa["client_id"])
		}
		if sa["username"] != "service-account-myapp" {
			t.Errorf("expected username=service-account-myapp, got %v", sa["username"])
		}
		if sa["user_id"] != "abc-123" {
			t.Errorf("expected user_id=abc-123, got %v", sa["user_id"])
		}
	})

	t.Run("rh-org-id takes precedence", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"client_id":          "myapp",
					"sub":                "abc-123",
					"rh-org-id":          "rh-org-override",
					"organization": map[string]any{
						"id": "org-1",
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["org_id"] != "rh-org-override" {
			t.Errorf("expected org_id=rh-org-override, got %v", identity["org_id"])
		}
	})

	t.Run("missing client_id fails", func(t *testing.T) {
		_, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"sub":                "abc-123",
				},
			},
		})
		var mf *service.MappingFailure
		if !errors.As(err, &mf) {
			t.Fatalf("expected MappingFailure, got %v", err)
		}
		if mf.Message != "missing_client_id" {
			t.Errorf("expected message=missing_client_id, got %v", mf.Message)
		}
	})

	t.Run("clientId fallback", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"clientId":           "fallback-client",
					"sub":                "abc-123",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		identity := mustNestedMap(t, result.Claims, "identity")
		sa := mustNestedMap(t, identity, "service_account")
		if sa["client_id"] != "fallback-client" {
			t.Errorf("expected client_id=fallback-client, got %v", sa["client_id"])
		}
	})

	t.Run("empty client_id falls back to clientId", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"client_id":          "",
					"clientId":           "fallback-client",
					"sub":                "abc-123",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		identity := mustNestedMap(t, result.Claims, "identity")
		sa := mustNestedMap(t, identity, "service_account")
		if sa["client_id"] != "fallback-client" {
			t.Errorf("expected client_id=fallback-client, got %v", sa["client_id"])
		}
	})

	t.Run("both client_ids empty fails", func(t *testing.T) {
		_, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"client_id":          "",
					"clientId":           "",
					"sub":                "abc-123",
				},
			},
		})
		var mf *service.MappingFailure
		if !errors.As(err, &mf) {
			t.Fatalf("expected MappingFailure, got %v", err)
		}
	})

	t.Run("auth_time from iat", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "service-account-myapp",
					"client_id":          "myapp",
					"sub":                "abc-123",
					"iat":                float64(1718442000),
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		identity := mustNestedMap(t, result.Claims, "identity")
		internal := mustNestedMap(t, identity, "internal")
		if internal["auth_time"] != int64(1718442000000) {
			t.Errorf("expected auth_time=1718442000000, got %v", internal["auth_time"])
		}
	})
}

func TestRedHatIdentityMapper_ConsoleAPI(t *testing.T) {
	m := NewRedHatIdentityMapper()

	t.Run("missing idp denied", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"scope": "api.console openid",
					"sub":   "user-123",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeny(t, result, service.AbortReasonInvalidSubject, "claim 'idp' is required")
	})

	t.Run("internal user", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"sub":                "user-123",
					"preferred_username": "jdoe",
					"email":              "jdoe@example.com",
					"given_name":         "John",
					"family_name":        "Doe",
					"locale":             "en_US",
					"user_id":            float64(42),
					"scope":              "api.console openid",
					"idp":                "https://sso.redhat.com/auth/realms/internal",
					"organization": map[string]any{
						"id":             "org-1",
						"account_number": "12345",
					},
					"realm_access": map[string]any{
						"roles": []any{"admin:org:all"},
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "org-1" {
			t.Errorf("expected org_id=org-1, got %v", identity["org_id"])
		}

		user := mustNestedMap(t, identity, "user")
		if user["username"] != "jdoe" {
			t.Errorf("expected username=jdoe, got %v", user["username"])
		}
		if user["is_org_admin"] != true {
			t.Errorf("expected is_org_admin=true, got %v", user["is_org_admin"])
		}
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true, got %v", user["is_internal"])
		}
		if user["user_id"] != "42" {
			t.Errorf("expected user_id=42, got %v", user["user_id"])
		}
	})

	t.Run("external user", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"sub":                "user-456",
					"preferred_username": "external",
					"scope":              "api.console openid",
					"idp":                "https://sso.redhat.com/auth/realms/redhat-external",
					"organization": map[string]any{
						"id": "org-2",
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		identity := mustNestedMap(t, result.Claims, "identity")
		user := mustNestedMap(t, identity, "user")
		if user["is_internal"] != false {
			t.Errorf("expected is_internal=false, got %v", user["is_internal"])
		}
	})
}

func TestRedHatIdentityMapper_RHSM(t *testing.T) {
	m := NewRedHatIdentityMapper()

	t.Run("external user", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"rhsm-api"},
				Claims: claims.Claims{
					"preferred_username": "rhsm-user",
					"email":              "rhsm@example.com",
					"sub":                "rhsm-sub-789",
					"account_id":         "acct-001",
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "acct-001" {
			t.Errorf("expected org_id=acct-001, got %v", identity["org_id"])
		}
		if identity["account_number"] != "acct-001" {
			t.Errorf("expected account_number=acct-001, got %v", identity["account_number"])
		}

		user := mustNestedMap(t, identity, "user")
		if user["username"] != "rhsm-user" {
			t.Errorf("expected username=rhsm-user, got %v", user["username"])
		}
		if user["user_id"] != "rhsm-sub-789" {
			t.Errorf("expected user_id=rhsm-sub-789, got %v", user["user_id"])
		}
		if user["is_internal"] != false {
			t.Errorf("expected is_internal=false, got %v", user["is_internal"])
		}
	})

	t.Run("internal user", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"rhsm-api"},
				Claims: claims.Claims{
					"preferred_username": "internal-rhsm-user",
					"email":              "internal@redhat.com",
					"sub":                "internal-rhsm-sub",
					"account_id":         "acct-internal",
					"idp":                "https://sso.redhat.com/auth/realms/internal",
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		user := mustNestedMap(t, identity, "user")
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true, got %v", user["is_internal"])
		}
	})

	t.Run("alternative claim names", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"rhsm-api"},
				Claims: claims.Claims{
					"username":  "alt-user",
					"firstName": "Alt",
					"lastName":  "User",
					"lang":      "fr_FR",
					"sub":       "alt-sub",
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		user := mustNestedMap(t, identity, "user")
		if user["username"] != "alt-user" {
			t.Errorf("expected username=alt-user, got %v", user["username"])
		}
		if user["first_name"] != "Alt" {
			t.Errorf("expected first_name=Alt, got %v", user["first_name"])
		}
		if user["last_name"] != "User" {
			t.Errorf("expected last_name=User, got %v", user["last_name"])
		}
		if user["locale"] != "fr_FR" {
			t.Errorf("expected locale=fr_FR, got %v", user["locale"])
		}
	})
}

func TestRedHatIdentityMapper_CustomerPortal(t *testing.T) {
	m := NewRedHatIdentityMapper()

	t.Run("external user", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"customer-portal"},
				Claims: claims.Claims{
					"username":  "portal-jane",
					"email":     "jane@acme.com",
					"firstName": "Jane",
					"lastName":  "Smith",
					"lang":      "fr_FR",
					"user_id":   float64(101),
					"sub":       "portal-sub-101",
					"organization": map[string]any{
						"id": "org-portal",
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllow(t, result)

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "org-portal" {
			t.Errorf("expected org_id=org-portal, got %v", identity["org_id"])
		}

		user := mustNestedMap(t, identity, "user")
		if user["username"] != "portal-jane" {
			t.Errorf("expected username=portal-jane, got %v", user["username"])
		}
		if user["first_name"] != "Jane" {
			t.Errorf("expected first_name=Jane, got %v", user["first_name"])
		}
		if user["last_name"] != "Smith" {
			t.Errorf("expected last_name=Smith, got %v", user["last_name"])
		}
		if user["locale"] != "fr_FR" {
			t.Errorf("expected locale=fr_FR, got %v", user["locale"])
		}
		if user["is_internal"] != false {
			t.Errorf("expected is_internal=false, got %v", user["is_internal"])
		}
	})

	t.Run("internal user", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"customer-portal"},
				Claims: claims.Claims{
					"username":  "portal-internal",
					"email":     "internal@redhat.com",
					"firstName": "Internal",
					"lastName":  "User",
					"lang":      "en_US",
					"user_id":   float64(201),
					"sub":       "portal-internal-sub",
					"idp":       "https://sso.redhat.com/auth/realms/internal",
					"organization": map[string]any{
						"id": "org-internal-portal",
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		user := mustNestedMap(t, identity, "user")
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true, got %v", user["is_internal"])
		}
	})

	t.Run("account_number from claim", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"customer-portal"},
				Claims: claims.Claims{
					"username":       "portal-user",
					"account_number": "acct-direct",
					"sub":            "sub-1",
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["account_number"] != "acct-direct" {
			t.Errorf("expected account_number=acct-direct, got %v", identity["account_number"])
		}
	})
}

func TestRedHatIdentityMapper_UnsupportedToken(t *testing.T) {
	m := NewRedHatIdentityMapper()

	t.Run("no matching type", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"preferred_username": "unknown-user",
					"email":              "unknown@example.com",
					"sub":                "unknown-sub",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeny(t, result, service.AbortReasonUnsupportedTokenType, "unsupported_token_type")
	})

	t.Run("unknown audience", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"unknown-audience"},
				Claims: claims.Claims{
					"preferred_username": "unknown-aud-user",
					"sub":                "unknown-aud-sub",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeny(t, result, service.AbortReasonUnsupportedTokenType, "unsupported_token_type")
	})

	t.Run("nil subject", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeny(t, result, service.AbortReasonUnsupportedTokenType, "unsupported_token_type")
	})
}

func TestRedHatIdentityMapper_Precedence(t *testing.T) {
	m := NewRedHatIdentityMapper()

	t.Run("scope over audience", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"rhsm-api"},
				Claims: claims.Claims{
					"sub":                "dual-user",
					"preferred_username": "dual-user",
					"scope":              "api.console openid",
					"given_name":         "Dual",
					"family_name":        "User",
					"locale":             "en_US",
					"idp":                "https://sso.redhat.com/auth/realms/redhat-external",
					"organization": map[string]any{
						"id":             "org-dual",
						"account_number": "11111",
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["type"] != "User" {
			t.Errorf("expected type=User (Console API), got %v", identity["type"])
		}
		if identity["org_id"] != "org-dual" {
			t.Errorf("expected org_id=org-dual, got %v", identity["org_id"])
		}
	})

	t.Run("service account over audience", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"rhsm-api"},
				Claims: claims.Claims{
					"preferred_username": "service-account-sa-with-aud",
					"client_id":          "my-sa-client",
					"sub":                "sa-sub-1",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		if identity["type"] != "ServiceAccount" {
			t.Errorf("expected type=ServiceAccount, got %v", identity["type"])
		}
	})
}

func TestRedHatIdentityMapper_IsInternalFallback(t *testing.T) {
	m := NewRedHatIdentityMapper()

	t.Run("role fallback for console API", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Claims: claims.Claims{
					"sub":                "user-role-fb",
					"preferred_username": "role-fb-user",
					"scope":              "api.console openid",
					"idp":                "https://sso.redhat.com/auth/realms/redhat-external",
					"organization":       map[string]any{"id": "org-1"},
					"realm_access": map[string]any{
						"roles": []any{"redhat:employees"},
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		user := mustNestedMap(t, identity, "user")
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true (role fallback), got %v", user["is_internal"])
		}
	})

	t.Run("RHSM non-matching idp returns false", func(t *testing.T) {
		result, err := m.Map(context.Background(), &service.MapperInput{
			Subject: &trust.Result{
				Audience: []string{"rhsm-api"},
				Claims: claims.Claims{
					"sub": "user-ext",
					"idp": "https://sso.redhat.com/auth/realms/redhat-external",
					"realm_access": map[string]any{
						"roles": []any{"redhat:employees"},
					},
				},
			},
			DataSourceRegistry: registryWithIdentityPolicy(),
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		identity := mustNestedMap(t, result.Claims, "identity")
		user := mustNestedMap(t, identity, "user")
		if user["is_internal"] != false {
			t.Errorf("expected is_internal=false (non-matching idp is definitive for RHSM), got %v", user["is_internal"])
		}
	})
}

// --- test helpers ---

func assertAllow(t *testing.T, result service.MappingResult) {
	t.Helper()
	if !result.Decision.IsAllow() {
		t.Fatalf("expected Allow, got Deny: %v", result.Decision)
	}
}

func assertDeny(t *testing.T, result service.MappingResult, reason service.AbortReason, message string) {
	t.Helper()
	if result.Decision.IsAllow() {
		t.Fatalf("expected Deny, got Allow")
	}
	ee := result.Decision.AsExchangeError()
	if ee == nil {
		t.Fatalf("expected ExchangeError, got nil")
	}
	if ee.Reason != reason {
		t.Errorf("expected reason=%s, got %s", reason, ee.Reason)
	}
	if ee.Message != message {
		t.Errorf("expected message=%s, got %s", message, ee.Message)
	}
}

func mustNestedMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	child, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s to be a map, got %T (%v)", key, parent[key], parent[key])
	}
	return child
}
