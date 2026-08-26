package e2e_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestHermeticAuthzCheckJWT tests the JWT Bearer flow through the ext_authz
// Check() API. It mirrors the identity CEL mapping tests but goes through the
// full server stack instead of calling the mapper directly.
//
// Covers: ServiceAccount, Console API, RHSM API, Customer Portal tokens,
// precedence rules, and deny cases (unsupported token types).
func TestHermeticAuthzCheckJWT(t *testing.T) {
	// ============================================================
	// 1. Setup Fixtures
	// ============================================================

	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	jwksFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://sso.redhat.com/auth/realms/redhat-external",
		JWKSURL: "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("failed to create JWKS fixture: %v", err)
	}

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				return jwksFixture.GetFixture(req)
			}),
			Strict: true,
			Clock:  clk,
		}),
	}

	// ============================================================
	// 2. Build Components
	// ============================================================

	jwtValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      jwksFixture.Issuer(),
		JWKSURL:     jwksFixture.JWKSURL(),
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		HTTPClient:  httpClient,
		Clock:       clk,
	})
	if err != nil {
		t.Fatalf("failed to create JWT validator: %v", err)
	}

	trustStore := trust.NewStubStore()
	trustStore.AddValidator(jwtValidator)

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("failed to read redhat_identity.cel: %v", err)
	}

	celMapper, err := mapper.NewCELMapper(string(celScript), mapper.WithClock(clk))
	if err != nil {
		t.Fatalf("failed to create CEL mapper: %v", err)
	}

	txnIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeTransactionToken),
		ClaimMappers: []service.ClaimMapper{celMapper},
		Clock:        clk,
	})

	issuerRegistry := service.NewSimpleRegistry()
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	identityPolicyDS, err := datasource.NewStaticDataSource("identity-policy", map[string]any{
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
		"enforce_idp_auth":      false,
	})
	if err != nil {
		t.Fatalf("failed to create identity-policy datasource: %v", err)
	}

	dsRegistry := service.NewDataSourceRegistry()
	dsRegistry.Register(identityPolicyDS)

	tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, nil)

	authzServer := server.NewAuthzServer(trustStore, tokenService, nil, server.DefaultCredentialSources(), nil)

	// ============================================================
	// 3. Test Cases
	// ============================================================

	jwtIdentityTests(t, authzServer, jwksFixture)
}

func jwtIdentityTests(t *testing.T, authzServer *server.AuthzServer, jwks *httpfixture.JWKSFixture) {
	t.Run("service account valid", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "myapp",
			"sub":                "abc-123",
			"scope":              "api.console openid",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "ServiceAccount" {
			t.Errorf("expected type=ServiceAccount, got %v", identity["type"])
		}
		sa := assertNestedMap(t, identity, "service_account")
		if sa["client_id"] != "myapp" {
			t.Errorf("expected client_id=myapp, got %v", sa["client_id"])
		}
		if sa["username"] != "service-account-myapp" {
			t.Errorf("expected username=service-account-myapp, got %v", sa["username"])
		}
	})

	t.Run("service account deny missing client_id", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"sub":                "abc-123",
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedContains(t, resp, "missing_client_id")
	})

	t.Run("service account clientId fallback", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"clientId":           "fallback-client",
			"sub":                "abc-123",
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		sa := assertNestedMap(t, identity, "service_account")
		if sa["client_id"] != "fallback-client" {
			t.Errorf("expected client_id=fallback-client, got %v", sa["client_id"])
		}
	})

	t.Run("service account deny empty client_id", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "",
			"sub":                "abc-123",
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedContains(t, resp, "missing_client_id")
	})

	t.Run("service account empty client_id falls back to clientId", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "",
			"clientId":           "fallback-client",
			"sub":                "abc-123",
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		sa := assertNestedMap(t, identity, "service_account")
		if sa["client_id"] != "fallback-client" {
			t.Errorf("expected client_id=fallback-client, got %v", sa["client_id"])
		}
	})

	t.Run("service account deny both client_ids empty", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "",
			"clientId":           "",
			"sub":                "abc-123",
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedContains(t, resp, "missing_client_id")
	})

	t.Run("console API user", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"sub":                "user-123",
			"preferred_username": "jdoe",
			"email":              "jdoe@example.com",
			"given_name":         "John",
			"family_name":        "Doe",
			"locale":             "en_US",
			"user_id":            42,
			"scope":              "api.console openid",
			"idp":                "https://sso.redhat.com/auth/realms/internal",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin:org:all"},
			},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "org-1" {
			t.Errorf("expected org_id=org-1, got %v", identity["org_id"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["username"] != "jdoe" {
			t.Errorf("expected username=jdoe, got %v", user["username"])
		}
		if user["first_name"] != "John" {
			t.Errorf("expected first_name=John, got %v", user["first_name"])
		}
		if user["is_org_admin"] != true {
			t.Errorf("expected is_org_admin=true, got %v", user["is_org_admin"])
		}
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true (idp matches internal), got %v", user["is_internal"])
		}
	})

	t.Run("RHSM API user", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "rhsm-user",
			"email":              "rhsm@example.com",
			"sub":                "rhsm-sub-789",
			"account_id":         "acct-001",
			"aud":                []string{"rhsm-api"},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["auth_type"] != "jwt-auth" {
			t.Errorf("expected auth_type=jwt-auth, got %v", identity["auth_type"])
		}
		if identity["org_id"] != "acct-001" {
			t.Errorf("expected org_id=acct-001, got %v", identity["org_id"])
		}
		if identity["account_number"] != "acct-001" {
			t.Errorf("expected account_number=acct-001, got %v", identity["account_number"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["username"] != "rhsm-user" {
			t.Errorf("expected username=rhsm-user, got %v", user["username"])
		}
		if user["user_id"] != "rhsm-sub-789" {
			t.Errorf("expected user_id=rhsm-sub-789, got %v", user["user_id"])
		}
		if user["is_internal"] != false {
			t.Errorf("expected is_internal=false (no idp claim), got %v", user["is_internal"])
		}
	})

	t.Run("RHSM API internal user", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "internal-rhsm-user",
			"email":              "internal@redhat.com",
			"sub":                "internal-rhsm-sub",
			"account_id":         "acct-internal",
			"idp":                "https://sso.redhat.com/auth/realms/internal",
			"aud":                []string{"rhsm-api"},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		user := assertNestedMap(t, identity, "user")
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true (idp matches internal target), got %v", user["is_internal"])
		}
	})

	t.Run("customer portal user", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"username":  "portal-jane",
			"email":     "jane@acme.com",
			"firstName": "Jane",
			"lastName":  "Smith",
			"lang":      "fr_FR",
			"user_id":   101,
			"sub":       "portal-sub-101",
			"aud":       []string{"customer-portal"},
			"organization": map[string]interface{}{
				"id": "org-portal",
			},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "org-portal" {
			t.Errorf("expected org_id=org-portal, got %v", identity["org_id"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["username"] != "portal-jane" {
			t.Errorf("expected username=portal-jane, got %v", user["username"])
		}
		if user["first_name"] != "Jane" {
			t.Errorf("expected first_name=Jane (from firstName), got %v", user["first_name"])
		}
		if user["last_name"] != "Smith" {
			t.Errorf("expected last_name=Smith (from lastName), got %v", user["last_name"])
		}
		if user["locale"] != "fr_FR" {
			t.Errorf("expected locale=fr_FR (from lang), got %v", user["locale"])
		}
		if user["is_internal"] != false {
			t.Errorf("expected is_internal=false (no idp claim), got %v", user["is_internal"])
		}
	})

	t.Run("customer portal internal user", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"username":  "portal-internal",
			"email":     "internal@redhat.com",
			"firstName": "Internal",
			"lastName":  "User",
			"lang":      "en_US",
			"user_id":   201,
			"sub":       "portal-internal-sub",
			"idp":       "https://sso.redhat.com/auth/realms/internal",
			"aud":       []string{"customer-portal"},
			"organization": map[string]interface{}{
				"id": "org-internal-portal",
			},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "org-internal-portal" {
			t.Errorf("expected org_id=org-internal-portal, got %v", identity["org_id"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["username"] != "portal-internal" {
			t.Errorf("expected username=portal-internal, got %v", user["username"])
		}
		if user["is_internal"] != true {
			t.Errorf("expected is_internal=true (idp matches internal target), got %v", user["is_internal"])
		}
	})

	t.Run("unsupported token denied", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "unknown-user",
			"email":              "unknown@example.com",
			"sub":                "unknown-sub",
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedContains(t, resp, "unsupported_token_type")
	})

	t.Run("unsupported token with unknown audience denied", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "unknown-aud-user",
			"sub":                "unknown-aud-sub",
			"aud":                []string{"unknown-audience"},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedContains(t, resp, "unsupported_token_type")
	})

	t.Run("precedence scope over audience", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"sub":                "dual-user",
			"preferred_username": "dual-user",
			"scope":              "api.console openid",
			"given_name":         "Dual",
			"family_name":        "User",
			"locale":             "en_US",
			"idp":                "https://sso.redhat.com/auth/realms/redhat-external",
			"aud":                []string{"rhsm-api"},
			"organization": map[string]interface{}{
				"id":             "org-dual",
				"account_number": "11111",
			},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
		if identity["org_id"] != "org-dual" {
			t.Errorf("expected org_id from Console API branch (organization.id), got %v", identity["org_id"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["locale"] != "en_US" {
			t.Errorf("expected locale=en_US from Console API branch, got %v", user["locale"])
		}
	})

	t.Run("precedence service account over audience", func(t *testing.T) {
		token := mustSignToken(t, jwks, map[string]interface{}{
			"preferred_username": "service-account-sa-with-aud",
			"client_id":          "my-sa-client",
			"sub":                "sa-sub-1",
			"aud":                []string{"rhsm-api"},
		})

		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)

		if identity["type"] != "ServiceAccount" {
			t.Errorf("expected type=ServiceAccount (SA branch wins over aud), got %v", identity["type"])
		}
	})
}

func mustSignToken(t *testing.T, jwks *httpfixture.JWKSFixture, claims map[string]interface{}) string {
	t.Helper()
	token, err := jwks.CreateAndSignToken(claims)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

func checkRequestWithBearer(token string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/test",
					Headers: map[string]string{
						"authorization": "Bearer " + token,
					},
				},
			},
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "192.168.1.1",
						},
					},
				},
			},
		},
	}
}
