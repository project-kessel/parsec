package e2e_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
)

const (
	testRBACAPI  = "https://rbac.example.internal"
	testRBACPath = "/api/rbac/v1/cross-account-requests/"
)

// TestHermeticAuthzCrossAccount covers RHCLOUD-47320: cross-account RBAC check
// via Lua data source + redhat_identity.cel.
//
// All I/O is hermetic (fixtures). Tests cover:
//   - internal + cookies + approved RBAC → swapped identity (AC1)
//   - non-internal + cookies → 403 forbidden (AC2)
//   - internal + empty RBAC → 403 denied (AC3)
//   - no cookies → normal identity (AC4)
//   - RBAC 5xx → 500 (AC5)
//   - DS not registered → skip (fail-safe)
//   - service account + cookies → no RBAC call (JWT-only)
//   - blocked export compliance + cookies → compliance 403, no RBAC
//   - export_compliance=false + cookies → swap still happens
func TestHermeticAuthzCrossAccount(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	jwksFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://sso.redhat.com/auth/realms/redhat-external",
		JWKSURL: "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("JWKS fixture: %v", err)
	}

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("read CEL: %v", err)
	}
	luaScript, err := os.ReadFile("../../configs/scripts/cross_account.lua")
	if err != nil {
		t.Fatalf("read Lua: %v", err)
	}

	celMapper, err := mapper.NewCELMapper(string(celScript), mapper.WithClock(clk))
	if err != nil {
		t.Fatalf("CEL mapper: %v", err)
	}

	identityPolicyDS, err := datasource.NewStaticDataSource("identity-policy", map[string]any{
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
		"enforce_idp_auth":      false,
	})
	if err != nil {
		t.Fatalf("identity-policy DS: %v", err)
	}

	newCrossAccountDS := func(client *http.Client) service.DataSource {
		ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
			Name:   "cross_account",
			Script: string(luaScript),
			ConfigSource: luaservices.NewMapConfigSource(map[string]any{
				"rbac_api":              testRBACAPI,
				"requests_path":         testRBACPath,
				"query_by":              "account",
				"internal_email_suffix": "@redhat.com",
				"bypass_is_internal":    false,
			}),
			HTTPClient: client,
		})
		if err != nil {
			t.Fatalf("cross_account DS: %v", err)
		}
		return ds
	}

	makeClient := func(rbacStatus int, rbacBody string) *http.Client {
		return &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACAPI) {
						return &httpfixture.Fixture{StatusCode: rbacStatus, Body: rbacBody}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
	}

	newAuthz := func(withDS bool, client *http.Client) *server.AuthzServer {
		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)
		if withDS {
			dsRegistry.Register(newCrossAccountDS(client))
		}
		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
			TokenType:    string(service.TokenTypeTransactionToken),
			ClaimMappers: []service.ClaimMapper{celMapper},
			Clock:        clk,
		}))
		tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, nil)
		return server.NewAuthzServer(trustStore(t, jwksFixture, client), tokenService, nil, server.DefaultCredentialSources(), nil)
	}

	internalClaims := map[string]interface{}{
		"sub":                "user-1",
		"preferred_username": "alice",
		"email":              "alice@redhat.com",
		"is_internal":        true,
		"scope":              "api.console openid",
		"user_id":            "user-1",
		"organization": map[string]interface{}{
			"id":             "emp-org",
			"account_number": "11111",
		},
	}

	checkWithCookie := func(token, cookie string) *authv3.CheckRequest {
		req := checkRequestWithBearer(token)
		if cookie != "" {
			req.Attributes.Request.Http.Headers["cookie"] = cookie
		}
		return req
	}

	t.Run("internal + cookies + approved RBAC → swapped identity", func(t *testing.T) {
		client := makeClient(200, `{"data":[{"status":"approved"}]}`)
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalClaims)
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155; cross_access_org_id=target-org"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)
		if identity["account_number"] != "540155" {
			t.Errorf("account_number=%v, want 540155", identity["account_number"])
		}
		if identity["org_id"] != "target-org" {
			t.Errorf("org_id=%v, want target-org", identity["org_id"])
		}
		if identity["employee_account_number"] != "11111" {
			t.Errorf("employee_account_number=%v, want 11111", identity["employee_account_number"])
		}
		user := assertNestedMap(t, identity, "user")
		if user["is_org_admin"] != false {
			t.Errorf("is_org_admin=%v, want false", user["is_org_admin"])
		}
		internal := assertNestedMap(t, identity, "internal")
		if internal["cross_access"] != true {
			t.Errorf("cross_access=%v, want true", internal["cross_access"])
		}
	})

	t.Run("non-internal + cookies → 403 forbidden", func(t *testing.T) {
		client := makeClient(200, `{"data":[{"status":"approved"}]}`)
		authz := newAuthz(true, client)
		claims := map[string]interface{}{
			"sub":                "user-2",
			"preferred_username": "bob",
			"email":              "bob@example.com",
			"is_internal":        false,
			"scope":              "api.console openid",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
		}
		token := mustSignToken(t, jwksFixture, claims)
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertHTTPDenied(t, resp, 403, "Cross account access is forbidden.")
	})

	t.Run("internal + cookies + empty RBAC → 403 denied", func(t *testing.T) {
		client := makeClient(200, `{"data":[]}`)
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalClaims)
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertHTTPDenied(t, resp, 403, "Access denied from RBAC on cross-access check.")
	})

	t.Run("no cookies → normal identity", func(t *testing.T) {
		client := makeClient(200, `{"data":[{"status":"approved"}]}`)
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)
		if identity["account_number"] != "11111" {
			t.Errorf("account_number=%v, want 11111", identity["account_number"])
		}
		if _, ok := identity["employee_account_number"]; ok {
			t.Errorf("unexpected employee_account_number: %v", identity["employee_account_number"])
		}
		internal := assertNestedMap(t, identity, "internal")
		if internal["cross_access"] != false {
			t.Errorf("cross_access=%v, want false", internal["cross_access"])
		}
	})

	t.Run("RBAC 503 → 500", func(t *testing.T) {
		client := makeClient(503, `{"error":"unavailable"}`)
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalClaims)
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if resp.Status.Code == int32(codes.OK) {
			t.Fatal("expected internal error, got OK")
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.Status.Code != 500 {
			t.Errorf("HTTP status=%d, want 500", denied.Status.Code)
		}
	})

	t.Run("DS not registered → skip", func(t *testing.T) {
		client := makeClient(200, `{"data":[{"status":"approved"}]}`)
		authz := newAuthz(false, client)
		token := mustSignToken(t, jwksFixture, internalClaims)
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
	})

	t.Run("service account + cookies → no RBAC", func(t *testing.T) {
		var rbacCalls int
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACAPI) {
						rbacCalls++
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"status":"approved"}]}`}
					}
					return nil
				}),
				Strict: false,
				Clock:  clk,
			}),
		}
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "myapp",
			"sub":                "abc-123",
			"email":              "sa@redhat.com",
			"is_internal":        true,
			"scope":              "api.console openid",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
		})
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		if rbacCalls != 0 {
			t.Fatalf("expected no RBAC calls for service account, got %d", rbacCalls)
		}
	})

	t.Run("blocked compliance + cookies → compliance 403, no RBAC", func(t *testing.T) {
		complianceScript, err := os.ReadFile("../../configs/scripts/export_compliance.lua")
		if err != nil {
			t.Fatalf("read export_compliance.lua: %v", err)
		}
		var rbacCalls int
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.URL.String() == testComplianceAPIURL {
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"result_code":"ERROR_T5"}`}
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACAPI) {
						rbacCalls++
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"status":"approved"}]}`}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
		complianceDS, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
			Name:   "export_compliance",
			Script: string(complianceScript),
			ConfigSource: luaservices.NewMapConfigSource(map[string]any{
				"compliance_api": testComplianceAPIURL,
			}),
			HTTPClient: client,
		})
		if err != nil {
			t.Fatalf("export_compliance DS: %v", err)
		}
		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)
		dsRegistry.Register(complianceDS)
		dsRegistry.Register(newCrossAccountDS(client))
		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
			TokenType:    string(service.TokenTypeTransactionToken),
			ClaimMappers: []service.ClaimMapper{celMapper},
			Clock:        clk,
		}))
		tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, nil)
		authz := server.NewAuthzServer(trustStore(t, jwksFixture, client), tokenService, nil, server.DefaultCredentialSources(), nil)
		token := mustSignToken(t, jwksFixture, internalClaims)
		resp, err := authz.Check(context.Background(), checkWithCookie(token, "cross_access_account_number=540155"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertHTTPDenied(t, resp, 403, "export compliance")
		if rbacCalls != 0 {
			t.Fatalf("expected no RBAC calls when compliance blocks, got %d", rbacCalls)
		}
	})

	t.Run("export_compliance=false + cookies → swap", func(t *testing.T) {
		complianceScript, err := os.ReadFile("../../configs/scripts/export_compliance.lua")
		if err != nil {
			t.Fatalf("read export_compliance.lua: %v", err)
		}
		var complianceCalls int
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.URL.String() == testComplianceAPIURL {
						complianceCalls++
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"result_code":"ERROR_T5"}`}
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACAPI) {
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"status":"approved"}]}`}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
		complianceDS, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
			Name:   "export_compliance",
			Script: string(complianceScript),
			ConfigSource: luaservices.NewMapConfigSource(map[string]any{
				"compliance_api": testComplianceAPIURL,
			}),
			HTTPClient: client,
		})
		if err != nil {
			t.Fatalf("export_compliance DS: %v", err)
		}
		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)
		dsRegistry.Register(complianceDS)
		dsRegistry.Register(newCrossAccountDS(client))
		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
			TokenType:    string(service.TokenTypeTransactionToken),
			ClaimMappers: []service.ClaimMapper{celMapper},
			Clock:        clk,
		}))
		tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, nil)
		authz := server.NewAuthzServer(trustStore(t, jwksFixture, client), tokenService, nil, server.DefaultCredentialSources(), nil)
		token := mustSignToken(t, jwksFixture, internalClaims)
		req := checkWithCookie(token, "cross_access_account_number=540155; cross_access_org_id=target-org")
		req.Attributes.ContextExtensions = map[string]string{"export_compliance": "false"}
		resp, err := authz.Check(context.Background(), req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		if complianceCalls != 0 {
			t.Fatalf("expected no compliance calls when opted out, got %d", complianceCalls)
		}
		identity := decodeTokenIdentity(t, resp)
		if identity["account_number"] != "540155" {
			t.Errorf("account_number=%v, want 540155", identity["account_number"])
		}
	})
}

func assertHTTPDenied(t *testing.T, resp *authv3.CheckResponse, httpStatus int, substr string) {
	t.Helper()
	if resp.Status.Code == int32(codes.OK) {
		t.Fatal("expected denied response, got OK")
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedHttpResponse")
	}
	if int(denied.Status.Code) != httpStatus {
		t.Errorf("HTTP status=%d, want %d", denied.Status.Code, httpStatus)
	}
	body := string(denied.Body)
	if substr != "" && !strings.Contains(body, substr) && !strings.Contains(resp.Status.Message, substr) {
		t.Errorf("expected %q in body %q or message %q", substr, body, resp.Status.Message)
	}
}
