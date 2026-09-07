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
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const testRBACBaseURL = "https://rbac.example.internal"
const testRBACListURL = testRBACBaseURL + "/api/rbac/v1/cross-account-requests/"

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
				"rbac_path":                       "/api/rbac/v1/cross-account-requests/",
				"approved_only":                   "true",
				"internal_idp_target":             "https://sso.redhat.com/auth/realms/internal",
				"role_fallback_enabled":           false,
				"cross_access_bypass_is_internal": false,
				"cross_access_query_by":           "account",
				"employee_email_suffix":           "@redhat.com",
			}),
			HTTP: httpclient.LuaClient{Client: client, BaseURL: testRBACBaseURL},
		})
		if err != nil {
			t.Fatalf("cross_account DS: %v", err)
		}
		return ds
	}

	internalConsoleClaims := map[string]interface{}{
		"sub":                "emp-1",
		"preferred_username": "tam@redhat.com",
		"email":              "tam@redhat.com",
		"scope":              "api.console openid",
		"idp":                "https://sso.redhat.com/auth/realms/internal",
		"user_id":            "emp-1",
		"organization": map[string]interface{}{
			"id":             "emp-org",
			"account_number": "111111",
		},
	}

	newAuthz := func(withCrossAccountDS bool, client *http.Client) *server.AuthzServer {
		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)
		if withCrossAccountDS {
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

	t.Run("DS absent → normal identity without cross_access", func(t *testing.T) {
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					return jwksFixture.GetFixture(req)
				}),
				Strict: false,
				Clock:  clk,
			}),
		}
		authz := newAuthz(false, client)
		token := mustSignToken(t, jwksFixture, internalConsoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithCrossAccountCookies(token, "cross_access_account_number=999999"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)
		internal, ok := identity["internal"].(map[string]any)
		if !ok {
			t.Fatalf("internal=%T", identity["internal"])
		}
		if internal["cross_access"] == true {
			t.Error("expected cross_access false when DS absent")
		}
	})

	t.Run("non-internal + cookies → 403 forbidden", func(t *testing.T) {
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					return jwksFixture.GetFixture(req)
				}),
				Strict: false,
				Clock:  clk,
			}),
		}
		authz := newAuthz(true, client)
		claims := map[string]interface{}{
			"sub":                "user-1",
			"preferred_username": "alice",
			"email":              "alice@example.com",
			"scope":              "api.console openid",
			"idp":                "https://sso.redhat.com/auth/realms/redhat-external",
			"user_id":            "user-1",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
		}
		token := mustSignToken(t, jwksFixture, claims)
		resp, err := authz.Check(context.Background(), checkRequestWithCrossAccountCookies(token, "cross_access_account_number=999999"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertCrossAccountDenied(t, resp, "Cross account access is forbidden.")
	})

	t.Run("internal + cookies + RBAC denied → 403", func(t *testing.T) {
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACListURL) {
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[]}`}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalConsoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithCrossAccountCookies(token, "cross_access_account_number=999999"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertCrossAccountDenied(t, resp, "Access denied from RBAC on cross-access check.")
	})

	t.Run("internal + cookies + RBAC approved → swapped identity", func(t *testing.T) {
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACListURL) {
						return &httpfixture.Fixture{StatusCode: 200, Body: `{"data":[{"status":"approved"}]}`}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalConsoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithCrossAccountCookies(token, "cross_access_account_number=999999; cross_access_org_id=target-org"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)
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
	})

	t.Run("RBAC unavailable → 500", func(t *testing.T) {
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), testRBACListURL) {
						return &httpfixture.Fixture{StatusCode: 503, Body: "down"}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
		authz := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, internalConsoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithCrossAccountCookies(token, "cross_access_account_number=999999"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if resp.Status.Code == int32(codes.OK) {
			t.Fatal("expected denied response for RBAC outage")
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.Status.Code != 500 {
			t.Errorf("expected HTTP 500, got %d", denied.Status.Code)
		}
	})
}

func checkRequestWithCrossAccountCookies(token, cookie string) *authv3.CheckRequest {
	req := checkRequestWithBearer(token)
	req.Attributes.Request.Http.Headers["cookie"] = cookie
	return req
}

func assertCrossAccountDenied(t *testing.T, resp *authv3.CheckResponse, wantMessage string) {
	t.Helper()
	if resp.Status.Code == int32(codes.OK) {
		t.Fatal("expected denied response, got OK")
	}
	deniedResp := resp.GetDeniedResponse()
	if deniedResp == nil {
		t.Fatal("expected DeniedHttpResponse")
	}
	if deniedResp.Status.Code != 403 {
		t.Errorf("expected HTTP 403, got %d", deniedResp.Status.Code)
	}
	if !strings.Contains(deniedResp.Body, wantMessage) {
		t.Errorf("body=%q, want substring %q", deniedResp.Body, wantMessage)
	}
}
