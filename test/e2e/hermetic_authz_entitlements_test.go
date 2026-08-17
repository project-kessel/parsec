package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const entitlementsAPIURL = "https://entitlements.example.internal/api"

// TestHermeticAuthzEntitlements covers RHCLOUD-49315: gated entitlements injection
// via Lua data source + redhat_identity.cel.
func TestHermeticAuthzEntitlements(t *testing.T) {
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

	entitlementsBody := `{"insights":{"is_entitled":true},"ansible":{"is_entitled":false}}`
	var entitlementsCalls int

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if fix := jwksFixture.GetFixture(req); fix != nil {
					return fix
				}
				if req.Method == http.MethodGet && req.URL.String() == entitlementsAPIURL {
					entitlementsCalls++
					if req.Header.Get("x-rh-identity") == "" {
						t.Error("entitlements request missing x-rh-identity")
					}
					if req.Header.Get("Authorization") != "" {
						t.Error("entitlements request must not send Authorization")
					}
					return &httpfixture.Fixture{
						StatusCode: 200,
						Body:       entitlementsBody,
					}
				}
				return nil
			}),
			Strict: true,
			Clock:  clk,
		}),
	}

	failClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
				if fix := jwksFixture.GetFixture(req); fix != nil {
					return fix
				}
				if req.Method == http.MethodGet && req.URL.String() == entitlementsAPIURL {
					return &httpfixture.Fixture{StatusCode: 503, Body: `{"error":"unavailable"}`}
				}
				return nil
			}),
			Strict: true,
			Clock:  clk,
		}),
	}

	jwtValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      jwksFixture.Issuer(),
		JWKSURL:     jwksFixture.JWKSURL(),
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		HTTPClient:  httpClient,
		Clock:       clk,
	})
	if err != nil {
		t.Fatalf("JWT validator: %v", err)
	}
	trustStore := trust.NewStubStore()
	trustStore.AddValidator(jwtValidator)

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("read CEL: %v", err)
	}
	luaScript, err := os.ReadFile("../../configs/scripts/user_entitlements.lua")
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
	})
	if err != nil {
		t.Fatalf("identity-policy DS: %v", err)
	}

	newEntitlementsDS := func(client *http.Client) service.DataSource {
		ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
			Name:   "user_entitlements",
			Script: string(luaScript),
			ConfigSource: luaservices.NewMapConfigSource(map[string]any{
				"entitlements_api": entitlementsAPIURL,
			}),
			HTTPClient: client,
		})
		if err != nil {
			t.Fatalf("entitlements DS: %v", err)
		}
		return ds
	}

	newAuthz := func(withEntitlementsDS bool, client *http.Client) *server.AuthzServer {
		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)
		if withEntitlementsDS {
			dsRegistry.Register(newEntitlementsDS(client))
		}

		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
			TokenType:    string(service.TokenTypeTransactionToken),
			ClaimMappers: []service.ClaimMapper{celMapper},
			Clock:        clk,
		}))

		tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, nil)
		return server.NewAuthzServer(trustStore, tokenService, nil, server.DefaultCredentialSources(), nil)
	}

	consoleClaims := map[string]interface{}{
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

	t.Run("gate off keeps empty entitlements", func(t *testing.T) {
		entitlementsCalls = 0
		authz := newAuthz(true, httpClient)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		claims := decodeTokenClaims(t, resp)
		ents, ok := claims["entitlements"].(map[string]any)
		if !ok || len(ents) != 0 {
			t.Fatalf("expected empty entitlements map, got %v", claims["entitlements"])
		}
		if entitlementsCalls != 0 {
			t.Fatalf("expected no entitlements HTTP calls, got %d", entitlementsCalls)
		}
	})

	t.Run("gate on fetches entitlements for console user", func(t *testing.T) {
		entitlementsCalls = 0
		authz := newAuthz(true, httpClient)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearerAndEntitlements(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		claims := decodeTokenClaims(t, resp)
		ents, ok := claims["entitlements"].(map[string]any)
		if !ok {
			t.Fatalf("expected entitlements map, got %T %v", claims["entitlements"], claims["entitlements"])
		}
		insights, _ := ents["insights"].(map[string]any)
		if insights["is_entitled"] != true {
			t.Fatalf("unexpected entitlements: %v", ents)
		}
		if entitlementsCalls != 1 {
			t.Fatalf("expected 1 entitlements call, got %d", entitlementsCalls)
		}
	})

	t.Run("gate on without data source fails closed", func(t *testing.T) {
		authz := newAuthz(false, httpClient)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearerAndEntitlements(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertDeniedResponse(t, resp)
	})

	t.Run("gate on entitlements service error fails closed", func(t *testing.T) {
		authz := newAuthz(true, failClient)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearerAndEntitlements(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertDeniedResponse(t, resp)
	})

	t.Run("service account keeps empty entitlements when gated", func(t *testing.T) {
		entitlementsCalls = 0
		authz := newAuthz(true, httpClient)
		token := mustSignToken(t, jwksFixture, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "myapp",
			"sub":                "abc-123",
			"scope":              "api.console openid",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
		})
		resp, err := authz.Check(context.Background(), checkRequestWithBearerAndEntitlements(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		claims := decodeTokenClaims(t, resp)
		ents, ok := claims["entitlements"].(map[string]any)
		if !ok || len(ents) != 0 {
			t.Fatalf("expected empty entitlements for SA, got %v", claims["entitlements"])
		}
		if entitlementsCalls != 0 {
			t.Fatalf("expected no entitlements HTTP for SA, got %d", entitlementsCalls)
		}
	})
}

func checkRequestWithBearerAndEntitlements(token string) *authv3.CheckRequest {
	req := checkRequestWithBearer(token)
	req.Attributes.ContextExtensions = map[string]string{
		"enable_entitlements": "true",
	}
	return req
}

func decodeTokenClaims(t *testing.T, resp *authv3.CheckResponse) map[string]any {
	t.Helper()

	okResp := resp.GetOkResponse()
	if okResp == nil {
		t.Fatal("expected OkResponse, got nil")
	}

	var tokenValue string
	for _, h := range okResp.Headers {
		if h.Header.Key == "Transaction-Token" {
			tokenValue = h.Header.Value
			break
		}
	}
	if tokenValue == "" {
		t.Fatal("Transaction-Token header not found")
	}

	tokenJSON, err := base64.StdEncoding.DecodeString(tokenValue)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(tokenJSON, &claims); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	return claims
}
