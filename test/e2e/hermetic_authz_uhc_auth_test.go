package e2e_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestHermeticAuthzCheckUHCAuth demonstrates end-to-end testing of uhc-auth via
// the ext_authz Authorization.Check RPC using hermetic fixtures.
//
// uhc-auth authenticates OpenShift in-cluster operators that present an OCM
// cluster token. The token cannot be validated locally and the cluster id
// travels in the User-Agent, so the credential is the (Authorization,
// User-Agent) pair. The Lua validator resolves it against OCM's
// current_account endpoint into a System identity keyed on system.cluster_id.
//
// The header credential source is ordered ahead of the bearer source, and both
// see an Authorization header, so the test also covers the routing decision:
// a non-operator User-Agent must fall through to the bearer path.
func TestHermeticAuthzCheckUHCAuth(t *testing.T) {
	// ============================================================
	// 1. Setup Fixtures
	// ============================================================

	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	const currentAccountURL = "https://api.openshift.example.com/api/accounts_mgmt/v1/current_account"

	ocmFixture := httpfixture.NewRuleBasedProvider([]httpfixture.HTTPFixtureRule{
		{
			// A cluster OCM does not recognize.
			Request: httpfixture.FixtureRequest{
				Method:  "GET",
				URL:     currentAccountURL,
				URLType: "exact",
				Headers: map[string]string{"Authorization": "AccessToken 9999999:test-token"},
			},
			Response: httpfixture.Fixture{
				StatusCode: 401,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"reason":"unauthorized"}`,
			},
		},
		{
			Request: httpfixture.FixtureRequest{
				Method:  "GET",
				URL:     currentAccountURL,
				URLType: "exact",
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"organization":{"external_id":"12345","ebs_account_id":"540155"}}`,
			},
		},
	})

	jwksFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://sso.redhat.com/auth/realms/redhat-external",
		JWKSURL: "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("failed to create JWKS fixture: %v", err)
	}

	newFixtureClient := func(provider httpfixture.FixtureProvider) *http.Client {
		return &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
				Clock:    clk,
			}),
		}
	}

	// ============================================================
	// 2. Load Production Scripts and Build Components
	// ============================================================

	luaScript, err := os.ReadFile("../../configs/scripts/uhc_auth.lua")
	if err != nil {
		t.Fatalf("failed to read uhc_auth.lua: %v", err)
	}

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("failed to read redhat_identity.cel: %v", err)
	}

	luaValidator, err := trust.NewLuaValidator(
		"uhc-auth",
		string(luaScript),
		[]trust.CredentialType{trust.CredentialTypeHeader},
		trust.WithLuaHTTPClient(newFixtureClient(ocmFixture)),
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"current_account_url": currentAccountURL,
			"trust_domain":        "uhc.example.com",
			"issuer":              "uhc://api.openshift.example.com",
		})),
	)
	if err != nil {
		t.Fatalf("failed to create Lua validator: %v", err)
	}

	// The bearer path behind the header source, so fall-through is observable.
	jwtValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      jwksFixture.Issuer(),
		JWKSURL:     jwksFixture.JWKSURL(),
		TrustDomain: "sso.example.com",
		HTTPClient: newFixtureClient(httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
			return jwksFixture.GetFixture(req)
		})),
		Clock: clk,
	})
	if err != nil {
		t.Fatalf("failed to create JWT validator: %v", err)
	}

	trustStore := trust.NewStubStore()
	trustStore.AddValidator(luaValidator)
	trustStore.AddValidator(jwtValidator)

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

	dsRegistry := service.NewDataSourceRegistry()
	tokenService := service.NewTokenService("uhc.example.com", dsRegistry, issuerRegistry, nil)

	noStrip := false
	uhcSrc, err := server.NewHeaderCredentialSource("uhc-auth", []server.HeaderSpec{
		{Name: "authorization"},
		{Name: "user-agent", Match: "^.*-operator/.* cluster/.*", Strip: &noStrip},
	})
	if err != nil {
		t.Fatalf("failed to create header credential source: %v", err)
	}
	bearerSrc, err := server.NewBearerCredentialSource("authorization-bearer")
	if err != nil {
		t.Fatalf("failed to create bearer credential source: %v", err)
	}
	credSources := server.NewCredentialSources(uhcSrc, bearerSrc)

	// ============================================================
	// 3. Create the Authz Server
	// ============================================================

	authzServer := server.NewAuthzServer(trustStore, tokenService, nil, credSources, nil)

	// ============================================================
	// 4. Test Cases
	// ============================================================

	t.Run("operator cluster token yields a System identity", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithUHC("insights-operator/abcdef cluster/1234321", "test-token"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "uhc-auth" {
			t.Errorf("expected auth_type 'uhc-auth', got %v", identity["auth_type"])
		}
		if identity["type"] != "System" {
			t.Errorf("expected type 'System', got %v", identity["type"])
		}
		if identity["org_id"] != "12345" {
			t.Errorf("expected org_id '12345', got %v", identity["org_id"])
		}
		if identity["account_number"] != "540155" {
			t.Errorf("expected account_number '540155', got %v", identity["account_number"])
		}

		system := assertNestedMap(t, identity, "system")
		if system["cluster_id"] != "1234321" {
			t.Errorf("expected system.cluster_id '1234321', got %v", system["cluster_id"])
		}
	})

	// OCM rejecting the cluster token surfaces as a deny; parsec maps every
	// validator rejection to Unauthenticated rather than the upstream status.
	t.Run("OCM rejects the cluster token", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithUHC("insights-operator/abcdef cluster/9999999", "test-token"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("operator not on the allowlist is denied", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithUHC("rogue-operator/abcdef cluster/1234321", "test-token"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	// The routing decision the whole design turns on: an ordinary client
	// carrying an Authorization header must not be captured by the header
	// source sitting in front of the bearer source.
	t.Run("non-operator user-agent falls through to the bearer path", func(t *testing.T) {
		token := mustSignToken(t, jwksFixture, map[string]any{
			"sub":                "service-account-id",
			"preferred_username": "service-account-my-client",
			"client_id":          "my-client",
			"scope":              "openid",
			"organization": map[string]any{
				"id":             "org-1",
				"account_number": "12345",
			},
		})

		req := checkRequestWithBearer(token)
		req.Attributes.Request.Http.Headers["user-agent"] = "curl/8.0.1"

		resp, err := authzServer.Check(context.Background(), req)
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)
		if identity["type"] != "ServiceAccount" {
			t.Errorf("expected type 'ServiceAccount', got %v", identity["type"])
		}
		if identity["auth_type"] != "jwt-auth" {
			t.Errorf("expected auth_type 'jwt-auth', got %v", identity["auth_type"])
		}
	})

	t.Run("no credentials returns denied", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithHeaders(map[string]string{}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})
}

func checkRequestWithUHC(userAgent, token string) *authv3.CheckRequest {
	return checkRequestWithHeaders(map[string]string{
		"user-agent":    userAgent,
		"authorization": "Bearer " + token,
	})
}
