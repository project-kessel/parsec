package e2e_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestHermeticAuthzCheck demonstrates end-to-end testing of Parsec's ext_authz
// Authorization.Check RPC using hermetic fixtures.
//
// This test:
// - Uses ONLY the external gRPC API (Authorization.Check)
// - Treats all internals as a black box
// - Tests the API contract: credentials → Check response with issued tokens
// - Uses fixtures for all I/O (HTTP endpoints, time)
//
// Currently covers registry auth (Basic Auth). Additional credential flows
// (JWT Bearer, mTLS, etc.) can be added as separate subtests following the
// same pattern.
//
// Note: This test manually constructs fixtures via the Go API. For config-driven
// hermetic testing using top-level fixtures, see
// configs/examples/parsec-registry-auth-hermetic.yaml.
func TestHermeticAuthzCheck(t *testing.T) {
	// ============================================================
	// 1. Setup Fixtures
	// ============================================================

	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	registryURL := "https://example.container-registry-authorizer.stage.api.redhat.com/v1/authorization"

	registryFixture := httpfixture.NewRuleBasedProvider([]httpfixture.HTTPFixtureRule{
		{
			Request: httpfixture.FixtureRequest{
				Method:  "POST",
				URL:     registryURL,
				URLType: "exact",
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"access":{"pull":"granted"}}`,
			},
		},
	})

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: registryFixture,
			Strict:   true,
			Clock:    clk,
		}),
	}

	// ============================================================
	// 2. Load Production Scripts and Build Components
	// ============================================================

	luaScript, err := os.ReadFile("../../configs/scripts/registry_auth.lua")
	if err != nil {
		t.Fatalf("failed to read registry_auth.lua: %v", err)
	}

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("failed to read redhat_identity.cel: %v", err)
	}

	luaValidator, err := trust.NewLuaValidator(
		"registry-auth",
		string(luaScript),
		[]trust.CredentialType{trust.CredentialTypeBasicAuth},
		trust.WithLuaHTTPClient(httpClient),
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"registry_url":     registryURL,
			"trust_domain":     "registry.example.com",
			"username_pattern": "^%d*|.+",
		})),
	)
	if err != nil {
		t.Fatalf("failed to create Lua validator: %v", err)
	}

	trustStore := trust.NewStubStore()
	trustStore.AddValidator(luaValidator)

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
	tokenService := service.NewTokenService("registry.example.com", dsRegistry, issuerRegistry, nil)

	basicAuthSrc, err := server.NewBasicAuthCredentialSource("registry-basic-auth")
	if err != nil {
		t.Fatalf("failed to create basic auth credential source: %v", err)
	}
	credSources := server.NewCredentialSources(basicAuthSrc)

	// ============================================================
	// 3. Create the Authz Server
	// ============================================================

	authzServer := server.NewAuthzServer(trustStore, tokenService, nil, credSources, nil)

	// ============================================================
	// 4. Test Cases
	// ============================================================

	registryAuthSubtests(t, authzServer)
}

func assertOKResponse(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	if resp.Status.Code != int32(codes.OK) {
		t.Fatalf("expected OK response, got code %d: %s", resp.Status.Code, resp.Status.Message)
	}
}

func assertDeniedResponse(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	if resp.Status.Code == int32(codes.OK) {
		t.Fatal("expected denied response, got OK")
	}
}

func decodeTokenIdentity(t *testing.T, resp *authv3.CheckResponse) map[string]any {
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
		t.Fatal("Transaction-Token header not found in response")
	}

	tokenJSON, err := base64.StdEncoding.DecodeString(tokenValue)
	if err != nil {
		t.Fatalf("failed to base64-decode token: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(tokenJSON, &claims); err != nil {
		t.Fatalf("failed to parse token JSON: %v", err)
	}

	identity, ok := claims["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'identity' key in token claims, got keys: %v", mapKeys(claims))
	}

	return identity
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
