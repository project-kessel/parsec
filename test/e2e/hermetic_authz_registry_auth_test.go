package e2e_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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

// TestHermeticAuthzCheck demonstrates end-to-end testing of Parsec's ext_authz
// Authorization.Check RPC using hermetic fixtures.
//
// This test:
// - Uses ONLY the external gRPC API (Authorization.Check)
// - Treats all internals as a black box
// - Tests the API contract: credentials → Check response with issued tokens
// - Uses fixtures for all I/O (HTTP endpoints, time)
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

	registryAuthTests(t, authzServer)
}

// IMPORTANT: registry auth flow is specific to Red Hat HCC deployment of parsec.
// These tests could be ripped out at any time should we refactor e2e tests to keep things generic.
//
// registryAuthTests runs the registry auth test cases against the given
// AuthzServer. Registry auth validates Basic Auth credentials of the form
// "org_id|username:password" against an external registry authorization service.
// The org_id prefix is optional — credentials like "|username:password" are valid
// and should produce a successful response with an empty org_id.
func registryAuthTests(t *testing.T, authzServer *server.AuthzServer) {
	t.Run("registry auth with org_id", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("123|alice", "secret"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "registry-auth" {
			t.Errorf("expected auth_type 'registry-auth', got %v", identity["auth_type"])
		}
		if identity["org_id"] != "123" {
			t.Errorf("expected org_id '123', got %v", identity["org_id"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["username"] != "alice" {
			t.Errorf("expected username 'alice', got %v", user["username"])
		}
	})

	t.Run("registry auth without org_id", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("|alice", "secret"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "registry-auth" {
			t.Errorf("expected auth_type 'registry-auth', got %v", identity["auth_type"])
		}
		if identity["org_id"] != nil {
			t.Errorf("expected org_id nil, got %v", identity["org_id"])
		}

		user := assertNestedMap(t, identity, "user")
		if user["username"] != "alice" {
			t.Errorf("expected username 'alice', got %v", user["username"])
		}
	})

	t.Run("rejects missing pipe separator", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("alice", "secret"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("rejects empty password", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("|alice", ""))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})
}

func checkRequestWithBasicAuth(username, password string) *authv3.CheckRequest {
	cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/test",
					Headers: map[string]string{
						"authorization": "Basic " + cred,
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
