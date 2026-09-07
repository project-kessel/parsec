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
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestHermeticAuthzCheckCertAuth demonstrates end-to-end testing of cert-auth
// via the ext_authz Authorization.Check RPC using hermetic fixtures.
//
// Cert auth validates certificate credentials forwarded as x-rh-certauth-cn
// and x-rh-certauth-issuer headers by a TLS-terminating proxy (e.g., Akamai).
// The Lua validator calls BOP (Back Office Proxy) to resolve the certificate
// identity into account_number, org_id, and cert_type.
func TestHermeticAuthzCheckCertAuth(t *testing.T) {
	// ============================================================
	// 1. Setup Fixtures
	// ============================================================

	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	bopBaseURL := "https://example.backoffice-proxy.api.redhat.com"
	bopAuthURL := bopBaseURL + "/v1/auth"

	bopFixture := httpfixture.NewRuleBasedProvider([]httpfixture.HTTPFixtureRule{
		{
			Request: httpfixture.FixtureRequest{
				Method:  "GET",
				URL:     bopAuthURL,
				URLType: "exact",
				Headers: map[string]string{"x-rh-certauth-cn": "/CN=no-user-field"},
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{}`,
			},
		},
		{
			Request: httpfixture.FixtureRequest{
				Method:  "GET",
				URL:     bopAuthURL,
				URLType: "exact",
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"user":{"account_number":"12345","org_id":"org-abc","type":"satellite"}}`,
			},
		},
	})

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: bopFixture,
			Strict:   true,
			Clock:    clk,
		}),
	}

	// ============================================================
	// 2. Load Production Scripts and Build Components
	// ============================================================

	luaScript, err := os.ReadFile("../../configs/scripts/forwarded_client_cert_auth.lua")
	if err != nil {
		t.Fatalf("failed to read forwarded_client_cert_auth.lua: %v", err)
	}

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("failed to read redhat_identity.cel: %v", err)
	}

	luaValidator, err := trust.NewLuaValidator(
		"cert-auth",
		string(luaScript),
		[]trust.CredentialType{trust.CredentialTypeForwardedClientCert},
		trust.WithLuaHTTPClient(httpClient),
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"bop_url":             bopBaseURL,
			"bop_env":             "stage",
			"trust_domain":        "cert.example.com",
			"issuer_host":         "rhsm.example.com",
			"bop_certauth_secret": "test-secret",
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
	tokenService := service.NewTokenService("cert.example.com", dsRegistry, issuerRegistry, nil)

	certAuthSrc, err := server.NewForwardedClientCertCredentialSource("cert-auth", "x-rh-certauth-cn", "x-rh-certauth-issuer")
	if err != nil {
		t.Fatalf("failed to create forwarded client cert credential source: %v", err)
	}
	credSources := server.NewCredentialSources(certAuthSrc)

	// ============================================================
	// 3. Create the Authz Server
	// ============================================================

	authzServer := server.NewAuthzServer(trustStore, tokenService, nil, credSources, nil)

	// ============================================================
	// 4. Test Cases
	// ============================================================

	certAuthTests(t, authzServer)
}

// certAuthTests runs cert-auth test cases against the given AuthzServer.
// Cert auth validates certificate credentials forwarded as x-rh-certauth-cn
// and x-rh-certauth-issuer headers by a TLS-terminating proxy.
func certAuthTests(t *testing.T, authzServer *server.AuthzServer) {
	t.Run("cert auth with simple CN", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithCertAuth("/CN=test-system-123", "CN=Red Hat CA"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "cert-auth" {
			t.Errorf("expected auth_type 'cert-auth', got %v", identity["auth_type"])
		}
		if identity["type"] != "System" {
			t.Errorf("expected type 'System', got %v", identity["type"])
		}
		if identity["org_id"] != "org-abc" {
			t.Errorf("expected org_id 'org-abc', got %v", identity["org_id"])
		}
		if identity["account_number"] != "12345" {
			t.Errorf("expected account_number '12345', got %v", identity["account_number"])
		}

		system := assertNestedMap(t, identity, "system")
		if system["cn"] != "test-system-123" {
			t.Errorf("expected system.cn 'test-system-123', got %v", system["cn"])
		}
		if system["cert_type"] != "satellite" {
			t.Errorf("expected system.cert_type 'satellite', got %v", system["cert_type"])
		}
	})

	t.Run("cert auth with compound subject", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithCertAuth("/O=MyOrg/CN=compound-cn/I=issuer", "CN=Some Issuer"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		system := assertNestedMap(t, identity, "system")
		if system["cn"] != "compound-cn" {
			t.Errorf("expected system.cn 'compound-cn', got %v", system["cn"])
		}
	})

	t.Run("rejects BOP response without user object", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithCertAuth("/CN=no-user-field", "CN=Red Hat CA"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("rejects missing cn header", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithHeaders(map[string]string{
				"x-rh-certauth-issuer": "CN=Some Issuer",
			}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("rejects missing issuer header", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithHeaders(map[string]string{
				"x-rh-certauth-cn": "/CN=test",
			}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("no cert headers returns denied", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithHeaders(map[string]string{}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})
}

func checkRequestWithCertAuth(cn, issuer string) *authv3.CheckRequest {
	return checkRequestWithHeaders(map[string]string{
		"x-rh-certauth-cn":     cn,
		"x-rh-certauth-issuer": issuer,
	})
}

func checkRequestWithHeaders(headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/api/test",
					Headers: headers,
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
