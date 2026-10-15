package e2e_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestHermeticAuthzJWT_EnforceIdpAuth(t *testing.T) {
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

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("failed to read redhat_identity.cel: %v", err)
	}

	celMapper, err := mapper.NewCELMapper(string(celScript), mapper.WithClock(clk))
	if err != nil {
		t.Fatalf("failed to create CEL mapper: %v", err)
	}

	buildServer := func(enforceIdpAuth bool) *server.AuthzServer {
		trustStore := trust.NewStubStore()
		trustStore.AddValidator(jwtValidator)

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
			"enforce_idp_auth":      enforceIdpAuth,
		})
		if err != nil {
			t.Fatalf("failed to create identity-policy datasource: %v", err)
		}

		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)

		tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, nil)
		return server.NewAuthzServer(trustStore, tokenService, nil, server.DefaultCredentialSources(), nil)
	}

	consoleTokenWithoutIdp := mustSignToken(t, jwksFixture, map[string]interface{}{
		"sub":                "user-123",
		"preferred_username": "jdoe",
		"email":              "jdoe@example.com",
		"scope":              "api.console openid",
		"organization": map[string]interface{}{
			"id":             "org-1",
			"account_number": "12345",
		},
	})

	t.Run("enforced denies console token without idp", func(t *testing.T) {
		authzServer := buildServer(true)
		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(consoleTokenWithoutIdp))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}
		assertDeniedContains(t, resp, "claim 'idp' is required")
	})

	t.Run("not enforced allows console token without idp", func(t *testing.T) {
		authzServer := buildServer(false)
		resp, err := authzServer.Check(context.Background(), checkRequestWithBearer(consoleTokenWithoutIdp))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}
		assertOKResponse(t, resp)
		identity := decodeTokenIdentity(t, resp)
		if identity["type"] != "User" {
			t.Errorf("expected type=User, got %v", identity["type"])
		}
	})
}
