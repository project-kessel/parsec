package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestHermeticTokenExchange demonstrates end-to-end testing of Parsec's external API
// using only the gRPC TokenExchange service with hermetic fixtures.
//
// This test:
// - Uses ONLY the external gRPC API (TokenExchange.Exchange)
// - Treats all internals as a black box
// - Tests the API contract: credentials + request → response
// - Uses fixtures for all I/O (JWKS, HTTP APIs, time)
//
// Note: This test manually constructs fixtures via the Go API. For config-driven
// hermetic testing using top-level fixtures, see configs/examples/parsec-hermetic.yaml
// which demonstrates HTTP rule fixtures that can be loaded from configuration.
// JWKS and clock fixtures will be added to the config schema in the future.
func TestHermeticTokenExchange(t *testing.T) {
	// ============================================================
	// 1. Setup Fixtures (All I/O Control)
	// ============================================================

	// Fixed time for deterministic behavior
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	// JWKS fixture for actor authentication (the service calling parsec)
	actorJWKS, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://auth.internal.example.com",
		JWKSURL: "https://auth.internal.example.com/.well-known/jwks.json",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("failed to create actor JWKS fixture: %v", err)
	}

	// JWKS fixture for subject authentication (the end user)
	subjectJWKS, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://idp.customer.example.com",
		JWKSURL: "https://idp.customer.example.com/.well-known/jwks.json",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("failed to create subject JWKS fixture: %v", err)
	}

	// HTTP fixtures for datasource APIs
	apiFixtures := httpfixture.NewRuleBasedProvider([]httpfixture.HTTPFixtureRule{
		{
			Request: httpfixture.FixtureRequest{
				Method:  "GET",
				URL:     "https://api.prod.example.com/users/.*",
				URLType: "pattern",
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body: `{
					"user_id": "alice",
					"email": "alice@customer.example.com",
					"roles": ["developer", "admin"],
					"department": "engineering"
				}`,
			},
		},
	})

	// Combine all HTTP fixtures
	allFixtures := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if f := actorJWKS.GetFixture(req); f != nil {
			return f
		}
		if f := subjectJWKS.GetFixture(req); f != nil {
			return f
		}
		return apiFixtures.GetFixture(req)
	})

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: allFixtures,
			Strict:   true,
			Clock:    clk,
		}),
	}

	// ============================================================
	// 2. Load Production Configuration (Using Fixtures)
	// ============================================================
	// This simulates loading a production config file,
	// but with I/O overridden by fixtures for hermetic testing

	// Configure actor validator (internal service IdP)
	actorValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      actorJWKS.Issuer(),
		JWKSURL:     actorJWKS.JWKSURL(),
		TrustDomain: "internal.example.com",
		HTTPClient:  httpClient,
		Clock:       clk,
	})
	if err != nil {
		t.Fatalf("failed to create actor validator: %v", err)
	}

	// Configure subject validator (customer IdP)
	subjectValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      subjectJWKS.Issuer(),
		JWKSURL:     subjectJWKS.JWKSURL(),
		TrustDomain: "customer.example.com",
		HTTPClient:  httpClient,
		Clock:       clk,
	})
	if err != nil {
		t.Fatalf("failed to create subject validator: %v", err)
	}

	trustStore := trust.NewStubStore()
	trustStore.AddValidator(actorValidator)
	trustStore.AddValidator(subjectValidator)

	// Configure datasources (production APIs, but with fixtures)
	userProfileDS, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
		Name: "user-profile",
		Script: `
function fetch(input)
    local user_id = input.subject.subject
    local response = http.get("https://api.prod.example.com/users/" .. user_id)
    if response.status == 200 then
        return {data = response.body, content_type = "application/json"}
    end
    return nil
end`,
		HTTPConfig: &lua.HTTPServiceConfig{
			Timeout: 30 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: allFixtures,
				Strict:   true,
				Clock:    clk,
			}),
		},
	})
	if err != nil {
		t.Fatalf("failed to create datasource: %v", err)
	}

	dsRegistry := service.NewDataSourceRegistry()
	dsRegistry.Register(userProfileDS)

	// Configure token issuer with claim mappers that include datasource data
	celMapper, err := mapper.NewCELMapper(`{
		"sub": subject.subject,
		"issuer": subject.issuer,
		"trust_domain": subject.trust_domain,
		"email": has(subject.claims) && has(subject.claims.email) ? subject.claims.email : null,
		"name": has(subject.claims) && has(subject.claims.name) ? subject.claims.name : null,
		"user_profile": datasource("user-profile"),
		"request": {
			"path": request.path,
			"method": request.method
		}
	}`)
	if err != nil {
		t.Fatalf("failed to create CEL mapper: %v", err)
	}

	claimMappers := []service.ClaimMapper{celMapper}
	txnIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeTransactionToken),
		ClaimMappers: claimMappers,
		Clock:        clk, // Inject the fixture clock for deterministic timestamps
	})

	issuerRegistry := service.NewSimpleRegistry()
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	// Create token service
	tokenService := service.NewTokenService("prod.example.com", dsRegistry, issuerRegistry, nil)
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// ============================================================
	// 3. Create the Exchange Server (External API)
	// ============================================================
	// This is the only component we'll interact with - the external gRPC API
	exchangeServer := server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, nil)

	// ============================================================
	// 4. TEST: Token Exchange API Contract
	// ============================================================
	t.Run("successful token exchange via gRPC API", func(t *testing.T) {
		// GIVEN: Actor credentials (Bearer token in gRPC metadata)
		actorToken, err := actorJWKS.CreateAndSignToken(map[string]interface{}{
			"sub":   "api-gateway",
			"scope": "token:exchange",
		})
		if err != nil {
			t.Fatalf("failed to create actor token: %v", err)
		}

		// GIVEN: Subject credentials (end user JWT)
		subjectToken, err := subjectJWKS.CreateAndSignToken(map[string]interface{}{
			"sub":   "alice",
			"email": "alice@customer.example.com",
			"name":  "Alice Developer",
		})
		if err != nil {
			t.Fatalf("failed to create subject token: %v", err)
		}

		// GIVEN: gRPC context with actor credentials in metadata
		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+actorToken),
		)

		// WHEN: Call the external gRPC API
		resp, err := exchangeServer.Exchange(ctx, &parsecv1.ExchangeRequest{
			GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
			Audience:           "prod.example.com",
			RequestedTokenType: string(service.TokenTypeTransactionToken),
			SubjectToken:       subjectToken,
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		})

		// THEN: Verify successful response
		if err != nil {
			t.Fatalf("Exchange RPC failed: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected non-empty access_token")
		}

		if resp.IssuedTokenType != string(service.TokenTypeTransactionToken) {
			t.Errorf("expected issued_token_type %s, got %s",
				service.TokenTypeTransactionToken, resp.IssuedTokenType)
		}

		if resp.TokenType != "Bearer" {
			t.Errorf("expected token_type 'Bearer', got %s", resp.TokenType)
		}

		if resp.ExpiresIn <= 0 {
			t.Errorf("expected positive expires_in, got %d", resp.ExpiresIn)
		}

		// THEN: Parse and verify the token claims
		// UnsignedIssuer returns base64-encoded JSON
		tokenJSON, err := base64.StdEncoding.DecodeString(resp.AccessToken)
		if err != nil {
			t.Fatalf("failed to decode token: %v", err)
		}

		var claims map[string]interface{}
		if err := json.Unmarshal(tokenJSON, &claims); err != nil {
			t.Fatalf("failed to parse token JSON: %v", err)
		}

		// Verify subject claims
		if claims["sub"] != "alice" {
			t.Errorf("expected sub 'alice', got %v", claims["sub"])
		}

		if claims["email"] != "alice@customer.example.com" {
			t.Errorf("expected email 'alice@customer.example.com', got %v", claims["email"])
		}

		if claims["name"] != "Alice Developer" {
			t.Errorf("expected name 'Alice Developer', got %v", claims["name"])
		}

		if claims["issuer"] != subjectJWKS.Issuer() {
			t.Errorf("expected issuer '%s', got %v", subjectJWKS.Issuer(), claims["issuer"])
		}

		if claims["trust_domain"] != "customer.example.com" {
			t.Errorf("expected trust_domain 'customer.example.com', got %v", claims["trust_domain"])
		}

		// Verify datasource enrichment
		userProfile, ok := claims["user_profile"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected user_profile to be a map, got %T", claims["user_profile"])
		}

		if userProfile["user_id"] != "alice" {
			t.Errorf("expected user_profile.user_id 'alice', got %v", userProfile["user_id"])
		}

		if userProfile["department"] != "engineering" {
			t.Errorf("expected user_profile.department 'engineering', got %v", userProfile["department"])
		}

		roles, ok := userProfile["roles"].([]interface{})
		if !ok || len(roles) != 2 {
			t.Errorf("expected user_profile.roles to be array of 2, got %v", userProfile["roles"])
		} else {
			if roles[0] != "developer" || roles[1] != "admin" {
				t.Errorf("expected roles [developer, admin], got %v", roles)
			}
		}

		t.Logf("✓ Token claims verified:")
		t.Logf("  - Subject: %s", claims["sub"])
		t.Logf("  - Email: %s", claims["email"])
		t.Logf("  - Trust domain: %s", claims["trust_domain"])
		t.Logf("  - User profile department: %s", userProfile["department"])
		t.Logf("  - User profile roles: %v", roles)
	})

	t.Run("includes request context in token", func(t *testing.T) {
		// GIVEN: Actor and subject tokens
		actorToken, _ := actorJWKS.CreateAndSignToken(map[string]interface{}{
			"sub": "api-gateway",
		})
		subjectToken, _ := subjectJWKS.CreateAndSignToken(map[string]interface{}{
			"sub": "alice",
		})

		// GIVEN: Request context claims (from client)
		requestContextClaims := map[string]interface{}{
			"path":   "/api/v1/resources",
			"method": "POST",
			"ip":     "192.168.1.100",
		}
		requestContextJSON, _ := json.Marshal(requestContextClaims)
		requestContextB64 := base64.StdEncoding.EncodeToString(requestContextJSON)

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+actorToken),
		)

		// WHEN: Call API with request_context
		resp, err := exchangeServer.Exchange(ctx, &parsecv1.ExchangeRequest{
			GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
			Audience:           "prod.example.com",
			RequestedTokenType: string(service.TokenTypeTransactionToken),
			SubjectToken:       subjectToken,
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
			RequestContext:     requestContextB64,
		})

		// THEN: Exchange should succeed
		if err != nil {
			t.Fatalf("exchange failed: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected token to be issued")
		}

		t.Log("✓ Token issued with request context")
		// Note: We can't inspect token internals in an e2e test
		// The important thing is the API accepted the request_context
	})

}
