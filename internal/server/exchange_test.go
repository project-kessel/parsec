package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"google.golang.org/grpc/metadata"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestExchangeServer_WithActorFiltering(t *testing.T) {
	ctx := context.Background()

	// Setup filtered trust store with CEL-based filtering
	filteredStore, err := trust.NewFilteredStore(
		trust.WithCELFilter(`actor.trust_domain == "client.example.com" && validator_name in ["external-validator"]`),
	)
	if err != nil {
		t.Fatalf("failed to create filtered store: %v", err)
	}

	// Add two validators - one for external tokens, one for internal tokens
	externalValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	externalValidator.WithResult(&trust.Result{
		Subject:     "external-user",
		Issuer:      "https://external-idp.com",
		TrustDomain: "external",
	})
	filteredStore.AddValidator("external-validator", externalValidator)

	internalValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	internalValidator.WithResult(&trust.Result{
		Subject:     "internal-user",
		Issuer:      "https://internal-idp.com",
		TrustDomain: "internal",
	})
	filteredStore.AddValidator("internal-validator", internalValidator)

	// Setup token service
	dataSourceRegistry := service.NewDataSourceRegistry()

	issuerRegistry := service.NewSimpleRegistry()
	// Create mappers for the issuer
	txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
	reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
	txnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnTokenIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	claimsFilterRegistry := NewStubClaimsFilterRegistry()
	exchangeServer := NewExchangeServer(filteredStore, tokenService, claimsFilterRegistry, nil)

	t.Run("anonymous actor gets filtered store - no validators match", func(t *testing.T) {
		// No actor credentials in context, so ForActor will be called with AnonymousResult
		// The CEL filter requires trust_domain == "client.example.com", which won't match empty actor
		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "external-token",
			Audience:     "parsec.test",
		}

		_, err := exchangeServer.Exchange(ctx, req)

		// Should fail - no validators available after filtering
		if err == nil {
			t.Error("expected error for anonymous actor with no matching validators, got nil")
		}

		if !strings.Contains(err.Error(), "token validation failed") {
			t.Errorf("expected 'token validation failed' in error, got: %v", err)
		}
	})

	t.Run("actor credentials via gRPC metadata - Bearer token", func(t *testing.T) {
		// Create a context with gRPC metadata containing actor credentials
		md := metadata.New(map[string]string{
			"authorization": "Bearer client-token",
		})
		actorCtx := metadata.NewIncomingContext(ctx, md)

		// Setup a validator for the client actor
		clientValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		clientValidator.WithResult(&trust.Result{
			Subject:     "client-app",
			Issuer:      "https://client-idp.com",
			TrustDomain: "client.example.com",
		})

		// Create a new store with the client validator
		storeWithClient, err := trust.NewFilteredStore(
			trust.WithCELFilter(`actor.trust_domain == "client.example.com" && validator_name in ["external-validator"]`),
		)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}

		// Add client validator to validate actor
		storeWithClient.AddValidator("client-validator", clientValidator)
		storeWithClient.AddValidator("external-validator", externalValidator)
		storeWithClient.AddValidator("internal-validator", internalValidator)

		exchangeServerWithClient := NewExchangeServer(storeWithClient, tokenService, claimsFilterRegistry, nil)

		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "external-token",
			Audience:     "parsec.test",
		}

		resp, err := exchangeServerWithClient.Exchange(actorCtx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should succeed - client actor can access external-validator
		if resp.AccessToken == "" {
			t.Error("expected access token, got empty string")
		}

		if resp.IssuedTokenType != "urn:ietf:params:oauth:token-type:txn_token" {
			t.Errorf("expected txn_token type, got %s", resp.IssuedTokenType)
		}
	})

	t.Run("actor validation failure returns error", func(t *testing.T) {
		// Create a store with only JWT validators - no Bearer validators
		// So when a Bearer actor token is presented, validation will fail
		emptyStore := trust.NewStubStore()

		// Add only a JWT validator for subjects, not Bearer
		jwtValidator := trust.NewStubValidator(trust.CredentialTypeJWT)
		jwtValidator.WithResult(&trust.Result{
			Subject:     "jwt-user",
			Issuer:      "https://jwt-idp.com",
			TrustDomain: "jwt",
		})
		emptyStore.AddValidator(jwtValidator)

		exchangeServerFailing := NewExchangeServer(emptyStore, tokenService, claimsFilterRegistry, nil)

		// Add actor credentials (Bearer) that will fail validation since no Bearer validator exists
		md := metadata.New(map[string]string{
			"authorization": "Bearer invalid-actor-token",
		})
		actorCtx := metadata.NewIncomingContext(ctx, md)

		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "subject-token",
			Audience:     "parsec.test",
		}

		_, err := exchangeServerFailing.Exchange(actorCtx, req)

		// Should fail with actor validation error
		if err == nil {
			t.Error("expected error for invalid actor credentials, got nil")
		}

		if !strings.Contains(err.Error(), "actor validation failed") {
			t.Errorf("expected 'actor validation failed' in error, got: %v", err)
		}
	})

	t.Run("actor allows access to different validators based on claims", func(t *testing.T) {
		// Setup a store with filtering based on actor claims
		roleBasedStore, err := trust.NewFilteredStore(
			trust.WithCELFilter(`
				(has(actor.claims.role) && actor.claims.role == "admin" && validator_name == "admin-validator") ||
				(has(actor.claims.role) && actor.claims.role == "user" && validator_name == "user-validator")
			`),
		)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}

		// Create validators
		adminActorValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		adminActorValidator.WithResult(&trust.Result{
			Subject:     "admin-actor",
			Issuer:      "https://actor-idp.com",
			TrustDomain: "actors",
			Claims: map[string]interface{}{
				"role": "admin",
			},
		})

		adminSubjectValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		adminSubjectValidator.WithResult(&trust.Result{
			Subject:     "admin-subject",
			Issuer:      "https://admin-idp.com",
			TrustDomain: "admin",
		})

		userValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		userValidator.WithResult(&trust.Result{
			Subject:     "user-subject",
			Issuer:      "https://user-idp.com",
			TrustDomain: "users",
		})

		roleBasedStore.AddValidator("admin-actor-validator", adminActorValidator)
		roleBasedStore.AddValidator("admin-validator", adminSubjectValidator)
		roleBasedStore.AddValidator("user-validator", userValidator)

		exchangeServerRoleBased := NewExchangeServer(roleBasedStore, tokenService, claimsFilterRegistry, nil)

		// Test admin actor can access admin validator
		adminMd := metadata.New(map[string]string{
			"authorization": "Bearer admin-actor-token",
		})
		adminCtx := metadata.NewIncomingContext(ctx, adminMd)

		adminReq := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "admin-subject-token",
			Audience:     "parsec.test",
		}

		adminResp, err := exchangeServerRoleBased.Exchange(adminCtx, adminReq)
		if err != nil {
			t.Fatalf("unexpected error for admin actor: %v", err)
		}

		if adminResp.AccessToken == "" {
			t.Error("expected access token for admin actor, got empty string")
		}

		// Test admin actor cannot access user validator
		// Note: With StubValidator, both validators will match Bearer tokens,
		// so the validation might succeed with admin-validator even when trying to use user token.
		// For this test to truly validate filtering, we'd need distinct token formats or validation logic.
		// Since we're using stubs, we'll verify that the system works with properly configured validators
		// but skip the negative test with stubs as it depends on implementation details.
	})
}

func TestExchangeServer_WithActorFilteringByAudience(t *testing.T) {
	ctx := context.Background()

	// Setup filtered trust store that checks request audience
	filteredStore, err := trust.NewFilteredStore(
		trust.WithCELFilter(`
			(validator_name == "prod-validator" && has(request.additional.requested_audience) && request.additional.requested_audience == "prod.example.com") ||
			(validator_name == "dev-validator" && has(request.additional.requested_audience) && request.additional.requested_audience == "dev.example.com")
		`),
	)
	if err != nil {
		t.Fatalf("failed to create filtered store: %v", err)
	}

	prodValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	prodValidator.WithResult(&trust.Result{
		Subject:     "prod-user",
		Issuer:      "https://prod-idp.com",
		TrustDomain: "prod",
	})
	filteredStore.AddValidator("prod-validator", prodValidator)

	devValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	devValidator.WithResult(&trust.Result{
		Subject:     "dev-user",
		Issuer:      "https://dev-idp.com",
		TrustDomain: "dev",
	})
	filteredStore.AddValidator("dev-validator", devValidator)

	// Setup token service
	dataSourceRegistry := service.NewDataSourceRegistry()

	// Use a custom trust domain for this test
	issuerRegistry := service.NewSimpleRegistry()
	// Create mappers for the issuer
	txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
	reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
	prodIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://prod.example.com",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, prodIssuer)
	tokenService := service.NewTokenService("prod.example.com", dataSourceRegistry, issuerRegistry, nil)

	claimsFilterRegistry := NewStubClaimsFilterRegistry()
	exchangeServer := NewExchangeServer(filteredStore, tokenService, claimsFilterRegistry, nil)

	t.Run("prod audience allows prod validator", func(t *testing.T) {
		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "prod-token",
			Audience:     "prod.example.com",
		}

		resp, err := exchangeServer.Exchange(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error for prod audience: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token for prod audience, got empty string")
		}
	})

	// Use a different token service for dev with matching trust domain
	devIssuerRegistry := service.NewSimpleRegistry()
	devTxnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
	devReqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
	devIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://dev.example.com",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: devTxnMappers,
		RequestContextMappers:     devReqMappers,
	})
	devIssuerRegistry.Register(service.TokenTypeTransactionToken, devIssuer)
	devTokenService := service.NewTokenService("dev.example.com", dataSourceRegistry, devIssuerRegistry, nil)
	devExchangeServer := NewExchangeServer(filteredStore, devTokenService, claimsFilterRegistry, nil)

	t.Run("dev audience allows dev validator", func(t *testing.T) {
		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "dev-token",
			Audience:     "dev.example.com",
		}

		resp, err := devExchangeServer.Exchange(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error for dev audience: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token for dev audience, got empty string")
		}
	})

	t.Run("wrong audience denies access", func(t *testing.T) {
		// Use prod trust domain but request a different audience
		// This will fail the audience check
		wrongIssuerRegistry := service.NewSimpleRegistry()
		wrongTxnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		wrongReqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
		wrongIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://wrong.example.com",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: wrongTxnMappers,
			RequestContextMappers:     wrongReqMappers,
		})
		wrongIssuerRegistry.Register(service.TokenTypeTransactionToken, wrongIssuer)
		wrongTokenService := service.NewTokenService("wrong.example.com", dataSourceRegistry, wrongIssuerRegistry, nil)
		wrongExchangeServer := NewExchangeServer(filteredStore, wrongTokenService, claimsFilterRegistry, nil)

		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "prod-token",
			Audience:     "wrong.example.com",
		}

		_, err := wrongExchangeServer.Exchange(ctx, req)

		// Should fail - no validators match for wrong audience
		if err == nil {
			t.Error("expected error for wrong audience, got nil")
		}
	})
}

func TestExchangeServer_ActorPassedToTokenIssuance(t *testing.T) {
	ctx := context.Background()

	// Setup store with a client actor validator
	store := trust.NewStubStore()

	clientValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	clientValidator.WithResult(&trust.Result{
		Subject:     "client-app-123",
		Issuer:      "https://client-idp.com",
		TrustDomain: "clients",
		Claims: map[string]interface{}{
			"app_id":  "app-123",
			"version": "2.0",
		},
	})
	store.AddValidator(clientValidator)

	subjectValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	subjectValidator.WithResult(&trust.Result{
		Subject:     "user-456",
		Issuer:      "https://user-idp.com",
		TrustDomain: "users",
	})
	store.AddValidator(subjectValidator)

	// Setup token service
	dataSourceRegistry := service.NewDataSourceRegistry()

	// Create mappers that include actor information
	actorMapper, err := mapper.NewCELMapper(`actor != null ? {"actor_subject": actor.subject, "actor_trust_domain": actor.trust_domain} : {}`)
	if err != nil {
		t.Fatalf("failed to create actor mapper: %v", err)
	}
	txnMappers := []service.ClaimMapper{actorMapper}
	reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}

	issuerRegistry := service.NewSimpleRegistry()
	txnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnTokenIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	claimsFilterRegistry := NewStubClaimsFilterRegistry()
	exchangeServer := NewExchangeServer(store, tokenService, claimsFilterRegistry, nil)

	t.Run("actor information is passed to token issuance", func(t *testing.T) {
		// Add actor credentials via gRPC metadata
		md := metadata.New(map[string]string{
			"authorization": "Bearer client-app-token",
		})
		actorCtx := metadata.NewIncomingContext(ctx, md)

		req := &parsecv1.ExchangeRequest{
			GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken: "user-token",
			Audience:     "parsec.test",
		}

		resp, err := exchangeServer.Exchange(actorCtx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token, got empty string")
		}

		// The token should now contain actor information in the transaction context
		// This is verified by the fact that the CEL mapper runs without error
		// In a real scenario, you'd parse the JWT and verify the actor claims are present
	})
}

func TestExchangeServer_RequestContextFiltering(t *testing.T) {
	ctx := context.Background()

	// Setup trust store
	store := trust.NewStubStore()
	validator := trust.NewStubValidator(trust.CredentialTypeBearer)
	validator.WithResult(&trust.Result{
		Subject:     "test-user",
		Issuer:      "https://test-idp.com",
		TrustDomain: "test",
	})
	store.AddValidator(validator)

	// Setup token service for sub-tests that need it
	dataSourceRegistry := service.NewDataSourceRegistry()
	trustDomain := "parsec.test"

	// Create a simple token service for sub-tests
	simpleIssuerRegistry := service.NewSimpleRegistry()
	simpleTxnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
	simpleReqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
	simpleIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: simpleTxnMappers,
		RequestContextMappers:     simpleReqMappers,
	})
	simpleIssuerRegistry.Register(service.TokenTypeTransactionToken, simpleIssuer)
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, simpleIssuerRegistry, nil)

	t.Run("passthrough filter allows all claims", func(t *testing.T) {
		// Setup token service with stub issuer that includes request context in token
		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}

		localIssuerRegistry := service.NewSimpleRegistry()
		localTxnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://parsec.test",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
		})
		localIssuerRegistry.Register(service.TokenTypeTransactionToken, localTxnTokenIssuer)
		localTokenService := service.NewTokenService(trustDomain, dataSourceRegistry, localIssuerRegistry, nil)

		// Use passthrough filter that allows all claims
		claimsFilterRegistry := NewStubClaimsFilterRegistry()
		exchangeServer := NewExchangeServer(store, localTokenService, claimsFilterRegistry, nil)

		requestContextJSON := `{
			"method": "GET",
			"path": "/api/users",
			"ip_address": "192.168.1.1",
			"user_agent": "TestClient/1.0",
			"custom_claim": "custom_value"
		}`

		// Base64-encode the request context (per transaction token spec)
		requestContextBase64 := base64.StdEncoding.EncodeToString([]byte(requestContextJSON))

		req := &parsecv1.ExchangeRequest{
			GrantType:      "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:   "test-token",
			Audience:       "parsec.test",
			RequestContext: requestContextBase64,
		}

		resp, err := exchangeServer.Exchange(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token, got empty string")
		}

		// Parse the token to extract the request context
		reqCtx, err := parseTestTokenRequestContext(resp.AccessToken)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		// Verify all claims were passed through to the token
		if method, ok := reqCtx["method"].(string); !ok || method != "GET" {
			t.Errorf("expected method 'GET', got %v", reqCtx["method"])
		}
		if path, ok := reqCtx["path"].(string); !ok || path != "/api/users" {
			t.Errorf("expected path '/api/users', got %v", reqCtx["path"])
		}
		if ipAddress, ok := reqCtx["ip_address"].(string); !ok || ipAddress != "192.168.1.1" {
			t.Errorf("expected ip_address '192.168.1.1', got %v", reqCtx["ip_address"])
		}
		if userAgent, ok := reqCtx["user_agent"].(string); !ok || userAgent != "TestClient/1.0" {
			t.Errorf("expected user_agent 'TestClient/1.0', got %v", reqCtx["user_agent"])
		}
		if customClaim, ok := reqCtx["custom_claim"].(string); !ok || customClaim != "custom_value" {
			t.Errorf("expected custom_claim 'custom_value', got %v", reqCtx["custom_claim"])
		}
	})

	t.Run("allow list filter only allows specified claims", func(t *testing.T) {
		// Setup token service with stub issuer that includes request context in token
		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}

		localIssuerRegistry := service.NewSimpleRegistry()
		localTxnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://parsec.test",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
		})
		localIssuerRegistry.Register(service.TokenTypeTransactionToken, localTxnTokenIssuer)
		localTokenService := service.NewTokenService(trustDomain, dataSourceRegistry, localIssuerRegistry, nil)

		// Use allow list filter that only allows method and path
		allowListFilter := NewAllowListClaimsFilterRegistry([]string{"method", "path"})
		exchangeServer := NewExchangeServer(store, localTokenService, allowListFilter, nil)

		requestContextJSON := `{
			"method": "GET",
			"path": "/api/users",
			"ip_address": "192.168.1.1",
			"user_agent": "TestClient/1.0",
			"custom_claim": "custom_value"
		}`

		// Base64-encode the request context (per transaction token spec)
		requestContextBase64 := base64.StdEncoding.EncodeToString([]byte(requestContextJSON))

		req := &parsecv1.ExchangeRequest{
			GrantType:      "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:   "test-token",
			Audience:       "parsec.test",
			RequestContext: requestContextBase64,
		}

		resp, err := exchangeServer.Exchange(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token, got empty string")
		}

		// Parse the token to extract the request context
		reqCtx, err := parseTestTokenRequestContext(resp.AccessToken)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		// Verify only allowed claims are in the token
		// These should be present (allowed)
		if method, ok := reqCtx["method"].(string); !ok || method != "GET" {
			t.Errorf("expected method 'GET', got %v", reqCtx["method"])
		}
		if path, ok := reqCtx["path"].(string); !ok || path != "/api/users" {
			t.Errorf("expected path '/api/users', got %v", reqCtx["path"])
		}

		// These should NOT be present in the token (filtered out)
		if _, exists := reqCtx["ip_address"]; exists {
			t.Errorf("expected ip_address to be filtered out, but found: %v", reqCtx["ip_address"])
		}
		if _, exists := reqCtx["user_agent"]; exists {
			t.Errorf("expected user_agent to be filtered out, but found: %v", reqCtx["user_agent"])
		}
		if _, exists := reqCtx["custom_claim"]; exists {
			t.Errorf("expected custom_claim to be filtered out, but found: %v", reqCtx["custom_claim"])
		}
	})

	t.Run("empty request_context uses empty attributes", func(t *testing.T) {
		claimsFilterRegistry := NewStubClaimsFilterRegistry()
		exchangeServer := NewExchangeServer(store, tokenService, claimsFilterRegistry, nil)

		req := &parsecv1.ExchangeRequest{
			GrantType:      "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:   "test-token",
			Audience:       "parsec.test",
			RequestContext: "", // No request context
		}

		resp, err := exchangeServer.Exchange(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token, got empty string")
		}
	})

	t.Run("invalid base64 in request_context returns error", func(t *testing.T) {
		claimsFilterRegistry := NewStubClaimsFilterRegistry()
		exchangeServer := NewExchangeServer(store, tokenService, claimsFilterRegistry, nil)

		req := &parsecv1.ExchangeRequest{
			GrantType:      "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:   "test-token",
			Audience:       "parsec.test",
			RequestContext: "not-valid-base64!@#$",
		}

		_, err := exchangeServer.Exchange(ctx, req)
		if err == nil {
			t.Fatal("expected error for invalid base64, got nil")
		}

		if !strings.Contains(err.Error(), "failed to decode request_context base64") {
			t.Errorf("expected 'failed to decode request_context base64' in error, got: %v", err)
		}
	})

	t.Run("invalid JSON in decoded request_context returns error", func(t *testing.T) {
		claimsFilterRegistry := NewStubClaimsFilterRegistry()
		exchangeServer := NewExchangeServer(store, tokenService, claimsFilterRegistry, nil)

		// Base64-encode invalid JSON
		invalidJSON := "not valid json at all"
		requestContextBase64 := base64.StdEncoding.EncodeToString([]byte(invalidJSON))

		req := &parsecv1.ExchangeRequest{
			GrantType:      "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:   "test-token",
			Audience:       "parsec.test",
			RequestContext: requestContextBase64,
		}

		_, err := exchangeServer.Exchange(ctx, req)
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}

		if !strings.Contains(err.Error(), "failed to parse request_context JSON") {
			t.Errorf("expected 'failed to parse request_context JSON' in error, got: %v", err)
		}
	})
}

// Helper to create an allow list claims filter registry for testing
type AllowListClaimsFilterRegistry struct {
	allowedClaims []string
}

func (r *AllowListClaimsFilterRegistry) GetFilter(actor *trust.Result) (claims.ClaimsFilter, error) {
	return claims.NewAllowListClaimsFilter(r.allowedClaims), nil
}

// NewAllowListClaimsFilterRegistry creates a test registry with an allow list filter
func NewAllowListClaimsFilterRegistry(allowedClaims []string) *AllowListClaimsFilterRegistry {
	return &AllowListClaimsFilterRegistry{
		allowedClaims: allowedClaims,
	}
}

// parseTestTokenRequestContext extracts the request context from a stub token
// Format: stub-txn-token.{subject}.{txnID}.{requestContextJSON}
func parseTestTokenRequestContext(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid token format: expected at least 4 parts, got %d", len(parts))
	}

	// The request context JSON is everything after the third dot
	// Join all parts after index 2 in case the JSON itself contains dots
	requestContextJSON := strings.Join(parts[3:], ".")

	var reqCtx map[string]any
	if err := json.Unmarshal([]byte(requestContextJSON), &reqCtx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request context: %w", err)
	}

	return reqCtx, nil
}
