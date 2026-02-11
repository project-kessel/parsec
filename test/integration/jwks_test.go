package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestJWKSEndpoint tests that the JWKS endpoint returns valid JSON Web Key Sets
func TestJWKSEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()
	issuerRegistry := service.NewSimpleRegistry()

	// Create a signing transaction token issuer with an in-memory key manager
	kp := keys.NewInMemoryKeyProvider(keys.KeyTypeECP256, "ES256")
	slotStore := keys.NewInMemoryKeySlotStore()
	providerRegistry := map[string]keys.KeyProvider{
		"test-provider": kp,
	}
	signer := keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
		Namespace:           string(service.TokenTypeTransactionToken),
		KeyProviderID:       "test-provider",
		KeyProviderRegistry: providerRegistry,
		SlotStore:           slotStore,
	})

	if err := signer.Start(ctx); err != nil {
		t.Fatalf("Failed to start signer: %v", err)
	}

	txnIssuer := issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		Signer:                    signer,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
	})

	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	// Create claims filter registry
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19092,
		HTTPPort:       18082,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, nil),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry}),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(ctx) }()

	// Wait for the server to be ready
	waitForServer(t, 18082, 5*time.Second)

	t.Run("GET /v1/jwks.json", func(t *testing.T) {
		testJWKSEndpoint(t, "http://localhost:18082/v1/jwks.json")
	})

	t.Run("GET /.well-known/jwks.json", func(t *testing.T) {
		testJWKSEndpoint(t, "http://localhost:18082/.well-known/jwks.json")
	})
}

func testJWKSEndpoint(t *testing.T, url string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify content type is JSON
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Logf("Warning: Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse the JWKS response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// Verify we have at least one key
	if len(jwks.Keys) == 0 {
		t.Fatal("Expected at least one key in JWKS, got none")
	}

	// Verify the key has required fields per RFC 7517
	key := jwks.Keys[0]

	requiredFields := []string{"kty", "kid", "alg"}
	for _, field := range requiredFields {
		if _, ok := key[field]; !ok {
			t.Errorf("Key missing required field: %s", field)
		}
	}

	// For EC keys, verify curve-specific fields
	if key["kty"] == "EC" {
		ecFields := []string{"crv", "x", "y"}
		for _, field := range ecFields {
			if _, ok := key[field]; !ok {
				t.Errorf("EC key missing required field: %s", field)
			}
		}

		// Verify the curve is P-256 (as configured)
		if key["crv"] != "P-256" {
			t.Errorf("Expected curve P-256, got %v", key["crv"])
		}

		// Verify algorithm
		if key["alg"] != "ES256" {
			t.Errorf("Expected algorithm ES256, got %v", key["alg"])
		}
	}

	// Verify 'use' field if present (should be 'sig' for signing keys)
	if use, ok := key["use"]; ok {
		if use != "sig" {
			t.Errorf("Expected use 'sig', got %v", use)
		}
	}

	t.Logf("✓ JWKS endpoint returned valid key set")
	t.Logf("  Key type: %v", key["kty"])
	t.Logf("  Key ID: %v", key["kid"])
	t.Logf("  Algorithm: %v", key["alg"])
	if key["kty"] == "EC" {
		t.Logf("  Curve: %v", key["crv"])
	}
}

// TestJWKSWithMultipleIssuers tests that JWKS returns keys from multiple issuers
func TestJWKSWithMultipleIssuers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()
	issuerRegistry := service.NewSimpleRegistry()

	// Create first issuer (transaction token with ECP256)
	kp1 := keys.NewInMemoryKeyProvider(keys.KeyTypeECP256, "ES256")
	slotStore1 := keys.NewInMemoryKeySlotStore()
	providerRegistry1 := map[string]keys.KeyProvider{
		"test-provider-1": kp1,
	}
	rotatingSigner1 := keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
		Namespace:           string(service.TokenTypeTransactionToken),
		KeyProviderID:       "test-provider-1",
		KeyProviderRegistry: providerRegistry1,
		SlotStore:           slotStore1,
	})

	if err := rotatingSigner1.Start(ctx); err != nil {
		t.Fatalf("Failed to start rotating signer 1: %v", err)
	}

	txnIssuer := issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		Signer:                    rotatingSigner1,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
	})

	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	// Create second issuer (access token with ECP384)
	kp2 := keys.NewInMemoryKeyProvider(keys.KeyTypeECP384, "ES384")
	slotStore2 := keys.NewInMemoryKeySlotStore()
	providerRegistry2 := map[string]keys.KeyProvider{
		"test-provider-2": kp2,
	}
	rotatingSigner2 := keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
		Namespace:           string(service.TokenTypeAccessToken),
		KeyProviderID:       "test-provider-2",
		KeyProviderRegistry: providerRegistry2,
		SlotStore:           slotStore2,
	})

	if err := rotatingSigner2.Start(ctx); err != nil {
		t.Fatalf("Failed to start rotating key manager 2: %v", err)
	}

	accessIssuer := issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       15 * time.Minute,
		Signer:                    rotatingSigner2,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{},
	})

	issuerRegistry.Register(service.TokenTypeAccessToken, accessIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	// Create claims filter registry
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19093,
		HTTPPort:       18083,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, nil),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry}),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(ctx) }()

	// Wait for the server to be ready
	waitForServer(t, 18083, 5*time.Second)

	// Request JWKS
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:18083/v1/jwks.json")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// Verify we have keys from both issuers
	if len(jwks.Keys) < 2 {
		t.Fatalf("Expected at least 2 keys (one per issuer), got %d", len(jwks.Keys))
	}

	// Verify we have different curves
	curves := make(map[string]bool)
	for _, key := range jwks.Keys {
		if crv, ok := key["crv"]; ok {
			curves[crv.(string)] = true
		}
	}

	if len(curves) < 2 {
		t.Errorf("Expected keys with different curves, got: %v", curves)
	}

	t.Logf("✓ JWKS endpoint returned keys from multiple issuers")
	t.Logf("  Total keys: %d", len(jwks.Keys))
	t.Logf("  Curves: %v", curves)
}

// TestJWKSWithUnsignedIssuer tests that unsigned issuers don't contribute keys to JWKS
func TestJWKSWithUnsignedIssuer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()
	issuerRegistry := service.NewSimpleRegistry()

	// Create an unsigned issuer (no public keys)
	unsignedIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeTransactionToken),
		ClaimMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
	})

	issuerRegistry.Register(service.TokenTypeTransactionToken, unsignedIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	// Create claims filter registry
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19094,
		HTTPPort:       18084,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, nil),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry}),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(ctx) }()

	// Wait for the server to be ready
	waitForServer(t, 18084, 5*time.Second)

	// Request JWKS
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:18084/v1/jwks.json")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// Verify we have no keys (unsigned issuer doesn't provide public keys)
	if len(jwks.Keys) != 0 {
		t.Errorf("Expected 0 keys from unsigned issuer, got %d", len(jwks.Keys))
	}

	t.Logf("✓ JWKS endpoint correctly returns empty set for unsigned issuer")
}
