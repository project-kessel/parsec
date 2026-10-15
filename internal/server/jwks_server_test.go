package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// startJWKSTestServer creates a full test server with the given issuer
// registry, wiring up a stub trust store, data source registry, and token
// service so tests only need to set up issuers.
func startJWKSTestServer(t *testing.T, issuerRegistry service.Registry) *testEnv {
	t.Helper()
	trustStore := trust.NewStubStore()
	trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))

	dataSourceRegistry := service.NewDataSourceRegistry()
	tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)
	claimsFilterRegistry := NewStubClaimsFilterRegistry()

	return startTestServer(t, Config{
		AuthzServer:    NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil),
		ExchangeServer: NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, DefaultCredentialSources(), nil),
		JWKSServer:     NewJWKSServer(JWKSServerConfig{IssuerRegistry: issuerRegistry, Observer: NoOpServerObserver{}}),
		Observer:       NoOpServerObserver{},
	})
}

// newTestSigner creates and starts a DualSlotRotatingSigner with an in-memory
// key provider of the given type. Fails the test if the signer cannot start.
func newTestSigner(t *testing.T, namespace string, keyType keys.KeyType, algo string) *keys.DualSlotRotatingSigner {
	t.Helper()
	kp := keys.NewInMemoryKeyProvider(keys.InMemoryKeyProviderConfig{KeyType: keyType, Algorithm: algo})
	signer := keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
		Namespace:           namespace,
		KeyProviderID:       "test-provider",
		KeyProviderRegistry: map[string]keys.KeyProvider{"test-provider": kp},
		SlotStore:           keys.NewInMemoryKeySlotStore(),
		Observer:            keys.NoOpKeysObserver{},
	})
	if err := signer.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start signer: %v", err)
	}
	return signer
}

// TestJWKSEndpoint tests that the JWKS endpoint returns valid JSON Web Key Sets
// via the HTTP server.
func TestJWKSEndpoint(t *testing.T) {
	issuerRegistry := service.NewSimpleRegistry()
	signer := newTestSigner(t, string(service.TokenTypeTransactionToken), keys.KeyTypeECP256, "ES256")
	txnIssuer := issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		Signer:                    signer,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	env := startJWKSTestServer(t, issuerRegistry)

	t.Run("GET /v1/jwks.json", func(t *testing.T) {
		assertValidJWKS(t, env.HTTPClient, env.HTTPBaseURL+"/v1/jwks.json")
	})

	t.Run("GET /.well-known/jwks.json", func(t *testing.T) {
		assertValidJWKS(t, env.HTTPClient, env.HTTPBaseURL+"/.well-known/jwks.json")
	})
}

// TestJWKSWithMultipleIssuers tests that JWKS returns keys from multiple issuers.
func TestJWKSWithMultipleIssuers(t *testing.T) {
	issuerRegistry := service.NewSimpleRegistry()

	signer1 := newTestSigner(t, string(service.TokenTypeTransactionToken), keys.KeyTypeECP256, "ES256")
	txnIssuer := issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		Signer:                    signer1,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	signer2 := newTestSigner(t, string(service.TokenTypeAccessToken), keys.KeyTypeECP384, "ES384")
	accessIssuer := issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       15 * time.Minute,
		Signer:                    signer2,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{},
	})
	issuerRegistry.Register(service.TokenTypeAccessToken, accessIssuer)

	env := startJWKSTestServer(t, issuerRegistry)

	resp, err := env.HTTPClient.Get(env.HTTPBaseURL + "/v1/jwks.json")
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

	if len(jwks.Keys) < 2 {
		t.Fatalf("Expected at least 2 keys (one per issuer), got %d", len(jwks.Keys))
	}

	curves := make(map[string]bool)
	for _, key := range jwks.Keys {
		if crv, ok := key["crv"]; ok {
			curves[crv.(string)] = true
		}
	}

	if len(curves) < 2 {
		t.Errorf("Expected keys with different curves, got: %v", curves)
	}
}

// TestJWKSWithUnsignedIssuer tests that unsigned issuers don't contribute keys to JWKS.
func TestJWKSWithUnsignedIssuer(t *testing.T) {
	issuerRegistry := service.NewSimpleRegistry()
	unsignedIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeTransactionToken),
		ClaimMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, unsignedIssuer)

	env := startJWKSTestServer(t, issuerRegistry)

	resp, err := env.HTTPClient.Get(env.HTTPBaseURL + "/v1/jwks.json")
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

	if len(jwks.Keys) != 0 {
		t.Errorf("Expected 0 keys from unsigned issuer, got %d", len(jwks.Keys))
	}
}

// --- test helpers ---

func assertValidJWKS(t *testing.T, client *http.Client, url string) {
	t.Helper()

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Logf("Warning: Expected Content-Type 'application/json', got '%s'", contentType)
	}

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

	if len(jwks.Keys) == 0 {
		t.Fatal("Expected at least one key in JWKS, got none")
	}

	key := jwks.Keys[0]

	requiredFields := []string{"kty", "kid", "alg"}
	for _, field := range requiredFields {
		if _, ok := key[field]; !ok {
			t.Errorf("Key missing required field: %s", field)
		}
	}

	if key["kty"] == "EC" {
		ecFields := []string{"crv", "x", "y"}
		for _, field := range ecFields {
			if _, ok := key[field]; !ok {
				t.Errorf("EC key missing required field: %s", field)
			}
		}

		if key["crv"] != "P-256" {
			t.Errorf("Expected curve P-256, got %v", key["crv"])
		}

		if key["alg"] != "ES256" {
			t.Errorf("Expected algorithm ES256, got %v", key["alg"])
		}
	}

	if use, ok := key["use"]; ok {
		if use != "sig" {
			t.Errorf("Expected use 'sig', got %v", use)
		}
	}
}
