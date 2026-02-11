package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"testing"

	"github.com/project-kessel/parsec/internal/service"
)

func TestJWKSServer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns empty JWKS when no issuers configured", func(t *testing.T) {
		emptyRegistry := service.NewSimpleRegistry()
		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: emptyRegistry,
			Logger:         slog.Default(),
		})

		resp, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}

		if len(resp.Keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(resp.Keys))
		}
	})

	t.Run("returns public keys from configured issuers", func(t *testing.T) {
		// Create a test issuer with a public key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		testIssuer := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "test-key-1",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, testIssuer)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		resp, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}

		if len(resp.Keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(resp.Keys))
		}

		key := resp.Keys[0]
		if key.Kid != "test-key-1" {
			t.Errorf("expected kid 'test-key-1', got %q", key.Kid)
		}
		if key.Kty != "EC" {
			t.Errorf("expected kty 'EC', got %q", key.Kty)
		}
		if key.Crv != "P-256" {
			t.Errorf("expected crv 'P-256', got %q", key.Crv)
		}
		if key.Alg != "ES256" {
			t.Errorf("expected alg 'ES256', got %q", key.Alg)
		}
		if key.Use != "sig" {
			t.Errorf("expected use 'sig', got %q", key.Use)
		}
		if key.X == "" {
			t.Error("expected x coordinate to be set")
		}
		if key.Y == "" {
			t.Error("expected y coordinate to be set")
		}
	})

	t.Run("returns keys from multiple issuers", func(t *testing.T) {
		privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privateKey2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

		issuer1 := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "issuer1-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey1.PublicKey,
				},
			},
		}

		issuer2 := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "issuer2-key",
					Algorithm: "ES384",
					Use:       "sig",
					Key:       &privateKey2.PublicKey,
				},
			},
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer1)
		registry.Register(service.TokenTypeAccessToken, issuer2)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		resp, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}

		if len(resp.Keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(resp.Keys))
		}

		// Verify both keys are present
		keyIDs := make(map[string]bool)
		for _, key := range resp.Keys {
			keyIDs[key.Kid] = true
		}

		if !keyIDs["issuer1-key"] {
			t.Error("expected issuer1-key to be present")
		}
		if !keyIDs["issuer2-key"] {
			t.Error("expected issuer2-key to be present")
		}
	})

	t.Run("handles issuers with no public keys", func(t *testing.T) {
		// Issuer with no keys (like unsigned issuer)
		issuerWithoutKeys := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{},
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuerWithoutKeys)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		resp, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}

		if len(resp.Keys) != 0 {
			t.Errorf("expected 0 keys from unsigned issuer, got %d", len(resp.Keys))
		}
	})

	t.Run("returns partial keys when some issuers fail", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		goodIssuer := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "good-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
		}

		badIssuer := &testIssuerWithError{}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, goodIssuer)
		registry.Register(service.TokenTypeAccessToken, badIssuer)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		resp, err := jwksServer.GetJWKS(ctx, nil)
		// Should succeed with partial keys
		if err != nil {
			t.Fatalf("GetJWKS should succeed with partial keys, got error: %v", err)
		}

		if len(resp.Keys) != 1 {
			t.Fatalf("expected 1 key from good issuer, got %d", len(resp.Keys))
		}

		if resp.Keys[0].Kid != "good-key" {
			t.Errorf("expected key ID 'good-key', got %q", resp.Keys[0].Kid)
		}
	})

	t.Run("returns error when all issuers fail", func(t *testing.T) {
		badIssuer := &testIssuerWithError{}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, badIssuer)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		resp, err := jwksServer.GetJWKS(ctx, nil)
		// Should return error when no keys available
		if err == nil {
			t.Error("expected error when all issuers fail, got nil")
		}

		// Response should be nil on error
		if resp != nil {
			t.Errorf("expected nil response on error, got %+v", resp)
		}
	})
}

// testIssuerWithKeys is a test issuer that returns a predefined set of public keys
type testIssuerWithKeys struct {
	publicKeys []service.PublicKey
}

func (i *testIssuerWithKeys) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	return nil, nil
}

func (i *testIssuerWithKeys) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return i.publicKeys, nil
}

// testIssuerWithError is a test issuer that returns an error
type testIssuerWithError struct{}

func (i *testIssuerWithError) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	return nil, nil
}

func (i *testIssuerWithError) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return nil, context.Canceled
}
