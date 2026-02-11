package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

func TestJWKSServerCaching(t *testing.T) {
	ctx := context.Background()

	t.Run("populates cache on start", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		issuer := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "test-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer)

		clk := clock.NewFixtureClock(time.Now())
		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry:  registry,
			RefreshInterval: 1 * time.Minute,
			Clock:           clk,
			Logger:          slog.Default(),
		})

		// Start should populate the cache
		err := jwksServer.Start(ctx)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		defer jwksServer.Stop()

		// Cache should be populated
		resp, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}

		if len(resp.Keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(resp.Keys))
		}

		if resp.Keys[0].Kid != "test-key" {
			t.Errorf("expected key ID 'test-key', got %q", resp.Keys[0].Kid)
		}
	})

	t.Run("populates cache on first request if not started", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		issuer := &testIssuerWithKeys{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "test-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		// First request should populate cache
		resp, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}

		if len(resp.Keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(resp.Keys))
		}
	})

	t.Run("serves cached response on subsequent requests", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		callCount := 0
		issuer := &testIssuerWithCallCount{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "test-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
			callCount: &callCount,
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer)

		clk := clock.NewFixtureClock(time.Now())
		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry:  registry,
			RefreshInterval: 1 * time.Hour, // Long interval so it doesn't refresh during test
			Clock:           clk,
			Logger:          slog.Default(),
		})

		// Start populates cache
		err := jwksServer.Start(ctx)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		defer jwksServer.Stop()

		firstCallCount := callCount

		// Subsequent requests should use cache
		for i := 0; i < 10; i++ {
			_, err := jwksServer.GetJWKS(ctx, nil)
			if err != nil {
				t.Fatalf("GetJWKS failed on iteration %d: %v", i, err)
			}
		}

		// Call count should not increase (cache is being used)
		if callCount != firstCallCount {
			t.Errorf("expected call count to remain %d, got %d (cache not being used)", firstCallCount, callCount)
		}
	})

	t.Run("refreshes cache periodically", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		callCount := 0
		issuer := &testIssuerWithCallCount{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "test-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
			callCount: &callCount,
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer)

		clk := clock.NewFixtureClock(time.Now())
		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry:  registry,
			RefreshInterval: 1 * time.Minute,
			Clock:           clk,
			Logger:          slog.Default(),
		})

		// Start populates cache and begins background refresh
		err := jwksServer.Start(ctx)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		defer jwksServer.Stop()

		initialCallCount := callCount

		// Advance time by 1 minute - should trigger refresh synchronously
		clk.Advance(1 * time.Minute)

		// Call count should have increased
		if callCount <= initialCallCount {
			t.Errorf("expected call count to increase after advancing time, got %d (initial: %d)", callCount, initialCallCount)
		}

		// Advance time by another minute
		secondCallCount := callCount
		clk.Advance(1 * time.Minute)

		// Call count should have increased again
		if callCount <= secondCallCount {
			t.Errorf("expected call count to increase again, got %d (previous: %d)", callCount, secondCallCount)
		}
	})

	t.Run("serves stale data if refresh fails", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		issuer := &testIssuerWithMutableBehavior{
			publicKeys: []service.PublicKey{
				{
					KeyID:     "test-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
			shouldFail: false,
		}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer)

		clk := clock.NewFixtureClock(time.Now())
		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry:  registry,
			RefreshInterval: 1 * time.Minute,
			Clock:           clk,
			Logger:          slog.Default(),
		})

		// Start populates cache with good data
		err := jwksServer.Start(ctx)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		defer jwksServer.Stop()

		// Get initial response
		resp1, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS failed: %v", err)
		}
		if len(resp1.Keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(resp1.Keys))
		}

		// Make issuer start failing
		issuer.shouldFail = true

		// Advance time to trigger refresh synchronously
		clk.Advance(1 * time.Minute)

		// Should still serve stale data
		resp2, err := jwksServer.GetJWKS(ctx, nil)
		if err != nil {
			t.Fatalf("GetJWKS should succeed with stale data: %v", err)
		}
		if len(resp2.Keys) != 1 {
			t.Fatalf("expected 1 key (stale), got %d", len(resp2.Keys))
		}
		if resp2.Keys[0].Kid != "test-key" {
			t.Errorf("expected stale key 'test-key', got %q", resp2.Keys[0].Kid)
		}
	})

	t.Run("returns error if initial population fails", func(t *testing.T) {
		badIssuer := &testIssuerWithError{}

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, badIssuer)

		jwksServer := NewJWKSServer(JWKSServerConfig{
			IssuerRegistry: registry,
			Logger:         slog.Default(),
		})

		// Start will fail to populate cache but shouldn't error
		_ = jwksServer.Start(ctx)
		// Start doesn't fail, but logs warning

		// GetJWKS should return error since cache is empty
		_, err := jwksServer.GetJWKS(ctx, nil)
		if err == nil {
			t.Error("expected error when cache is empty and issuer fails, got nil")
		}
	})
}

// testIssuerWithCallCount tracks how many times PublicKeys is called
type testIssuerWithCallCount struct {
	publicKeys []service.PublicKey
	callCount  *int
}

func (i *testIssuerWithCallCount) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	return nil, nil
}

func (i *testIssuerWithCallCount) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	*i.callCount++
	return i.publicKeys, nil
}

// testIssuerWithMutableBehavior can change from success to failure
type testIssuerWithMutableBehavior struct {
	publicKeys []service.PublicKey
	shouldFail bool
}

func (i *testIssuerWithMutableBehavior) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	return nil, nil
}

func (i *testIssuerWithMutableBehavior) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	if i.shouldFail {
		return nil, context.Canceled
	}
	return i.publicKeys, nil
}
