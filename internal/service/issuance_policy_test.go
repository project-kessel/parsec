package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/trust"
)

func testResult(c claims.Claims) *trust.Result {
	return &trust.Result{
		Subject:     "user@example.com",
		Issuer:      "https://sso.example.com",
		TrustDomain: "example.com",
		Claims:      c,
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
	}
}

func TestClaimAssertionPolicy_requiredClaims(t *testing.T) {
	ctx := context.Background()

	t.Run("accepts when required claim present", func(t *testing.T) {
		p := NewClaimAssertionPolicy([]string{"idp"}, nil)
		result := testResult(claims.Claims{"idp": "google"})

		if err := p.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("denies when required claim missing", func(t *testing.T) {
		p := NewClaimAssertionPolicy([]string{"idp"}, nil)
		result := testResult(claims.Claims{"sub": "user"})

		err := p.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}
	})

	t.Run("accepts when all required present", func(t *testing.T) {
		p := NewClaimAssertionPolicy([]string{"idp", "org_id"}, nil)
		result := testResult(claims.Claims{"idp": "google", "org_id": "123"})

		if err := p.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("denies when any required missing", func(t *testing.T) {
		p := NewClaimAssertionPolicy([]string{"idp", "org_id"}, nil)
		result := testResult(claims.Claims{"idp": "google"})

		err := p.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}
	})

	t.Run("skips enforcement when empty", func(t *testing.T) {
		p := NewClaimAssertionPolicy(nil, nil)
		result := testResult(claims.Claims{"sub": "user"})

		if err := p.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("nil subject is allowed", func(t *testing.T) {
		p := NewClaimAssertionPolicy([]string{"idp"}, nil)

		if err := p.Evaluate(ctx, nil); err != nil {
			t.Fatalf("expected nil for nil subject, got %v", err)
		}
	})
}

func TestClaimAssertionPolicy_rejectedClaims(t *testing.T) {
	ctx := context.Background()

	t.Run("denies when claim matches rejected value", func(t *testing.T) {
		p := NewClaimAssertionPolicy(nil, map[string]any{"impersonated": true})
		result := testResult(claims.Claims{"sub": "user", "impersonated": true})

		err := p.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}
	})

	t.Run("accepts when claim has different value", func(t *testing.T) {
		p := NewClaimAssertionPolicy(nil, map[string]any{"impersonated": true})
		result := testResult(claims.Claims{"sub": "user", "impersonated": false})

		if err := p.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("accepts when rejected claim absent", func(t *testing.T) {
		p := NewClaimAssertionPolicy(nil, map[string]any{"impersonated": true})
		result := testResult(claims.Claims{"sub": "user"})

		if err := p.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("rejects string value match", func(t *testing.T) {
		p := NewClaimAssertionPolicy(nil, map[string]any{"auth_type": "service_account"})
		result := testResult(claims.Claims{"auth_type": "service_account"})

		err := p.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}
	})

	t.Run("matches float64 against int via numeric normalization", func(t *testing.T) {
		// JSON decodes numbers as float64; YAML config may load as int
		p := NewClaimAssertionPolicy(nil, map[string]any{"error_code": 403})
		result := testResult(claims.Claims{"error_code": float64(403)})

		err := p.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied for float64/int match, got %v", err)
		}
	})

	t.Run("skips enforcement when empty", func(t *testing.T) {
		p := NewClaimAssertionPolicy(nil, nil)
		result := testResult(claims.Claims{"impersonated": true})

		if err := p.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})
}

func TestClaimAssertionPolicy_combined(t *testing.T) {
	ctx := context.Background()

	policy := NewClaimAssertionPolicy(
		[]string{"idp"},
		map[string]any{"impersonated": true},
	)

	t.Run("accepts when all assertions pass", func(t *testing.T) {
		result := testResult(claims.Claims{"idp": "google", "sub": "user"})
		if err := policy.Evaluate(ctx, result); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("denies on rejected claim even when required present", func(t *testing.T) {
		result := testResult(claims.Claims{"idp": "google", "impersonated": true})
		err := policy.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}
	})

	t.Run("denies on missing required even when rejected absent", func(t *testing.T) {
		result := testResult(claims.Claims{"sub": "user"})
		err := policy.Evaluate(ctx, result)
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}
	})
}

func TestTokenService_IssuancePolicy(t *testing.T) {
	ctx := context.Background()

	stubToken := &Token{
		Value:     "token-value",
		Type:      string(TokenTypeTransactionToken),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	registry := NewSimpleRegistry()
	registry.Register(TokenTypeTransactionToken, &testIssuerStub{token: stubToken})

	makeRequest := func() *IssueRequest {
		return &IssueRequest{
			Subject:    testResult(claims.Claims{"idp": "google", "sub": "user"}),
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}
	}

	t.Run("policy allows proceeds normally", func(t *testing.T) {
		fakeObs := NewFakeObserver(t)
		policy := NewClaimAssertionPolicy([]string{"idp"}, nil)
		svc := NewTokenService("example.com", nil, registry, fakeObs, WithIssuancePolicy(policy))

		tokens, err := svc.IssueTokens(ctx, makeRequest())
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(tokens) != 1 {
			t.Fatalf("expected 1 token, got %d", len(tokens))
		}
	})

	t.Run("policy denies returns error and calls probe", func(t *testing.T) {
		fakeObs := NewFakeObserver(t)
		policy := NewClaimAssertionPolicy([]string{"missing_claim"}, nil)
		svc := NewTokenService("example.com", nil, registry, fakeObs, WithIssuancePolicy(policy))

		_, err := svc.IssueTokens(ctx, makeRequest())
		if err == nil {
			t.Fatal("expected error from policy denial")
		}
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Fatalf("expected ErrIssuanceDenied, got %v", err)
		}

		p := fakeObs.AssertSingleProbe("TokenIssuanceStarted", nil)
		p.AssertProbeSequence(
			ProbeCall("IssuancePolicyDenied", AnyError()),
			"End",
		)
	})

	t.Run("no policy configured proceeds normally", func(t *testing.T) {
		fakeObs := NewFakeObserver(t)
		svc := NewTokenService("example.com", nil, registry, fakeObs)

		tokens, err := svc.IssueTokens(ctx, makeRequest())
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(tokens) != 1 {
			t.Fatalf("expected 1 token, got %d", len(tokens))
		}
	})
}
