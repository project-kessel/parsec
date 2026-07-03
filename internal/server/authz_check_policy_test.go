package server

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestStaticAuthenticatedPolicy_DenyAnonymousSubject(t *testing.T) {
	policy := NewStaticAuthenticatedPolicy(nil)

	decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
		Subject: Principal{Anonymous: true},
		Actor:   Principal{Anonymous: true},
		Request: &request.RequestAttributes{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != AuthzCheckDeny {
		t.Errorf("expected deny, got %s", decision.Action)
	}
	if decision.Reason == "" {
		t.Error("expected a reason for denial")
	}
}

func TestStaticAuthenticatedPolicy_IssueForAuthenticatedSubject(t *testing.T) {
	policy := NewStaticAuthenticatedPolicy(nil)

	decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
		Subject: Principal{
			Result: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example.com",
			},
		},
		Actor:   Principal{Anonymous: true},
		Request: &request.RequestAttributes{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != AuthzCheckIssue {
		t.Errorf("expected issue, got %s", decision.Action)
	}
	if len(decision.TokenTypes) != 1 {
		t.Fatalf("expected 1 token type, got %d", len(decision.TokenTypes))
	}
	if decision.TokenTypes[0].Type != service.TokenTypeTransactionToken {
		t.Errorf("expected transaction token type, got %s", decision.TokenTypes[0].Type)
	}
	if decision.TokenTypes[0].HeaderName != "Transaction-Token" {
		t.Errorf("expected Transaction-Token header, got %s", decision.TokenTypes[0].HeaderName)
	}
}

func TestStaticAuthenticatedPolicy_CustomTokenTypes(t *testing.T) {
	customTypes := []TokenTypeSpec{
		{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
		{Type: service.TokenTypeAccessToken, HeaderName: "Authorization"},
	}
	policy := NewStaticAuthenticatedPolicy(customTypes)

	decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
		Subject: Principal{
			Result: &trust.Result{Subject: "user@example.com"},
		},
		Request: &request.RequestAttributes{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != AuthzCheckIssue {
		t.Errorf("expected issue, got %s", decision.Action)
	}
	if len(decision.TokenTypes) != 2 {
		t.Fatalf("expected 2 token types, got %d", len(decision.TokenTypes))
	}
	if decision.TokenTypes[0].Type != service.TokenTypeTransactionToken {
		t.Errorf("expected transaction token type first, got %s", decision.TokenTypes[0].Type)
	}
	if decision.TokenTypes[1].Type != service.TokenTypeAccessToken {
		t.Errorf("expected access token type second, got %s", decision.TokenTypes[1].Type)
	}
}

func TestStaticAuthenticatedPolicy_DenyAnonymousEvenWithAuthenticatedActor(t *testing.T) {
	policy := NewStaticAuthenticatedPolicy(nil)

	decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
		Subject: Principal{Anonymous: true},
		Actor: Principal{
			Result: &trust.Result{
				Subject:     "gateway.example.com",
				TrustDomain: "infra.example.com",
			},
			CredentialType: trust.CredentialTypeMTLS,
		},
		Request: &request.RequestAttributes{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != AuthzCheckDeny {
		t.Errorf("expected deny even with authenticated actor, got %s", decision.Action)
	}
}

func TestStaticAuthenticatedPolicy_EmptyScopeByDefault(t *testing.T) {
	policy := NewStaticAuthenticatedPolicy(nil)

	decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
		Subject: Principal{
			Result: &trust.Result{Subject: "user@example.com"},
		},
		Request: &request.RequestAttributes{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Scope != "" {
		t.Errorf("expected empty scope, got %q", decision.Scope)
	}
}
