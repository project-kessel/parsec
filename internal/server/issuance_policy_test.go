package server

import (
	"context"
	"errors"
	"testing"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

var defaultTypes = []service.TokenType{service.TokenTypeTransactionToken}

func TestAlwaysIssuePolicy(t *testing.T) {
	policy := NewAlwaysIssuePolicy(defaultTypes)

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "user"}, trust.AnonymousResult(),
		&request.RequestAttributes{Path: "/api/test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if len(decision.TokenTypes) != 1 || decision.TokenTypes[0] != service.TokenTypeTransactionToken {
		t.Errorf("unexpected token types: %v", decision.TokenTypes)
	}
	if decision.Scope != "" {
		t.Errorf("expected empty scope, got %q", decision.Scope)
	}
}

func TestCelIssuancePolicy_BoolTrue(t *testing.T) {
	policy, err := NewCelIssuancePolicy("true", defaultTypes, "read")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "user"}, trust.AnonymousResult(),
		&request.RequestAttributes{Path: "/api/test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision for true")
	}
	if decision.Scope != "read" {
		t.Errorf("expected scope 'read', got %q", decision.Scope)
	}
}

func TestCelIssuancePolicy_BoolFalse(t *testing.T) {
	policy, err := NewCelIssuancePolicy("false", defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "user"}, trust.AnonymousResult(),
		&request.RequestAttributes{Path: "/api/test"})
	if err == nil {
		t.Fatal("expected error for false")
	}
	if !errors.Is(err, ErrIssuanceDenied) {
		t.Errorf("expected ErrIssuanceDenied, got: %v", err)
	}
	if decision != nil {
		t.Errorf("expected nil decision for deny, got: %+v", decision)
	}
}

func TestCelIssuancePolicy_Passthrough(t *testing.T) {
	policy, err := NewCelIssuancePolicy(`{"passthrough": true}`, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "user"}, trust.AnonymousResult(),
		&request.RequestAttributes{Path: "/health"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != nil {
		t.Errorf("expected nil decision for passthrough, got: %+v", decision)
	}
}

func TestCelIssuancePolicy_MapWithOverrides(t *testing.T) {
	script := `{"scope": "admin", "token_types": ["urn:ietf:params:oauth:token-type:access_token"]}`
	policy, err := NewCelIssuancePolicy(script, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "admin-user"}, trust.AnonymousResult(),
		&request.RequestAttributes{Path: "/api/admin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if decision.Scope != "admin" {
		t.Errorf("expected scope 'admin', got %q", decision.Scope)
	}
	if len(decision.TokenTypes) != 1 || decision.TokenTypes[0] != service.TokenTypeAccessToken {
		t.Errorf("unexpected token types: %v", decision.TokenTypes)
	}
}

func TestCelIssuancePolicy_UsesSubjectAndActor(t *testing.T) {
	script := `subject.subject == "admin" && actor.trust_domain == "gateway.example.com"`
	policy, err := NewCelIssuancePolicy(script, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	t.Run("matching subject and actor", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "admin"},
			&trust.Result{TrustDomain: "gateway.example.com"},
			&request.RequestAttributes{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision == nil {
			t.Fatal("expected issuance for matching subject+actor")
		}
	})

	t.Run("non-matching actor", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "admin"},
			&trust.Result{TrustDomain: "unknown.example.com"},
			&request.RequestAttributes{})
		if err == nil {
			t.Fatal("expected deny for non-matching actor")
		}
		if decision != nil {
			t.Errorf("expected nil decision: %+v", decision)
		}
	})
}

func TestCelIssuancePolicy_ConditionalPassthrough(t *testing.T) {
	script := `!request.path.startsWith("/health")`
	policy, err := NewCelIssuancePolicy(script, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	t.Run("health path denied means passthrough via PathPassthrough", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "user"}, trust.AnonymousResult(),
			&request.RequestAttributes{Path: "/health"})
		if err == nil {
			t.Fatal("expected deny for /health (use PathPassthroughPolicy for passthrough)")
		}
		if decision != nil {
			t.Errorf("expected nil decision: %+v", decision)
		}
	})

	t.Run("api path issues", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "user"}, trust.AnonymousResult(),
			&request.RequestAttributes{Path: "/api/data"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision == nil {
			t.Fatal("expected issuance for /api/data")
		}
	})
}

func TestCelIssuancePolicy_MapConditionalPassthrough(t *testing.T) {
	script := `request.path.startsWith("/health") ? dyn({"passthrough": true}) : dyn({"scope": "default"})`
	policy, err := NewCelIssuancePolicy(script, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	t.Run("health path passthroughs", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "user"}, trust.AnonymousResult(),
			&request.RequestAttributes{Path: "/health"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision != nil {
			t.Errorf("expected passthrough for /health, got: %+v", decision)
		}
	})

	t.Run("api path issues with scope", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "user"}, trust.AnonymousResult(),
			&request.RequestAttributes{Path: "/api/data"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision == nil {
			t.Fatal("expected issuance for /api/data")
		}
		if decision.Scope != "default" {
			t.Errorf("expected scope 'default', got %q", decision.Scope)
		}
	})
}

func TestCelIssuancePolicy_InvalidScript(t *testing.T) {
	_, err := NewCelIssuancePolicy("this is not valid CEL !!!", defaultTypes, "")
	if err == nil {
		t.Fatal("expected compile error for invalid CEL script")
	}
}

func TestCelIssuancePolicy_EmptyScript(t *testing.T) {
	_, err := NewCelIssuancePolicy("", defaultTypes, "")
	if err == nil {
		t.Fatal("expected error for empty CEL script")
	}
}

func TestPathPassthroughPolicy_Passthrough(t *testing.T) {
	policy, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `^/health$`, Outcome: "passthrough"},
		{Path: `^/api/[^/]+/v[0-9]+/openapi\.json$`, Outcome: "passthrough"},
	}, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		wantIssue   bool
		wantPassthr bool
	}{
		{"health path", "/health", false, true},
		{"openapi path", "/api/insights/v1/openapi.json", false, true},
		{"normal api path", "/api/data", true, false},
		{"empty path", "", true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := policy.Evaluate(context.Background(),
				&trust.Result{Subject: "user"}, trust.AnonymousResult(),
				&request.RequestAttributes{Path: tc.path})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantPassthr && decision != nil {
				t.Errorf("expected passthrough, got decision: %+v", decision)
			}
			if tc.wantIssue && decision == nil {
				t.Error("expected issue decision, got passthrough")
			}
		})
	}
}

func TestPathPassthroughPolicy_Deny(t *testing.T) {
	policy, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `^/admin/`, Outcome: "deny"},
	}, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	t.Run("denied path", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "user"}, trust.AnonymousResult(),
			&request.RequestAttributes{Path: "/admin/secret"})
		if err == nil {
			t.Fatal("expected deny error")
		}
		if !errors.Is(err, ErrIssuanceDenied) {
			t.Errorf("expected ErrIssuanceDenied, got: %v", err)
		}
		if decision != nil {
			t.Errorf("expected nil decision: %+v", decision)
		}
	})

	t.Run("allowed path", func(t *testing.T) {
		decision, err := policy.Evaluate(context.Background(),
			&trust.Result{Subject: "user"}, trust.AnonymousResult(),
			&request.RequestAttributes{Path: "/api/data"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision == nil {
			t.Fatal("expected issue decision")
		}
	})
}

func TestPathPassthroughPolicy_InvalidRegex(t *testing.T) {
	_, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `[invalid`, Outcome: "passthrough"},
	}, defaultTypes, "")
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestPathPassthroughPolicy_InvalidOutcome(t *testing.T) {
	_, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `^/health$`, Outcome: "unknown"},
	}, defaultTypes, "")
	if err == nil {
		t.Fatal("expected error for invalid outcome")
	}
}

func TestPathPassthroughPolicy_NilRequestAttrs(t *testing.T) {
	policy, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `^/health$`, Outcome: "passthrough"},
	}, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "user"}, trust.AnonymousResult(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected issue decision when reqAttrs is nil")
	}
}

func TestPathPassthroughPolicy_PathValidation(t *testing.T) {
	policy, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `^/health`, Outcome: "passthrough"},
		{Path: `^/admin/`, Outcome: "deny"},
	}, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	invalidPaths := []struct {
		name string
		path string
	}{
		{"percent-encoded traversal", "/health/%2e%2e/secret"},
		{"dot traversal", "/health/../secret"},
		{"double slash", "/health//extra"},
		{"percent-encoded slash", "/health%2fextra"},
		{"admin percent-encoded traversal", "/admin/%2e%2e/secret"},
		{"admin double slash", "/admin//secret"},
	}

	for _, tc := range invalidPaths {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := policy.Evaluate(context.Background(),
				&trust.Result{Subject: "user"}, trust.AnonymousResult(),
				&request.RequestAttributes{Path: tc.path})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision == nil {
				t.Errorf("path %q: expected default issuance (not passthrough/deny) for invalid path", tc.path)
			}
		})
	}
}

func TestPathPassthroughPolicy_QueryStringStripped(t *testing.T) {
	policy, err := NewPathPassthroughPolicy([]PathPatternRule{
		{Path: `^/health$`, Outcome: "passthrough"},
	}, defaultTypes, "")
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	decision, err := policy.Evaluate(context.Background(),
		&trust.Result{Subject: "user"}, trust.AnonymousResult(),
		&request.RequestAttributes{Path: "/health?check=true"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != nil {
		t.Error("expected passthrough for /health with query string stripped")
	}
}
