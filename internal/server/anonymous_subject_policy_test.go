package server

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestDenyAllPolicy(t *testing.T) {
	policy := DenyAllPolicy{}
	allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
		Path: "/anything",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("DenyAllPolicy should never allow")
	}
}

func TestCelAnonymousSubjectPolicy_EmptyScript(t *testing.T) {
	_, err := NewCelAnonymousSubjectPolicy("")
	if err == nil {
		t.Fatal("expected error for empty script")
	}
}

func TestCelAnonymousSubjectPolicy_CompileError(t *testing.T) {
	_, err := NewCelAnonymousSubjectPolicy("this is not valid CEL !!!")
	if err == nil {
		t.Fatal("expected compile error for invalid CEL")
	}
}

func TestCelAnonymousSubjectPolicy_PathMatching(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(`request.path.startsWith("/public/")`)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		allowed bool
	}{
		{"matching path", "/public/docs", true},
		{"non-matching path", "/api/resource", false},
		{"exact prefix boundary", "/public/", true},
		{"similar but not prefix", "/publicx/docs", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
				Path: tc.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.allowed {
				t.Errorf("path %q: expected allowed=%v, got %v", tc.path, tc.allowed, allowed)
			}
		})
	}
}

func TestCelAnonymousSubjectPolicy_MethodMatching(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(`request.method == "GET" && request.path == "/health"`)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	tests := []struct {
		name    string
		method  string
		path    string
		allowed bool
	}{
		{"GET /health", "GET", "/health", true},
		{"POST /health", "POST", "/health", false},
		{"GET /other", "GET", "/other", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
				Method: tc.method,
				Path:   tc.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.allowed {
				t.Errorf("expected allowed=%v, got %v", tc.allowed, allowed)
			}
		})
	}
}

func TestCelAnonymousSubjectPolicy_ActorFields(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(
		`has(actor.trust_domain) && actor.trust_domain == "mesh.internal" && request.path.startsWith("/internal/")`,
	)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	tests := []struct {
		name    string
		actor   *trust.Result
		path    string
		allowed bool
	}{
		{
			name: "matching actor and path",
			actor: &trust.Result{
				Subject:     "actor-1",
				TrustDomain: "mesh.internal",
			},
			path:    "/internal/api",
			allowed: true,
		},
		{
			name: "wrong trust domain",
			actor: &trust.Result{
				Subject:     "actor-1",
				TrustDomain: "external",
			},
			path:    "/internal/api",
			allowed: false,
		},
		{
			name: "right domain wrong path",
			actor: &trust.Result{
				Subject:     "actor-1",
				TrustDomain: "mesh.internal",
			},
			path:    "/public/docs",
			allowed: false,
		},
		{
			name:    "anonymous actor",
			actor:   trust.AnonymousResult(),
			path:    "/internal/api",
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := policy.IsAllowed(context.Background(), tc.actor, &request.RequestAttributes{
				Path: tc.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.allowed {
				t.Errorf("expected allowed=%v, got %v", tc.allowed, allowed)
			}
		})
	}
}

func TestCelAnonymousSubjectPolicy_PathValidation(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(`true`)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	invalidPaths := []struct {
		name string
		path string
	}{
		{"percent encoding", "/api/%2e%2e/secret"},
		{"double slash", "/api//docs"},
		{"dot traversal", "/api/docs/../secret"},
	}

	for _, tc := range invalidPaths {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
				Path: tc.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed {
				t.Errorf("path %q: expected denial for invalid path, got allowed", tc.path)
			}
		})
	}
}

func TestCelAnonymousSubjectPolicy_NilRequestAttributes(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(`true`)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected denial for nil request attributes")
	}
}

func TestCelAnonymousSubjectPolicy_QueryStringStripped(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(`request.path == "/openapi.json"`)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
		Path: "/openapi.json?version=2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected query string to be stripped before CEL evaluation")
	}
}

func TestCelAnonymousSubjectPolicy_RegexMatching(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(
		`request.path.matches("^/api/[^/]+/v[0-9]+/openapi\\.json$")`,
	)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		allowed bool
	}{
		{"matching versioned path", "/api/insights/v1/openapi.json", true},
		{"different service", "/api/other/v2/openapi.json", true},
		{"no match", "/api/insights/v1/other", false},
		{"extra segments", "/api/insights/v1/openapi.json/extra", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
				Path: tc.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.allowed {
				t.Errorf("path %q: expected allowed=%v, got %v", tc.path, tc.allowed, allowed)
			}
		})
	}
}

func TestCelAnonymousSubjectPolicy_ContextExtensions(t *testing.T) {
	policy, err := NewCelAnonymousSubjectPolicy(
		`has(request.additional.context_extensions) && request.additional.context_extensions.optional_auth == "true"`,
	)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	t.Run("with matching extension", func(t *testing.T) {
		allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
			Path: "/any",
			Additional: map[string]any{
				"context_extensions": map[string]any{
					"optional_auth": "true",
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed when context_extensions.optional_auth == true")
		}
	})

	t.Run("without extension", func(t *testing.T) {
		allowed, err := policy.IsAllowed(context.Background(), trust.AnonymousResult(), &request.RequestAttributes{
			Path:       "/any",
			Additional: map[string]any{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Error("expected denial without context_extensions")
		}
	})
}

func TestCelAnonymousSubjectPolicy_Script(t *testing.T) {
	script := `request.path == "/test"`
	policy, err := NewCelAnonymousSubjectPolicy(script)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	if policy.Script() != script {
		t.Errorf("Script() = %q, want %q", policy.Script(), script)
	}
}
