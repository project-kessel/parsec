package server

import (
	"context"
	"strings"
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

// --- allow_anonymous_without_issue_paths tests (ported from optional_path) ---

var testAllowAnonymousPaths = []string{
	`/r/insights/platform/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json`,
	`/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json`,
	`/api/pulp/api/v3/status/`,
	`/api/pulp-content/public-.*`,
	`/api/distributors/.*/v[0-9]/openapi.json`,
	`/api/content-sources/v[0-9]+(\.[0-9]+)?/repository_gpg_key/[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}`,
	`/api/distributors/docs`,
}

func newTestPolicyWithPaths(t *testing.T, tokenTypes []TokenTypeSpec) *StaticAuthenticatedPolicy {
	t.Helper()
	compiled, err := CompilePathPatterns(testAllowAnonymousPaths)
	if err != nil {
		t.Fatalf("CompilePathPatterns: %v", err)
	}
	return NewStaticAuthenticatedPolicy(tokenTypes, WithAllowAnonymousWithoutIssuePaths(compiled))
}

func TestNormalizeRequestPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{"/api/foo", "/api/foo"},
		{"/api/foo?bar=baz", "/api/foo"},
		{"/api/foo?", "/api/foo"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := normalizeRequestPath(tt.in); got != tt.want {
			t.Errorf("normalizeRequestPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStaticAuthenticatedPolicy_AllowAnonymousPaths(t *testing.T) {
	t.Parallel()

	customTypes := []TokenTypeSpec{
		{Type: service.TokenTypeRHIdentity, HeaderName: "x-rh-identity"},
	}
	policy := newTestPolicyWithPaths(t, customTypes)

	tests := []struct {
		name       string
		subject    Principal
		path       string
		wantAction AuthzCheckAction
		wantReason string
	}{
		{
			name:       "anonymous optional path",
			subject:    anonymousPrincipal(),
			path:       "/api/foo/v1/openapi.json",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "anonymous optional path with query",
			subject:    anonymousPrincipal(),
			path:       "/api/foo/v1/openapi.json?format=yaml",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "authenticated optional path",
			subject:    Principal{Result: &trust.Result{Subject: "user@example.com"}},
			path:       "/api/foo/v1/openapi.json",
			wantAction: AuthzCheckIssue,
		},
		{
			name:       "anonymous protected path",
			subject:    anonymousPrincipal(),
			path:       "/api/private/resource",
			wantAction: AuthzCheckDeny,
			wantReason: anonymousSubjectDenyReason,
		},
		{
			name:       "insights openapi",
			subject:    anonymousPrincipal(),
			path:       "/r/insights/platform/cost-management/v1/openapi.json",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "pulp status",
			subject:    anonymousPrincipal(),
			path:       "/api/pulp/api/v3/status/",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "pulp content public",
			subject:    anonymousPrincipal(),
			path:       "/api/pulp-content/public-foo/bar",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "distributors openapi",
			subject:    anonymousPrincipal(),
			path:       "/api/distributors/acme/v1/openapi.json",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "content sources gpg key",
			subject:    anonymousPrincipal(),
			path:       "/api/content-sources/v1/repository_gpg_key/12345678-1234-1234-1234-123456789012",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "distributors docs",
			subject:    anonymousPrincipal(),
			path:       "/api/distributors/docs",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "unanchored pattern does not substring match",
			subject:    anonymousPrincipal(),
			path:       "/private/api/distributors/docs/secret",
			wantAction: AuthzCheckDeny,
			wantReason: anonymousSubjectDenyReason,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
				Subject: tt.subject,
				Request: &request.RequestAttributes{Path: tt.path},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Action != tt.wantAction {
				t.Errorf("expected action %s, got %s", tt.wantAction, decision.Action)
			}
			if tt.wantReason != "" && decision.Reason != tt.wantReason {
				t.Errorf("expected reason %q, got %q", tt.wantReason, decision.Reason)
			}
			if tt.wantAction == AuthzCheckIssue {
				if len(decision.TokenTypes) != 1 || decision.TokenTypes[0].HeaderName != "x-rh-identity" {
					t.Errorf("unexpected token types: %+v", decision.TokenTypes)
				}
			}
		})
	}
}

func TestStaticAuthenticatedPolicy_ImplicitAnchoring(t *testing.T) {
	t.Parallel()

	compiled, err := CompilePathPatterns([]string{`/public/health`})
	if err != nil {
		t.Fatalf("CompilePathPatterns: %v", err)
	}
	policy := NewStaticAuthenticatedPolicy(nil, WithAllowAnonymousWithoutIssuePaths(compiled))

	tests := []struct {
		name       string
		path       string
		wantAction AuthzCheckAction
	}{
		{"exact match", "/public/health", AuthzCheckAllowWithoutIssue},
		{"prefix should not match", "/public/health/extra", AuthzCheckDeny},
		{"suffix should not match", "/x/public/health", AuthzCheckDeny},
		{"substring should not match", "/prefix/public/health/suffix", AuthzCheckDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
				Subject: anonymousPrincipal(),
				Request: &request.RequestAttributes{Path: tt.path},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Action != tt.wantAction {
				t.Errorf("path %q: expected action %s, got %s", tt.path, tt.wantAction, decision.Action)
			}
		})
	}
}

func TestCompilePathPatterns_InvalidPattern(t *testing.T) {
	t.Parallel()

	_, err := CompilePathPatterns([]string{`[invalid`})
	if err == nil {
		t.Fatal("expected error for invalid pattern")
	}
	if !strings.Contains(err.Error(), "allow_anonymous_without_issue_paths[0]") {
		t.Fatalf("expected indexed pattern error, got: %v", err)
	}
}

func TestCompilePathPatterns_InvalidPatternAfterValid(t *testing.T) {
	t.Parallel()

	_, err := CompilePathPatterns([]string{
		`/public`,
		`[invalid`,
	})
	if err == nil {
		t.Fatal("expected error for invalid pattern")
	}
	if !strings.Contains(err.Error(), "allow_anonymous_without_issue_paths[1]") {
		t.Fatalf("expected indexed pattern error, got: %v", err)
	}
}

func TestStaticAuthenticatedPolicy_HostAndPathRules(t *testing.T) {
	paths, err := CompilePathPatterns([]string{`/api/distributors/.*/openapi.json`})
	if err != nil {
		t.Fatalf("compile paths: %v", err)
	}
	hosts, err := CompilePathPatterns([]string{`api\.example\.com`})
	if err != nil {
		t.Fatalf("compile hosts: %v", err)
	}
	policy := NewStaticAuthenticatedPolicy(nil, WithAllowAnonymousWithoutIssueRules([]AnonymousRequestRule{{Hosts: hosts, Paths: paths}}))
	cases := []struct {
		name, host, path string
		want             AuthzCheckAction
	}{
		{"match", "api.example.com", "/api/distributors/acme/openapi.json", AuthzCheckAllowWithoutIssue},
		{"wrong host", "evil.example.com", "/api/distributors/acme/openapi.json", AuthzCheckDeny},
		{"wrong path", "api.example.com", "/api/distributors/acme/private", AuthzCheckDeny},
		{"query retained as path normalization", "api.example.com", "/api/distributors/acme/openapi.json?x=1", AuthzCheckAllowWithoutIssue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{Subject: anonymousPrincipal(), Request: &request.RequestAttributes{Path: tc.path, Additional: map[string]any{"host": tc.host}}})
			if err != nil || d.Action != tc.want {
				t.Fatalf("got decision=%+v err=%v, want %s", d, err, tc.want)
			}
		})
	}
}
