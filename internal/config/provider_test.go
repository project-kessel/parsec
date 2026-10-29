package config

import (
	"context"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestProvider_CredentialSources(t *testing.T) {
	t.Parallel()

	valid := []CredentialSourceConfig{
		{Name: "authorization-bearer", Type: "authorization_bearer_opaque"},
		{Name: "cs-jwt-cookie", Type: "cookie_bearer_opaque", CookieName: "cs_jwt"},
	}

	tests := []struct {
		name    string
		sources []CredentialSourceConfig
		wantErr string
	}{
		{
			name:    "nil defaults to bearer",
			sources: nil,
		},
		{
			name:    "valid sources",
			sources: valid,
		},
		{
			name:    "missing source name",
			sources: []CredentialSourceConfig{{Type: "authorization_bearer_opaque"}},
			wantErr: "credential_sources[0]: name is required",
		},
		{
			name: "duplicate source name",
			sources: []CredentialSourceConfig{
				{Name: "bearer-a", Type: "authorization_bearer_opaque"},
				{Name: "bearer-a", Type: "authorization_bearer_opaque"},
			},
			wantErr: "duplicate credential source name: bearer-a",
		},
		{
			name:    "missing type",
			sources: []CredentialSourceConfig{{Name: "x"}},
			wantErr: "credential_sources[0]: type is required",
		},
		{
			name:    "unknown type",
			sources: []CredentialSourceConfig{{Name: "x", Type: "not_a_real_type"}},
			wantErr: `unknown type "not_a_real_type"`,
		},
		{
			name:    "cookie without cookie_name",
			sources: []CredentialSourceConfig{{Name: "cookie", Type: "cookie_bearer_opaque"}},
			wantErr: `cookie_name is required`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := NewProvider(&Config{CredentialSources: tt.sources})

			got, err := p.CredentialSources()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Every valid case should extract from Authorization header
			ext, err := got.Extract(context.Background(), server.CredentialContext{
				Headers: map[string]string{"authorization": "Bearer test"},
			})
			if err != nil {
				t.Fatalf("extract failed: %v", err)
			}
			bearer, ok := ext.Credential.(*trust.BearerCredential)
			if !ok {
				t.Fatalf("expected BearerCredential, got %T", ext.Credential)
			}
			if bearer.Token != "test" {
				t.Fatalf("unexpected token: %q", bearer.Token)
			}
		})
	}
}

func TestProvider_AuthzCheckPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *Config
		wantErr    string
		wantTypes  []server.TokenTypeSpec
		wantAction server.AuthzCheckAction
	}{
		{
			name:   "nil authz_server defaults to static_authenticated with default token types",
			config: &Config{AuthzServer: nil},
			wantTypes: []server.TokenTypeSpec{
				{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
			},
			wantAction: server.AuthzCheckIssue,
		},
		{
			name:   "empty policy type defaults to static_authenticated",
			config: &Config{AuthzServer: &AuthzServerConfig{}},
			wantTypes: []server.TokenTypeSpec{
				{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
			},
			wantAction: server.AuthzCheckIssue,
		},
		{
			name: "explicit static_authenticated with custom token types",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					Type: "static_authenticated",
					TokenTypes: []TokenTypeConfig{
						{Type: string(service.TokenTypeTransactionToken), HeaderName: "Transaction-Token"},
						{Type: string(service.TokenTypeAccessToken), HeaderName: "Authorization"},
					},
				},
			}},
			wantTypes: []server.TokenTypeSpec{
				{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
				{Type: service.TokenTypeAccessToken, HeaderName: "Authorization"},
			},
			wantAction: server.AuthzCheckIssue,
		},
		{
			name: "implicit type with policy token_types defaults to static_authenticated",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					TokenTypes: []TokenTypeConfig{
						{Type: string(service.TokenTypeTransactionToken), HeaderName: "Transaction-Token"},
					},
				},
			}},
			wantTypes: []server.TokenTypeSpec{
				{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
			},
			wantAction: server.AuthzCheckIssue,
		},
		{
			name: "implicit type with allow_anonymous_without_issue_paths defaults to static_authenticated",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					AllowAnonymousWithoutIssuePaths: []string{`^/public$`},
				},
			}},
			wantTypes: []server.TokenTypeSpec{
				{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
			},
			wantAction: server.AuthzCheckIssue,
		},
		{
			name: "unknown policy type returns error",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{Type: "opa"},
			}},
			wantErr: `unknown authz check policy type: "opa"`,
		},
		{
			name: "static_authenticated with allow_anonymous_without_issue_paths",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					Type: "static_authenticated",
					AllowAnonymousWithoutIssuePaths: []string{
						`^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`,
					},
					TokenTypes: []TokenTypeConfig{
						{Type: string(service.TokenTypeRHIdentity), HeaderName: "x-rh-identity"},
					},
				},
			}},
			wantTypes: []server.TokenTypeSpec{
				{Type: service.TokenTypeRHIdentity, HeaderName: "x-rh-identity"},
			},
			wantAction: server.AuthzCheckIssue,
		},
		{
			name: "optional_path type is now unknown",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{Type: "optional_path"},
			}},
			wantErr: `unknown authz check policy type: "optional_path"`,
		},
		{
			name: "static_authenticated with invalid path pattern fails at startup",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					Type:                            "static_authenticated",
					AllowAnonymousWithoutIssuePaths: []string{`[invalid`},
				},
			}},
			wantErr: "allow_anonymous_without_issue_paths[0]",
		},
		{
			name: "token type validation: missing type",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					Type: "static_authenticated",
					TokenTypes: []TokenTypeConfig{
						{HeaderName: "Transaction-Token"},
					},
				},
			}},
			wantErr: "token type is required",
		},
		{
			name: "token type validation: missing header_name",
			config: &Config{AuthzServer: &AuthzServerConfig{
				Policy: AuthzCheckPolicyConfig{
					Type: "static_authenticated",
					TokenTypes: []TokenTypeConfig{
						{Type: string(service.TokenTypeTransactionToken)},
					},
				},
			}},
			wantErr: "header_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := NewProvider(tt.config)

			policy, err := p.AuthzCheckPolicy()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Exercise the policy with an authenticated subject to verify
			// the token types are wired through correctly.
			decision, err := policy.Decide(context.Background(), server.AuthzCheckPolicyInput{
				Subject: server.Principal{
					Result: &trust.Result{Subject: "user@example.com"},
				},
			})
			if err != nil {
				t.Fatalf("Decide() error: %v", err)
			}
			if decision.Action != tt.wantAction {
				t.Errorf("expected action %s, got %s", tt.wantAction, decision.Action)
			}
			if len(decision.TokenTypes) != len(tt.wantTypes) {
				t.Fatalf("expected %d token types, got %d", len(tt.wantTypes), len(decision.TokenTypes))
			}
			for i, want := range tt.wantTypes {
				got := decision.TokenTypes[i]
				if got.Type != want.Type {
					t.Errorf("token type[%d]: expected type %s, got %s", i, want.Type, got.Type)
				}
				if got.HeaderName != want.HeaderName {
					t.Errorf("token type[%d]: expected header %s, got %s", i, want.HeaderName, got.HeaderName)
				}
			}
		})
	}
}

func TestBuildStaticAuthenticatedOpts_HostRules(t *testing.T) {
	opts, err := buildStaticAuthenticatedOpts(AuthzCheckPolicyConfig{AllowAnonymousWithoutIssuePaths: []string{`/global`}, AllowAnonymousWithoutIssueRules: []AllowAnonymousRuleConfig{{Hosts: []string{`console\.example\.com`}, Paths: []string{`/docs`}}}})
	if err != nil {
		t.Fatalf("build options: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("got %d options, want 2", len(opts))
	}
}

func TestBuildStaticAuthenticatedOpts_HostRuleErrors(t *testing.T) {
	_, err := buildStaticAuthenticatedOpts(AuthzCheckPolicyConfig{AllowAnonymousWithoutIssueRules: []AllowAnonymousRuleConfig{{Paths: []string{`/docs`}}}})
	if err == nil || !strings.Contains(err.Error(), "allow_anonymous_without_issue_rules[0].hosts") {
		t.Fatalf("unexpected missing-host error: %v", err)
	}
	_, err = buildStaticAuthenticatedOpts(AuthzCheckPolicyConfig{AllowAnonymousWithoutIssueRules: []AllowAnonymousRuleConfig{{Hosts: []string{`[invalid`}, Paths: []string{`/docs`}}}})
	if err == nil || !strings.Contains(err.Error(), "allow_anonymous_without_issue_rules[0].hosts") {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = buildStaticAuthenticatedOpts(AuthzCheckPolicyConfig{AllowAnonymousWithoutIssueRules: []AllowAnonymousRuleConfig{{Hosts: []string{`example\.com`}, Paths: []string{`[invalid`}}}})
	if err == nil || !strings.Contains(err.Error(), "allow_anonymous_without_issue_rules[0].paths") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProvider_HostRulesReachAuthzServer(t *testing.T) {
	t.Parallel()

	policy, err := NewProvider(&Config{AuthzServer: &AuthzServerConfig{
		Policy: AuthzCheckPolicyConfig{
			Type:                            "static_authenticated",
			AllowAnonymousWithoutIssuePaths: []string{`^/global$`},
			AllowAnonymousWithoutIssueRules: []AllowAnonymousRuleConfig{{
				Hosts: []string{`^console\.example\.com$`},
				Paths: []string{`^/docs$`},
			}},
		},
	}}).AuthzCheckPolicy()
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	authzServer := server.NewAuthzServer(
		trust.NewStubStore(),
		service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), service.NewSimpleRegistry(), nil),
		policy,
		server.DefaultCredentialSources(),
		nil,
	)

	check := func(host, path string) int32 {
		t.Helper()
		resp, err := authzServer.Check(context.Background(), &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Host:   host,
					Path:   path,
				}},
			},
		})
		if err != nil {
			t.Fatalf("Check(%q, %q): %v", host, path, err)
		}
		return resp.Status.Code
	}

	if got := check("CONSOLE.EXAMPLE.COM", "/docs"); got != 0 {
		t.Errorf("host-scoped rule: got status %d, want OK", got)
	}
	if got := check("packages.example.com", "/docs"); got != 16 {
		t.Errorf("wrong host: got status %d, want Unauthenticated (16)", got)
	}
	if got := check("packages.example.com", "/global"); got != 0 {
		t.Errorf("global path rule: got status %d, want OK", got)
	}
}
