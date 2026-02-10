package trust

import (
	"testing"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
)

func TestCelValidatorFilter_IsAllowed(t *testing.T) {
	tests := []struct {
		name          string
		script        string
		actor         *Result
		validatorName string
		wantAllowed   bool
		wantErr       bool
	}{
		{
			name:   "allow by trust domain",
			script: `actor.trust_domain == "prod"`,
			actor: &Result{
				Subject:     "prod-service",
				TrustDomain: "prod",
			},
			validatorName: "any-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "deny by trust domain",
			script: `actor.trust_domain == "prod"`,
			actor: &Result{
				Subject:     "dev-service",
				TrustDomain: "dev",
			},
			validatorName: "any-validator",
			wantAllowed:   false,
			wantErr:       false,
		},
		{
			name:   "allow by validator name",
			script: `validator_name == "allowed-validator"`,
			actor: &Result{
				Subject:     "any-service",
				TrustDomain: "any",
			},
			validatorName: "allowed-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "deny by validator name",
			script: `validator_name == "allowed-validator"`,
			actor: &Result{
				Subject:     "any-service",
				TrustDomain: "any",
			},
			validatorName: "other-validator",
			wantAllowed:   false,
			wantErr:       false,
		},
		{
			name:   "allow by claim role",
			script: `actor.claims.role == "admin"`,
			actor: &Result{
				Subject:     "admin-user",
				TrustDomain: "internal",
				Claims:      claims.Claims{"role": "admin"},
			},
			validatorName: "any-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "deny by claim role",
			script: `actor.claims.role == "admin"`,
			actor: &Result{
				Subject:     "regular-user",
				TrustDomain: "internal",
				Claims:      claims.Claims{"role": "user"},
			},
			validatorName: "any-validator",
			wantAllowed:   false,
			wantErr:       false,
		},
		{
			name:   "complex expression with multiple conditions",
			script: `(actor.trust_domain == "prod" && validator_name == "prod-validator") || actor.claims.role == "admin"`,
			actor: &Result{
				Subject:     "admin-user",
				TrustDomain: "dev",
				Claims:      claims.Claims{"role": "admin"},
			},
			validatorName: "dev-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "check issuer field",
			script: `actor.issuer == "https://trusted.example.com"`,
			actor: &Result{
				Subject:     "trusted-user",
				Issuer:      "https://trusted.example.com",
				TrustDomain: "trusted",
			},
			validatorName: "any-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "validator name in list",
			script: `validator_name in ["validator1", "validator2", "validator3"]`,
			actor: &Result{
				Subject:     "any-user",
				TrustDomain: "any",
			},
			validatorName: "validator2",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "validator name not in list",
			script: `validator_name in ["validator1", "validator2", "validator3"]`,
			actor: &Result{
				Subject:     "any-user",
				TrustDomain: "any",
			},
			validatorName: "validator4",
			wantAllowed:   false,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewCelValidatorFilter(tt.script)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}

			allowed, err := filter.IsAllowed(tt.actor, tt.validatorName, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestNewCelValidatorFilter_InvalidScript(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{
			name:   "empty script",
			script: "",
		},
		{
			name:   "invalid syntax",
			script: "actor.trust_domain == ",
		},
		{
			name:   "undefined variable",
			script: "undefined_var == true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCelValidatorFilter(tt.script)
			if err == nil {
				t.Errorf("expected error for invalid script, got nil")
			}
		})
	}
}

func TestCelValidatorFilter_Script(t *testing.T) {
	script := `actor.trust_domain == "prod"`
	filter, err := NewCelValidatorFilter(script)
	if err != nil {
		t.Fatalf("failed to create filter: %v", err)
	}

	if filter.Script() != script {
		t.Errorf("Script() = %v, want %v", filter.Script(), script)
	}
}

func TestCelValidatorFilter_WithRequestAttributes(t *testing.T) {
	tests := []struct {
		name          string
		script        string
		actor         *Result
		validatorName string
		requestAttrs  *request.RequestAttributes
		wantAllowed   bool
		wantErr       bool
	}{
		{
			name:   "filter by request path",
			script: `request.path.startsWith("/admin")`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "admin-validator",
			requestAttrs: &request.RequestAttributes{
				Path: "/admin/users",
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "deny by request path",
			script: `request.path.startsWith("/admin")`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "admin-validator",
			requestAttrs: &request.RequestAttributes{
				Path: "/api/public",
			},
			wantAllowed: false,
			wantErr:     false,
		},
		{
			name:   "filter by HTTP method",
			script: `request.method == "POST" && validator_name == "write-validator"`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "write-validator",
			requestAttrs: &request.RequestAttributes{
				Method: "POST",
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "deny by HTTP method",
			script: `request.method == "POST"`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "any-validator",
			requestAttrs: &request.RequestAttributes{
				Method: "GET",
			},
			wantAllowed: false,
			wantErr:     false,
		},
		{
			name:   "filter by IP address",
			script: `request.ip_address.startsWith("10.0.")`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "internal-validator",
			requestAttrs: &request.RequestAttributes{
				IPAddress: "10.0.1.5",
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "filter by Envoy context extensions - env",
			script: `request.additional.context_extensions.env == "prod"`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "prod-validator",
			requestAttrs: &request.RequestAttributes{
				Additional: map[string]any{
					"context_extensions": map[string]string{
						"env": "prod",
					},
				},
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "deny by Envoy context extensions - env",
			script: `request.additional.context_extensions.env == "prod"`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "prod-validator",
			requestAttrs: &request.RequestAttributes{
				Additional: map[string]any{
					"context_extensions": map[string]string{
						"env": "dev",
					},
				},
			},
			wantAllowed: false,
			wantErr:     false,
		},
		{
			name:   "filter by multiple context extensions",
			script: `request.additional.context_extensions.env == "prod" && request.additional.context_extensions.region == "us-west"`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "regional-validator",
			requestAttrs: &request.RequestAttributes{
				Additional: map[string]any{
					"context_extensions": map[string]string{
						"env":    "prod",
						"region": "us-west",
					},
				},
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "combine actor and request attributes",
			script: `actor.trust_domain == "prod" && request.path.startsWith("/api") && request.method == "POST"`,
			actor: &Result{
				Subject:     "prod-service",
				TrustDomain: "prod",
			},
			validatorName: "api-validator",
			requestAttrs: &request.RequestAttributes{
				Method: "POST",
				Path:   "/api/users",
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "complex filter with actor claims and request",
			script: `actor.claims.role == "admin" || (request.path.startsWith("/public") && validator_name == "public-validator")`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
				Claims:      claims.Claims{"role": "user"},
			},
			validatorName: "public-validator",
			requestAttrs: &request.RequestAttributes{
				Path: "/public/health",
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "handle nil request attributes",
			script: `actor.trust_domain == "prod"`,
			actor: &Result{
				Subject:     "prod-service",
				TrustDomain: "prod",
			},
			validatorName: "any-validator",
			requestAttrs:  nil,
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:   "check request headers",
			script: `request.headers["x-api-key"] == "secret"`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "api-validator",
			requestAttrs: &request.RequestAttributes{
				Headers: map[string]string{
					"x-api-key": "secret",
				},
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "check user agent",
			script: `request.user_agent.contains("Mozilla")`,
			actor: &Result{
				Subject:     "user",
				TrustDomain: "test",
			},
			validatorName: "browser-validator",
			requestAttrs: &request.RequestAttributes{
				UserAgent: "Mozilla/5.0",
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:   "context extension namespace check",
			script: `request.additional.context_extensions.namespace == "production" && validator_name in ["prod-validator-1", "prod-validator-2"]`,
			actor: &Result{
				Subject:     "service",
				TrustDomain: "prod",
			},
			validatorName: "prod-validator-1",
			requestAttrs: &request.RequestAttributes{
				Additional: map[string]any{
					"context_extensions": map[string]string{
						"namespace": "production",
					},
				},
			},
			wantAllowed: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewCelValidatorFilter(tt.script)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}

			allowed, err := filter.IsAllowed(tt.actor, tt.validatorName, tt.requestAttrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestConvertRequestAttributesToMap(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *request.RequestAttributes
		wantNil bool
		check   func(t *testing.T, m map[string]any)
	}{
		{
			name:    "nil request attributes",
			attrs:   nil,
			wantNil: true,
		},
		{
			name: "basic attributes",
			attrs: &request.RequestAttributes{
				Method:    "GET",
				Path:      "/api/users",
				IPAddress: "192.168.1.1",
				UserAgent: "TestAgent/1.0",
			},
			wantNil: false,
			check: func(t *testing.T, m map[string]any) {
				if m["method"] != "GET" {
					t.Errorf("expected method GET, got %v", m["method"])
				}
				if m["path"] != "/api/users" {
					t.Errorf("expected path /api/users, got %v", m["path"])
				}
				if m["ip_address"] != "192.168.1.1" {
					t.Errorf("expected ip_address 192.168.1.1, got %v", m["ip_address"])
				}
			},
		},
		{
			name: "with headers",
			attrs: &request.RequestAttributes{
				Headers: map[string]string{
					"authorization": "Bearer token",
					"content-type":  "application/json",
				},
			},
			wantNil: false,
			check: func(t *testing.T, m map[string]any) {
				headers, ok := m["headers"].(map[string]any)
				if !ok {
					t.Errorf("expected headers to be map[string]any")
					return
				}
				if headers["authorization"] != "Bearer token" {
					t.Errorf("expected authorization header")
				}
			},
		},
		{
			name: "with context extensions",
			attrs: &request.RequestAttributes{
				Additional: map[string]any{
					"context_extensions": map[string]string{
						"env":       "prod",
						"namespace": "default",
					},
				},
			},
			wantNil: false,
			check: func(t *testing.T, m map[string]any) {
				additional, ok := m["additional"].(map[string]any)
				if !ok {
					t.Errorf("expected additional to be map[string]any")
					return
				}
				contextExt, ok := additional["context_extensions"].(map[string]any)
				if !ok {
					t.Errorf("expected context_extensions to be map[string]any")
					return
				}
				if contextExt["env"] != "prod" {
					t.Errorf("expected env=prod in context_extensions")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ConvertRequestAttributesToMap(tt.attrs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNil {
				if m != nil {
					t.Errorf("expected nil map, got %v", m)
				}
				return
			}

			if m == nil {
				t.Errorf("expected non-nil map")
				return
			}

			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}
