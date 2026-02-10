package trust

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
)

func TestJSONValidator_Validate(t *testing.T) {
	ctx := context.Background()

	baseResult := &Result{
		Subject:     "test-subject",
		Issuer:      "https://test-issuer.example.com",
		TrustDomain: "test-domain",
		Claims: claims.Claims{
			"email":    "test@example.com",
			"role":     "admin",
			"org":      "example-org",
			"internal": "secret-data",
		},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		Audience:  []string{"https://parsec.example.com"},
		Scope:     "read write",
	}

	tests := []struct {
		name          string
		validator     *JSONValidator
		credential    Credential
		wantErr       bool
		checkClaims   func(t *testing.T, result *Result)
		errorContains string
	}{
		{
			name:      "valid credential with passthrough filter",
			validator: NewJSONValidator(),
			credential: func() Credential {
				data, _ := json.Marshal(baseResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr: false,
			checkClaims: func(t *testing.T, result *Result) {
				if len(result.Claims) != 4 {
					t.Errorf("expected 4 claims, got %d", len(result.Claims))
				}
				if result.Claims.GetString("email") != "test@example.com" {
					t.Errorf("expected email claim to be preserved")
				}
			},
		},
		{
			name: "valid credential with allow list filter",
			validator: NewJSONValidator(
				WithClaimsFilter(claims.NewAllowListClaimsFilter([]string{"email", "role"})),
			),
			credential: func() Credential {
				data, _ := json.Marshal(baseResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr: false,
			checkClaims: func(t *testing.T, result *Result) {
				if len(result.Claims) != 2 {
					t.Errorf("expected 2 claims, got %d", len(result.Claims))
				}
				if result.Claims.GetString("email") != "test@example.com" {
					t.Errorf("expected email claim")
				}
				if result.Claims.GetString("role") != "admin" {
					t.Errorf("expected role claim")
				}
				if result.Claims.Has("org") {
					t.Errorf("org claim should be filtered out")
				}
			},
		},
		{
			name: "valid credential with deny list filter",
			validator: NewJSONValidator(
				WithClaimsFilter(claims.NewDenyListClaimsFilter([]string{"internal"})),
			),
			credential: func() Credential {
				data, _ := json.Marshal(baseResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr: false,
			checkClaims: func(t *testing.T, result *Result) {
				if len(result.Claims) != 3 {
					t.Errorf("expected 3 claims, got %d", len(result.Claims))
				}
				if result.Claims.Has("internal") {
					t.Errorf("internal claim should be filtered out")
				}
				if result.Claims.GetString("email") != "test@example.com" {
					t.Errorf("expected email claim")
				}
			},
		},
		{
			name: "valid credential with trust domain check",
			validator: NewJSONValidator(
				WithTrustDomain("test-domain"),
			),
			credential: func() Credential {
				data, _ := json.Marshal(baseResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr: false,
		},
		{
			name: "invalid trust domain",
			validator: NewJSONValidator(
				WithTrustDomain("other-domain"),
			),
			credential: func() Credential {
				data, _ := json.Marshal(baseResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr:       true,
			errorContains: "trust domain mismatch",
		},
		{
			name:      "missing subject",
			validator: NewJSONValidator(),
			credential: func() Credential {
				invalidResult := &Result{
					Issuer:      "https://test-issuer.example.com",
					TrustDomain: "test-domain",
				}
				data, _ := json.Marshal(invalidResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr:       true,
			errorContains: "subject is required",
		},
		{
			name: "missing issuer when required",
			validator: NewJSONValidator(
				WithRequireIssuer(true),
			),
			credential: func() Credential {
				invalidResult := &Result{
					Subject:     "test-subject",
					TrustDomain: "test-domain",
				}
				data, _ := json.Marshal(invalidResult)
				return &JSONCredential{RawJSON: data}
			}(),
			wantErr:       true,
			errorContains: "issuer is required",
		},
		{
			name:      "empty JSON",
			validator: NewJSONValidator(),
			credential: &JSONCredential{
				RawJSON: []byte{},
			},
			wantErr:       true,
			errorContains: "empty JSON credential",
		},
		{
			name:      "invalid JSON",
			validator: NewJSONValidator(),
			credential: &JSONCredential{
				RawJSON: []byte(`{"invalid": json`),
			},
			wantErr:       true,
			errorContains: "failed to parse",
		},
		{
			name:      "wrong credential type",
			validator: NewJSONValidator(),
			credential: &BearerCredential{
				Token: "test-token",
			},
			wantErr:       true,
			errorContains: "expected JSONCredential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.validator.Validate(ctx, tt.credential)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("expected result, got nil")
				return
			}

			if tt.checkClaims != nil {
				tt.checkClaims(t, result)
			}
		})
	}
}

func TestJSONValidator_CredentialTypes(t *testing.T) {
	validator := NewJSONValidator()
	types := validator.CredentialTypes()

	if len(types) != 1 {
		t.Errorf("expected 1 credential type, got %d", len(types))
	}

	if types[0] != CredentialTypeJSON {
		t.Errorf("expected CredentialTypeJSON, got %s", types[0])
	}
}

func TestClaimsFilters(t *testing.T) {
	testClaims := claims.Claims{
		"email":    "test@example.com",
		"role":     "admin",
		"org":      "example-org",
		"internal": "secret-data",
	}

	t.Run("PassthroughClaimsFilter", func(t *testing.T) {
		filter := &claims.PassthroughClaimsFilter{}
		result := filter.Filter(testClaims)

		if len(result) != len(testClaims) {
			t.Errorf("expected %d claims, got %d", len(testClaims), len(result))
		}

		// Ensure it's a copy, not the same map
		result["new"] = "value"
		if testClaims.Has("new") {
			t.Errorf("filter should return a copy, not the same map")
		}
	})

	t.Run("AllowListClaimsFilter", func(t *testing.T) {
		filter := claims.NewAllowListClaimsFilter([]string{"email", "role"})
		result := filter.Filter(testClaims)

		if len(result) != 2 {
			t.Errorf("expected 2 claims, got %d", len(result))
		}

		if !result.Has("email") || !result.Has("role") {
			t.Errorf("expected email and role claims")
		}

		if result.Has("org") || result.Has("internal") {
			t.Errorf("unexpected claims in result")
		}
	})

	t.Run("DenyListClaimsFilter", func(t *testing.T) {
		filter := claims.NewDenyListClaimsFilter([]string{"internal"})
		result := filter.Filter(testClaims)

		if len(result) != 3 {
			t.Errorf("expected 3 claims, got %d", len(result))
		}

		if result.Has("internal") {
			t.Errorf("internal claim should be filtered out")
		}

		if !result.Has("email") || !result.Has("role") || !result.Has("org") {
			t.Errorf("expected other claims to be present")
		}
	})

	t.Run("AllowListClaimsFilter with nil claims", func(t *testing.T) {
		filter := claims.NewAllowListClaimsFilter([]string{"email"})
		result := filter.Filter(nil)

		if result != nil {
			t.Errorf("expected nil result for nil input")
		}
	})

	t.Run("DenyListClaimsFilter with nil claims", func(t *testing.T) {
		filter := claims.NewDenyListClaimsFilter([]string{"internal"})
		result := filter.Filter(nil)

		if result != nil {
			t.Errorf("expected nil result for nil input")
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
