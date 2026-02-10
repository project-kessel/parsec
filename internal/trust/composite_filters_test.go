package trust

import (
	"fmt"
	"testing"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
)

// mockFilter is a simple mock filter for testing
type mockFilter struct {
	allowed bool
	err     error
}

func (f *mockFilter) IsAllowed(actor *Result, validatorName string, requestAttrs *request.RequestAttributes) (bool, error) {
	return f.allowed, f.err
}

func TestAnyValidatorFilter_IsAllowed(t *testing.T) {
	testActor := &Result{
		Subject:     "test-user",
		TrustDomain: "test",
		Claims:      claims.Claims{},
	}

	tests := []struct {
		name          string
		filters       []ValidatorFilter
		validatorName string
		wantAllowed   bool
		wantErr       bool
	}{
		{
			name: "single filter returns true",
			filters: []ValidatorFilter{
				&mockFilter{allowed: true},
			},
			validatorName: "test-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name: "single filter returns false",
			filters: []ValidatorFilter{
				&mockFilter{allowed: false},
			},
			validatorName: "test-validator",
			wantAllowed:   false,
			wantErr:       false,
		},
		{
			name: "first filter returns true",
			filters: []ValidatorFilter{
				&mockFilter{allowed: true},
				&mockFilter{allowed: false},
				&mockFilter{allowed: false},
			},
			validatorName: "test-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name: "second filter returns true",
			filters: []ValidatorFilter{
				&mockFilter{allowed: false},
				&mockFilter{allowed: true},
				&mockFilter{allowed: false},
			},
			validatorName: "test-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name: "last filter returns true",
			filters: []ValidatorFilter{
				&mockFilter{allowed: false},
				&mockFilter{allowed: false},
				&mockFilter{allowed: true},
			},
			validatorName: "test-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name: "all filters return false",
			filters: []ValidatorFilter{
				&mockFilter{allowed: false},
				&mockFilter{allowed: false},
				&mockFilter{allowed: false},
			},
			validatorName: "test-validator",
			wantAllowed:   false,
			wantErr:       false,
		},
		{
			name: "some filters error but one returns true",
			filters: []ValidatorFilter{
				&mockFilter{err: fmt.Errorf("filter error")},
				&mockFilter{allowed: true},
				&mockFilter{allowed: false},
			},
			validatorName: "test-validator",
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name: "all filters error",
			filters: []ValidatorFilter{
				&mockFilter{err: fmt.Errorf("error 1")},
				&mockFilter{err: fmt.Errorf("error 2")},
				&mockFilter{err: fmt.Errorf("error 3")},
			},
			validatorName: "test-validator",
			wantAllowed:   false,
			wantErr:       true,
		},
		{
			name: "mix of errors and false",
			filters: []ValidatorFilter{
				&mockFilter{allowed: false},
				&mockFilter{err: fmt.Errorf("error 1")},
				&mockFilter{allowed: false},
			},
			validatorName: "test-validator",
			wantAllowed:   false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewAnyValidatorFilter(tt.filters...)
			allowed, err := filter.IsAllowed(testActor, tt.validatorName, nil)

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

func TestAnyValidatorFilter_NoFilters(t *testing.T) {
	filter := NewAnyValidatorFilter()
	actor := &Result{
		Subject:     "test-user",
		TrustDomain: "test",
	}

	allowed, err := filter.IsAllowed(actor, "test-validator", nil)
	if err == nil {
		t.Errorf("expected error for no filters configured, got nil")
	}

	if allowed {
		t.Errorf("expected false when no filters configured")
	}
}

func TestAnyValidatorFilter_WithRealCELFilters(t *testing.T) {
	// Create two CEL filters
	prodFilter, err := NewCelValidatorFilter(`actor.trust_domain == "prod"`)
	if err != nil {
		t.Fatalf("failed to create prod filter: %v", err)
	}

	adminFilter, err := NewCelValidatorFilter(`actor.claims.role == "admin"`)
	if err != nil {
		t.Fatalf("failed to create admin filter: %v", err)
	}

	// Compose them with AnyValidatorFilter
	anyFilter := NewAnyValidatorFilter(prodFilter, adminFilter)

	tests := []struct {
		name        string
		actor       *Result
		wantAllowed bool
	}{
		{
			name: "prod actor allowed",
			actor: &Result{
				Subject:     "prod-service",
				TrustDomain: "prod",
				Claims:      claims.Claims{},
			},
			wantAllowed: true,
		},
		{
			name: "admin actor allowed",
			actor: &Result{
				Subject:     "admin-user",
				TrustDomain: "dev",
				Claims:      claims.Claims{"role": "admin"},
			},
			wantAllowed: true,
		},
		{
			name: "neither prod nor admin denied",
			actor: &Result{
				Subject:     "dev-user",
				TrustDomain: "dev",
				Claims:      claims.Claims{"role": "user"},
			},
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := anyFilter.IsAllowed(tt.actor, "test-validator", nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}
