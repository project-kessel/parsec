package trust

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
)

func TestFilteredStore_ForActor(t *testing.T) {
	ctx := context.Background()

	// Create test validators
	prodValidator := NewStubValidator(CredentialTypeBearer).
		WithResult(&Result{
			Subject:     "prod-user",
			Issuer:      "https://prod.example.com",
			TrustDomain: "prod",
			Claims:      claims.Claims{"env": "production"},
		})

	devValidator := NewStubValidator(CredentialTypeBearer).
		WithResult(&Result{
			Subject:     "dev-user",
			Issuer:      "https://dev.example.com",
			TrustDomain: "dev",
			Claims:      claims.Claims{"env": "development"},
		})

	adminValidator := NewStubValidator(CredentialTypeBearer).
		WithResult(&Result{
			Subject:     "admin-user",
			Issuer:      "https://admin.example.com",
			TrustDomain: "admin",
			Claims:      claims.Claims{"env": "admin"},
		})

	tests := []struct {
		name              string
		filterScript      string
		validators        map[string]Validator
		actor             *Result
		wantErr           bool
		expectedValidator []string
	}{
		{
			name:         "allow all validators for admin role",
			filterScript: `actor.claims.role == "admin"`,
			validators: map[string]Validator{
				"prod-validator":  prodValidator,
				"dev-validator":   devValidator,
				"admin-validator": adminValidator,
			},
			actor: &Result{
				Subject:     "admin-user",
				TrustDomain: "admin",
				Claims:      claims.Claims{"role": "admin"},
			},
			wantErr:           false,
			expectedValidator: []string{"prod-validator", "dev-validator", "admin-validator"},
		},
		{
			name:         "filter by trust domain",
			filterScript: `actor.trust_domain == "prod" && validator_name == "prod-validator"`,
			validators: map[string]Validator{
				"prod-validator": prodValidator,
				"dev-validator":  devValidator,
			},
			actor: &Result{
				Subject:     "prod-user",
				TrustDomain: "prod",
				Claims:      claims.Claims{},
			},
			wantErr:           false,
			expectedValidator: []string{"prod-validator"},
		},
		{
			name:         "filter by validator name list",
			filterScript: `validator_name in ["dev-validator", "admin-validator"]`,
			validators: map[string]Validator{
				"prod-validator":  prodValidator,
				"dev-validator":   devValidator,
				"admin-validator": adminValidator,
			},
			actor: &Result{
				Subject:     "any-user",
				TrustDomain: "any",
				Claims:      claims.Claims{},
			},
			wantErr:           false,
			expectedValidator: []string{"dev-validator", "admin-validator"},
		},
		{
			name:         "complex filter with multiple conditions",
			filterScript: `(actor.trust_domain == "prod" && validator_name == "prod-validator") || (actor.claims.role == "admin" && validator_name == "admin-validator")`,
			validators: map[string]Validator{
				"prod-validator":  prodValidator,
				"dev-validator":   devValidator,
				"admin-validator": adminValidator,
			},
			actor: &Result{
				Subject:     "admin-user",
				TrustDomain: "admin",
				Claims:      claims.Claims{"role": "admin"},
			},
			wantErr:           false,
			expectedValidator: []string{"admin-validator"},
		},
		{
			name:         "no validators match filter",
			filterScript: `actor.trust_domain == "nonexistent"`,
			validators: map[string]Validator{
				"prod-validator": prodValidator,
				"dev-validator":  devValidator,
			},
			actor: &Result{
				Subject:     "test-user",
				TrustDomain: "test",
				Claims:      claims.Claims{},
			},
			wantErr:           false,
			expectedValidator: []string{},
		},
		{
			name:         "check issuer field",
			filterScript: `actor.issuer == "https://trusted.example.com"`,
			validators: map[string]Validator{
				"prod-validator": prodValidator,
			},
			actor: &Result{
				Subject:     "trusted-user",
				Issuer:      "https://trusted.example.com",
				TrustDomain: "trusted",
				Claims:      claims.Claims{},
			},
			wantErr:           false,
			expectedValidator: []string{"prod-validator"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create filtered store with CEL filter
			store, err := NewFilteredStore(WithCELFilter(tt.filterScript))
			if err != nil {
				t.Fatalf("failed to create filtered store: %v", err)
			}

			// Add validators
			for name, validator := range tt.validators {
				store.AddValidator(name, validator)
			}

			// Get filtered store for actor
			filteredStore, err := store.ForActor(ctx, tt.actor, nil)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check that the correct validators are included
			if fs, ok := filteredStore.(*FilteredStore); ok {
				validators := fs.Validators()
				if len(validators) != len(tt.expectedValidator) {
					t.Errorf("expected %d validators, got %d", len(tt.expectedValidator), len(validators))
				}

				// Check each expected validator is present
				validatorNames := make(map[string]bool)
				for _, nv := range validators {
					validatorNames[nv.Name] = true
				}

				for _, expectedName := range tt.expectedValidator {
					if !validatorNames[expectedName] {
						t.Errorf("expected validator %s not found", expectedName)
					}
				}
			} else {
				t.Errorf("expected FilteredStore, got %T", filteredStore)
			}
		})
	}
}

func TestFilteredStore_Validate(t *testing.T) {
	ctx := context.Background()

	// Create a test validator
	validator := NewStubValidator(CredentialTypeBearer).
		WithResult(&Result{
			Subject:     "test-subject",
			TrustDomain: "test-domain",
		})

	store, err := NewFilteredStore()
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.AddValidator("test-validator", validator)

	// Test validation
	cred := &BearerCredential{Token: "test-token"}
	result, err := store.Validate(ctx, cred)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Errorf("expected result, got nil")
		return
	}

	if result.Subject != "test-subject" {
		t.Errorf("expected subject 'test-subject', got %s", result.Subject)
	}
}

func TestFilteredStore_NoFilterReturnsAllValidators(t *testing.T) {
	ctx := context.Background()

	validator := NewStubValidator(CredentialTypeBearer)

	// Create store without filter
	store, err := NewFilteredStore()
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.AddValidator("test-validator", validator)

	actor := &Result{
		Subject:     "test-actor",
		TrustDomain: "test",
	}

	// ForActor should return the same store when no filter is configured
	filteredStore, err := store.ForActor(ctx, actor, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if filteredStore != store {
		t.Errorf("expected same store when no filter configured")
	}
}

func TestFilteredStore_NilActorError(t *testing.T) {
	ctx := context.Background()

	store, err := NewFilteredStore(WithCELFilter(`true`))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	_, err = store.ForActor(ctx, nil, nil)
	if err == nil {
		t.Errorf("expected error for nil actor, got nil")
	}
}

func TestConvertResultToMap(t *testing.T) {
	now := time.Now()
	result := &Result{
		Subject:     "test-subject",
		Issuer:      "https://test.example.com",
		TrustDomain: "test-domain",
		Claims: claims.Claims{
			"email": "test@example.com",
			"role":  "admin",
		},
		ExpiresAt: now,
		IssuedAt:  now,
		Audience:  []string{"aud1", "aud2"},
		Scope:     "read write",
	}

	m, err := ConvertResultToMap(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m["subject"] != "test-subject" {
		t.Errorf("expected subject field")
	}

	if m["issuer"] != "https://test.example.com" {
		t.Errorf("expected issuer field")
	}

	if m["trust_domain"] != "test-domain" {
		t.Errorf("expected trust_domain field")
	}

	claims, ok := m["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims to be a map")
	}

	if claims["email"] != "test@example.com" {
		t.Errorf("expected email claim")
	}
}

func TestConvertResultToMap_Nil(t *testing.T) {
	m, err := ConvertResultToMap(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if m != nil {
		t.Errorf("expected nil map for nil result")
	}
}

func TestFilteredStore_InvalidCELScript(t *testing.T) {
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
			_, err := NewFilteredStore(WithCELFilter(tt.script))
			if err == nil {
				t.Errorf("expected error for invalid script, got nil")
			}
		})
	}
}

func TestJSONCredentialType(t *testing.T) {
	result := &Result{
		Subject:     "test",
		TrustDomain: "test-domain",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}

	cred := &JSONCredential{RawJSON: data}

	if cred.Type() != CredentialTypeJSON {
		t.Errorf("expected CredentialTypeJSON, got %s", cred.Type())
	}
}
