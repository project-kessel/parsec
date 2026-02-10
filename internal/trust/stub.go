package trust

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
)

// StubStore is a simple in-memory trust store for testing
type StubStore struct {
	// Index validators by credential type for fast lookup
	validatorsByType map[CredentialType][]Validator
}

// NewStubStore creates a new stub trust store
func NewStubStore() *StubStore {
	return &StubStore{
		validatorsByType: make(map[CredentialType][]Validator),
	}
}

// AddValidator adds a validator to the store
// The validator is indexed by all credential types it supports
func (s *StubStore) AddValidator(v Validator) *StubStore {
	for _, credType := range v.CredentialTypes() {
		s.validatorsByType[credType] = append(s.validatorsByType[credType], v)
	}
	return s
}

// Validate implements the Store interface
// Tries validators in order until one succeeds
func (s *StubStore) Validate(ctx context.Context, credential Credential) (*Result, error) {
	credType := credential.Type()

	// Look up validators for this credential type
	validators, ok := s.validatorsByType[credType]
	if !ok || len(validators) == 0 {
		return nil, fmt.Errorf("no validator found for credential type %s", credType)
	}

	// Try validators in order until one succeeds
	var errors []error
	for _, v := range validators {
		result, err := v.Validate(ctx, credential)
		if err == nil {
			return result, nil
		}

		// Collect errors
		errors = append(errors, err)
	}

	// All validators failed
	return nil, fmt.Errorf("all validators failed for credential type %s: %w", credType, errors[len(errors)-1])
}

// ForActor implements the Store interface
// For StubStore, this is a no-op that returns the same store
// Use FilteredStore for actual filtering logic
func (s *StubStore) ForActor(ctx context.Context, actor *Result, requestAttrs *request.RequestAttributes) (Store, error) {
	return s, nil
}

// StubValidator is a simple stub validator for testing
// It accepts any token and returns a fixed result
type StubValidator struct {
	credTypes []CredentialType
	result    *Result
	err       error
}

// NewStubValidator creates a new stub validator
// It can accept multiple credential types
func NewStubValidator(credTypes ...CredentialType) *StubValidator {
	if len(credTypes) == 0 {
		credTypes = []CredentialType{CredentialTypeBearer}
	}

	return &StubValidator{
		credTypes: credTypes,
		result: &Result{
			Subject:     "test-subject",
			Issuer:      "https://test-issuer.example.com",
			TrustDomain: "test-domain",
			Claims: claims.Claims{
				"email": "test@example.com",
			},
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			Audience:  []string{"https://parsec.example.com"},
			Scope:     "read write",
		},
	}
}

// WithResult configures the stub to return a specific result
func (v *StubValidator) WithResult(result *Result) *StubValidator {
	v.result = result
	return v
}

// WithError configures the stub to return an error
func (v *StubValidator) WithError(err error) *StubValidator {
	v.err = err
	return v
}

// Validate implements the Validator interface
func (v *StubValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	if v.err != nil {
		return nil, v.err
	}

	// Type assertion to check for token-based credentials
	switch cred := credential.(type) {
	case *BearerCredential:
		if cred.Token == "" {
			return nil, fmt.Errorf("empty token")
		}
	case *JWTCredential:
		if cred.Token == "" {
			return nil, fmt.Errorf("empty token")
		}
	case *OIDCCredential:
		if cred.Token == "" {
			return nil, fmt.Errorf("empty token")
		}
	default:
		// For other credential types, just validate the type is supported
		supported := slices.Contains(v.credTypes, credential.Type())
		if !supported {
			return nil, fmt.Errorf("credential type %s not supported", credential.Type())
		}
	}

	// For stub, just return the configured result
	return v.result, nil
}

// CredentialTypes implements the Validator interface
func (v *StubValidator) CredentialTypes() []CredentialType {
	return v.credTypes
}
