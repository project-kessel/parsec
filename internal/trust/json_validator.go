package trust

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/project-kessel/parsec/internal/claims"
)

// JSONValidator validates unsigned JSON credentials with a Result structure
// It validates that the JSON matches the expected structure and filters claims
// based on the configured filter
type JSONValidator struct {
	credTypes     []CredentialType
	claimsFilter  claims.ClaimsFilter
	trustDomain   string
	requireIssuer bool
}

// JSONValidatorOption is a functional option for configuring a JSONValidator
type JSONValidatorOption func(*JSONValidator)

// WithClaimsFilter sets the claims filter
func WithClaimsFilter(filter claims.ClaimsFilter) JSONValidatorOption {
	return func(v *JSONValidator) {
		v.claimsFilter = filter
	}
}

// WithTrustDomain sets the expected trust domain
// If set, the validator will only accept credentials from this trust domain
func WithTrustDomain(trustDomain string) JSONValidatorOption {
	return func(v *JSONValidator) {
		v.trustDomain = trustDomain
	}
}

// WithRequireIssuer requires that the issuer field be present
func WithRequireIssuer(require bool) JSONValidatorOption {
	return func(v *JSONValidator) {
		v.requireIssuer = require
	}
}

// NewJSONValidator creates a new JSON validator
func NewJSONValidator(opts ...JSONValidatorOption) *JSONValidator {
	v := &JSONValidator{
		credTypes:    []CredentialType{CredentialTypeJSON},
		claimsFilter: &claims.PassthroughClaimsFilter{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate implements the Validator interface
func (v *JSONValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	// Check credential type
	jsonCred, ok := credential.(*JSONCredential)
	if !ok {
		return nil, fmt.Errorf("expected JSONCredential, got %T", credential)
	}

	if len(jsonCred.RawJSON) == 0 {
		return nil, fmt.Errorf("empty JSON credential")
	}

	// Parse the JSON into a Result structure
	var result Result
	if err := json.Unmarshal(jsonCred.RawJSON, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON credential: %w", err)
	}

	// Validate required fields
	if result.Subject == "" {
		return nil, fmt.Errorf("subject is required")
	}

	if v.requireIssuer && result.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	// Validate trust domain if configured
	if v.trustDomain != "" && result.TrustDomain != v.trustDomain {
		return nil, fmt.Errorf("trust domain mismatch: expected %s, got %s", v.trustDomain, result.TrustDomain)
	}

	// Filter claims
	result.Claims = v.claimsFilter.Filter(result.Claims)

	return &result, nil
}

// CredentialTypes implements the Validator interface
func (v *JSONValidator) CredentialTypes() []CredentialType {
	return v.credTypes
}
