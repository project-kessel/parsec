package trust

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/request"
)

// ValidatorFilter determines which validators an actor is allowed to use
type ValidatorFilter interface {
	// IsAllowed returns true if the actor is allowed to use the named validator
	// The request attributes provide additional context about the request being made
	IsAllowed(actor *Result, validatorName string, requestAttrs *request.RequestAttributes) (bool, error)
}

// NamedValidator associates a name with a Validator
// This is used by FilteredStore to track validators with names
type NamedValidator struct {
	Name      string
	Validator Validator
}

// FilteredStore is a Store implementation that filters validators based on policies
// It associates names with validators and uses a ValidatorFilter to determine which
// validators an actor is allowed to use
type FilteredStore struct {
	// Named validators indexed by credential type
	validatorsByType map[CredentialType][]NamedValidator
	// All named validators in order
	validators []NamedValidator
	// Filter for determining validator access
	filter ValidatorFilter
}

// FilteredStoreOption is a functional option for configuring a FilteredStore
type FilteredStoreOption func(*FilteredStore) error

// WithValidatorFilter sets the validator filter for the store
func WithValidatorFilter(filter ValidatorFilter) FilteredStoreOption {
	return func(s *FilteredStore) error {
		s.filter = filter
		return nil
	}
}

// WithCELFilter sets a CEL-based filter expression for the store
// The expression should evaluate to a boolean indicating whether a validator is allowed
// It has access to:
//   - actor: the actor's Result object as a map
//   - validator_name: the name of the validator being checked
func WithCELFilter(script string) FilteredStoreOption {
	return func(s *FilteredStore) error {
		filter, err := NewCelValidatorFilter(script)
		if err != nil {
			return err
		}
		s.filter = filter
		return nil
	}
}

// NewFilteredStore creates a new filtered store
func NewFilteredStore(opts ...FilteredStoreOption) (*FilteredStore, error) {
	s := &FilteredStore{
		validatorsByType: make(map[CredentialType][]NamedValidator),
		validators:       make([]NamedValidator, 0),
	}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// AddValidator adds a named validator to the store
// The validator is indexed by all credential types it supports
func (s *FilteredStore) AddValidator(name string, v Validator) *FilteredStore {
	nv := NamedValidator{
		Name:      name,
		Validator: v,
	}

	for _, credType := range v.CredentialTypes() {
		s.validatorsByType[credType] = append(s.validatorsByType[credType], nv)
	}
	s.validators = append(s.validators, nv)
	return s
}

// Validate implements the Store interface
// Tries validators in order until one succeeds
func (s *FilteredStore) Validate(ctx context.Context, credential Credential) (*Result, error) {
	credType := credential.Type()

	// Look up validators for this credential type
	validators, ok := s.validatorsByType[credType]
	if !ok || len(validators) == 0 {
		return nil, fmt.Errorf("no validator found for credential type %s", credType)
	}

	// Try validators in order until one succeeds
	var errors []error
	for _, nv := range validators {
		result, err := nv.Validator.Validate(ctx, credential)
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
// Returns a new FilteredStore that only includes validators the actor is allowed to use
// The requestAttrs parameter provides additional context for filtering decisions
func (s *FilteredStore) ForActor(ctx context.Context, actor *Result, requestAttrs *request.RequestAttributes) (Store, error) {
	if actor == nil {
		return nil, fmt.Errorf("actor cannot be nil")
	}

	// If no filter is configured, return the same store
	if s.filter == nil {
		return s, nil
	}

	// Create a new filtered store with the same filter
	filtered := &FilteredStore{
		validatorsByType: make(map[CredentialType][]NamedValidator),
		validators:       make([]NamedValidator, 0),
		filter:           s.filter,
	}

	// Evaluate the filter for each validator
	for _, nv := range s.validators {
		allowed, err := s.filter.IsAllowed(actor, nv.Name, requestAttrs)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate filter for validator %s: %w", nv.Name, err)
		}

		if allowed {
			filtered.AddValidator(nv.Name, nv.Validator)
		}
	}

	return filtered, nil
}

// Validators returns all named validators in the store
func (s *FilteredStore) Validators() []NamedValidator {
	return s.validators
}
