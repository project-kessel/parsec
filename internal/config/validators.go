package config

import (
	"fmt"
	"net/http"
	"time"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// NewTrustStore creates a trust store from configuration
func NewTrustStore(cfg TrustStoreConfig, transport http.RoundTripper) (trust.Store, error) {
	switch cfg.Type {
	case "stub_store":
		return newStubStore(cfg, transport)
	case "filtered_store":
		return newFilteredStore(cfg, transport)
	default:
		return nil, fmt.Errorf("unknown trust store type: %s (supported: stub_store, filtered_store)", cfg.Type)
	}
}

// newStubStore creates a stub trust store (no filtering)
func newStubStore(cfg TrustStoreConfig, transport http.RoundTripper) (trust.Store, error) {
	store := trust.NewStubStore()

	// Add validators
	for _, validatorCfg := range cfg.Validators {
		validator, err := newValidator(validatorCfg.ValidatorConfig, transport)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator: %w", err)
		}
		store.AddValidator(validator)
	}

	return store, nil
}

// newFilteredStore creates a filtered trust store with validator filtering
func newFilteredStore(cfg TrustStoreConfig, transport http.RoundTripper) (trust.Store, error) {
	var opts []trust.FilteredStoreOption

	// Add validator filter if configured
	if cfg.Filter != nil {
		filter, err := newValidatorFilter(*cfg.Filter)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator filter: %w", err)
		}
		opts = append(opts, trust.WithValidatorFilter(filter))
	}

	store, err := trust.NewFilteredStore(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create filtered store: %w", err)
	}

	// Add named validators
	for _, validatorCfg := range cfg.Validators {
		if validatorCfg.Name == "" {
			return nil, fmt.Errorf("validator name is required for filtered store")
		}

		validator, err := newValidator(validatorCfg.ValidatorConfig, transport)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator %s: %w", validatorCfg.Name, err)
		}

		store.AddValidator(validatorCfg.Name, validator)
	}

	return store, nil
}

// newValidator creates a validator from configuration
func newValidator(cfg ValidatorConfig, transport http.RoundTripper) (trust.Validator, error) {
	switch cfg.Type {
	case "jwt_validator":
		return newJWTValidator(cfg, transport)
	case "json_validator":
		return newJSONValidator(cfg)
	case "stub_validator":
		return newStubValidator(cfg)
	default:
		return nil, fmt.Errorf("unknown validator type: %s (supported: jwt_validator, json_validator, stub_validator)", cfg.Type)
	}
}

// newJWTValidator creates a JWT validator
func newJWTValidator(cfg ValidatorConfig, transport http.RoundTripper) (trust.Validator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("jwt_validator requires issuer")
	}
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("jwt_validator requires trust_domain")
	}

	validatorCfg := trust.JWTValidatorConfig{
		Issuer:      cfg.Issuer,
		JWKSURL:     cfg.JWKSURL,
		TrustDomain: cfg.TrustDomain,
	}

	// Parse refresh interval if provided
	if cfg.RefreshInterval != "" {
		duration, err := time.ParseDuration(cfg.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh_interval: %w", err)
		}
		validatorCfg.RefreshInterval = duration
	}

	// Use provided transport if available
	if transport != nil {
		validatorCfg.HTTPClient = &http.Client{
			Transport: transport,
		}
	}

	return trust.NewJWTValidator(validatorCfg)
}

// newJSONValidator creates a JSON validator
func newJSONValidator(cfg ValidatorConfig) (trust.Validator, error) {
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("json_validator requires trust_domain")
	}

	return trust.NewJSONValidator(
		trust.WithTrustDomain(cfg.TrustDomain),
	), nil
}

// newStubValidator creates a stub validator
func newStubValidator(cfg ValidatorConfig) (trust.Validator, error) {
	// Convert credential type strings to CredentialType
	var credTypes []trust.CredentialType
	for _, typeStr := range cfg.CredentialTypes {
		credType, err := parseCredentialType(typeStr)
		if err != nil {
			return nil, err
		}
		credTypes = append(credTypes, credType)
	}

	// If no types specified, default to bearer
	if len(credTypes) == 0 {
		credTypes = []trust.CredentialType{trust.CredentialTypeBearer}
	}

	return trust.NewStubValidator(credTypes...), nil
}

// newValidatorFilter creates a validator filter from configuration
func newValidatorFilter(cfg ValidatorFilterConfig) (trust.ValidatorFilter, error) {
	switch cfg.Type {
	case "cel":
		if cfg.Script == "" {
			return nil, fmt.Errorf("cel filter requires script")
		}
		return trust.NewCelValidatorFilter(cfg.Script)
	case "any":
		// Composite filter - allows if any sub-filter allows
		if len(cfg.Filters) == 0 {
			return nil, fmt.Errorf("any filter requires at least one sub-filter")
		}

		// Recursively create sub-filters
		var subFilters []trust.ValidatorFilter
		for i, subCfg := range cfg.Filters {
			subFilter, err := newValidatorFilter(subCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create sub-filter %d: %w", i, err)
			}
			subFilters = append(subFilters, subFilter)
		}

		return trust.NewAnyValidatorFilter(subFilters...), nil
	case "passthrough":
		// Passthrough filter - allows all validators
		return &passthroughValidatorFilter{}, nil
	default:
		return nil, fmt.Errorf("unknown validator filter type: %s (supported: cel, any, passthrough)", cfg.Type)
	}
}

// passthroughValidatorFilter allows all validators (no filtering)
type passthroughValidatorFilter struct{}

func (f *passthroughValidatorFilter) IsAllowed(actor *trust.Result, validatorName string, requestAttrs *request.RequestAttributes) (bool, error) {
	return true, nil
}

// parseCredentialType converts a string to a CredentialType
func parseCredentialType(s string) (trust.CredentialType, error) {
	switch s {
	case "bearer":
		return trust.CredentialTypeBearer, nil
	case "jwt":
		return trust.CredentialTypeJWT, nil
	case "json":
		return trust.CredentialTypeJSON, nil
	case "mtls":
		return trust.CredentialTypeMTLS, nil
	default:
		return "", fmt.Errorf("unknown credential type: %s (supported: bearer, jwt, json, mtls)", s)
	}
}
