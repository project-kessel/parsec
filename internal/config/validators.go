package config

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/httpclient"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// NewTrustStore creates a trust store from configuration
func NewTrustStore(cfg TrustStoreConfig, httpRegistry *httpclient.Registry, trustObs trust.TrustObserver) (trust.Store, error) {
	switch cfg.Type {
	case "stub_store":
		return newStubStore(cfg, httpRegistry, trustObs)
	case "filtered_store":
		return newFilteredStore(cfg, httpRegistry, trustObs)
	default:
		return nil, fmt.Errorf("unknown trust store type: %s (supported: stub_store, filtered_store)", cfg.Type)
	}
}

// newStubStore creates a stub trust store (no filtering)
func newStubStore(cfg TrustStoreConfig, httpRegistry *httpclient.Registry, trustObs trust.TrustObserver) (trust.Store, error) {
	store := trust.NewStubStore()

	// Add validators
	for _, validatorCfg := range cfg.Validators {
		validator, err := newValidator(validatorCfg.Name, validatorCfg.ValidatorConfig, httpRegistry, trustObs)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator: %w", err)
		}
		store.AddValidator(validator)
	}

	return store, nil
}

// newFilteredStore creates a filtered trust store with validator filtering
func newFilteredStore(cfg TrustStoreConfig, httpRegistry *httpclient.Registry, trustObs trust.TrustObserver) (trust.Store, error) {
	var opts []trust.FilteredStoreOption

	// Add validator filter if configured
	if cfg.Filter != nil {
		filter, err := newValidatorFilter(*cfg.Filter)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator filter: %w", err)
		}
		opts = append(opts, trust.WithValidatorFilter(filter))
	}

	opts = append(opts, trust.WithObserver(trustObs))

	store, err := trust.NewFilteredStore(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create filtered store: %w", err)
	}

	// Add named validators
	for _, validatorCfg := range cfg.Validators {
		if validatorCfg.Name == "" {
			return nil, fmt.Errorf("validator name is required for filtered store")
		}

		validator, err := newValidator(validatorCfg.Name, validatorCfg.ValidatorConfig, httpRegistry, trustObs)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator %s: %w", validatorCfg.Name, err)
		}

		store.AddValidator(validatorCfg.Name, validator)
	}

	return store, nil
}

// newValidator creates a validator from configuration
func newValidator(name string, cfg ValidatorConfig, httpRegistry *httpclient.Registry, trustObs trust.TrustObserver) (trust.Validator, error) {
	switch cfg.Type {
	case "jwt_validator":
		return newJWTValidator(cfg, httpRegistry, trustObs)
	case "json_validator":
		return newJSONValidator(cfg)
	case "lua_validator":
		return newLuaValidator(name, cfg, httpRegistry, trustObs)
	case "stub_validator":
		return newStubValidator(cfg)
	default:
		return nil, fmt.Errorf("unknown validator type: %s (supported: jwt_validator, json_validator, lua_validator, stub_validator)", cfg.Type)
	}
}

// newJWTValidator creates a JWT validator
func newJWTValidator(cfg ValidatorConfig, httpRegistry *httpclient.Registry, trustObs trust.TrustObserver) (trust.Validator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("jwt_validator requires issuer")
	}
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("jwt_validator requires trust_domain")
	}

	validatorCfg := trust.JWTValidatorConfig{
		Issuer:           cfg.Issuer,
		JWKSURL:          cfg.JWKSURL,
		TrustDomain:      cfg.TrustDomain,
		AllowedAudiences: cfg.Audiences,
	}

	// Parse refresh interval if provided
	if cfg.RefreshInterval != "" {
		duration, err := time.ParseDuration(cfg.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh_interval: %w", err)
		}
		validatorCfg.RefreshInterval = duration
	}

	// Resolve HTTP client from registry (same mechanism as Lua consumers)
	client, err := resolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientSpec, httpRegistry)
	if err != nil {
		return nil, fmt.Errorf("jwt_validator: failed to resolve HTTP client: %w", err)
	}
	validatorCfg.HTTPClient = client

	validatorCfg.Observer = trustObs

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

func newLuaValidator(name string, cfg ValidatorConfig, httpRegistry *httpclient.Registry, trustObs trust.TrustObserver) (trust.Validator, error) {
	if name == "" {
		return nil, fmt.Errorf("lua_validator requires name")
	}

	script, err := readScript(cfg.Script, cfg.ScriptFile)
	if err != nil {
		return nil, err
	}
	if script == "" {
		return nil, fmt.Errorf("lua_validator requires either script or script_file")
	}

	credTypes, err := parseCredentialTypes(cfg.CredentialTypes)
	if err != nil {
		return nil, err
	}
	if len(credTypes) == 0 {
		return nil, fmt.Errorf("lua_validator requires credential_types")
	}

	var configSource luaservices.ConfigSource
	if cfg.Config != nil {
		configSource = luaservices.NewMapConfigSource(cfg.Config)
	}

	// Resolve HTTP client from registry
	client, err := resolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientSpec, httpRegistry)
	if err != nil {
		return nil, fmt.Errorf("lua_validator: failed to resolve HTTP client: %w", err)
	}

	opts := []trust.LuaValidatorOption{
		trust.WithLuaConfigSource(configSource),
		trust.WithLuaHTTPClient(client),
		trust.WithLuaValidatorObserver(trustObs),
	}

	var validator trust.Validator
	if cachingEnabled(cfg.Caching) {
		validator, err = trust.NewCacheableLuaValidator(name, script, credTypes, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create cacheable lua validator: %w", err)
		}
	} else {
		validator, err = trust.NewLuaValidator(name, script, credTypes, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create lua validator: %w", err)
		}
	}

	if cfg.Caching != nil {
		return wrapValidatorWithCaching(name, validator, *cfg.Caching, trustObs)
	}

	return validator, nil
}

func wrapValidatorWithCaching(name string, validator trust.Validator, cfg CachingConfig, obs trust.TrustObserver) (trust.Validator, error) {
	cacheTTL, err := parseCacheTTL(&cfg)
	if err != nil {
		return nil, err
	}

	switch cfg.Type {
	case "in_memory":
		return trust.NewInMemoryCachingValidator(name, validator, obs,
			trust.WithValidatorCacheTTL(cacheTTL),
		), nil

	case "distributed":
		groupName := cfg.GroupName
		if groupName == "" {
			groupName = "validator:" + name
		}

		cacheSize := cfg.CacheSize
		if cacheSize == 0 {
			cacheSize = 64 << 20
		}

		return trust.NewDistributedCachingValidator(name, validator, obs, trust.DistributedValidatorCachingConfig{
			GroupName:      groupName,
			CacheSizeBytes: cacheSize,
			CacheTTL:       cacheTTL,
		}), nil

	case "none", "":
		return validator, nil

	default:
		return nil, fmt.Errorf("unknown validator caching type: %s (supported: in_memory, distributed, none)", cfg.Type)
	}
}

// newStubValidator creates a stub validator
func newStubValidator(cfg ValidatorConfig) (trust.Validator, error) {
	// Convert credential type strings to CredentialType
	credTypes, err := parseCredentialTypes(cfg.CredentialTypes)
	if err != nil {
		return nil, err
	}

	// If no types specified, default to bearer
	if len(credTypes) == 0 {
		credTypes = []trust.CredentialType{trust.CredentialTypeBearer}
	}

	validator := trust.NewStubValidator(credTypes...)
	if len(cfg.Claims) == 0 {
		return validator, nil
	}

	trustDomain := cfg.TrustDomain
	if trustDomain == "" {
		trustDomain = "test-domain"
	}

	stubClaims := claims.Claims(maps.Clone(cfg.Claims))
	result := &trust.Result{
		Subject:     "test-subject",
		Issuer:      "https://test-issuer.example.com",
		TrustDomain: trustDomain,
		Claims:      stubClaims,
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Audience:    []string{"https://parsec.example.com"},
	}
	if scope, ok := stubClaims["scope"].(string); ok {
		result.Scope = scope
	}

	return validator.WithResult(result), nil
}

func parseCredentialTypes(typeStrings []string) ([]trust.CredentialType, error) {
	var credTypes []trust.CredentialType
	for _, typeStr := range typeStrings {
		credType, err := parseCredentialType(typeStr)
		if err != nil {
			return nil, err
		}
		credTypes = append(credTypes, credType)
	}
	return credTypes, nil
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

func (f *passthroughValidatorFilter) IsAllowed(_ context.Context, _ *trust.Result, _ string, _ *request.RequestAttributes) (bool, error) {
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
	case "oidc":
		return trust.CredentialTypeOIDC, nil
	default:
		return "", fmt.Errorf("unknown credential type: %s (supported: bearer, jwt, json, mtls, oidc)", s)
	}
}
