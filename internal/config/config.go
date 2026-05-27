package config

// Config is the root configuration structure for parsec
type Config struct {
	// Server configuration (gRPC and HTTP ports)
	Server ServerConfig `koanf:"server"`

	// TrustDomain is the trust domain for this parsec instance
	// Used as the audience for all issued tokens
	TrustDomain string `koanf:"trust_domain" usage:"trust domain for issued tokens (audience claim)"`

	// AuthzServer configuration for ext_authz service
	AuthzServer *AuthzServerConfig `koanf:"authz_server"`

	// ExchangeServer configuration for token exchange service
	ExchangeServer *ExchangeServerConfig `koanf:"exchange_server"`

	// TrustStore configuration (validators and filtering)
	TrustStore TrustStoreConfig `koanf:"trust_store"`

	// DataSources for token enrichment
	DataSources []DataSourceConfig `koanf:"data_sources"`

	// KeyProviders defines named key provider instances
	KeyProviders []KeyProviderConfig `koanf:"key_providers"`

	// Signers defines named signer instances (e.g., rotating key signers)
	Signers []SignerConfig `koanf:"signers"`

	// Issuers configuration for different token types
	Issuers []IssuerConfig `koanf:"issuers"`

	// Fixtures for hermetic testing (HTTP rules, etc.)
	Fixtures []FixtureConfig `koanf:"fixtures"`

	// Observability configuration (logging, metrics, tracing)
	Observability *ObservabilityConfig `koanf:"observability"`
}

// ServerConfig contains network-level server settings
type ServerConfig struct {
	// GRPCPort is the port for gRPC services (ext_authz, token exchange)
	GRPCPort int `koanf:"grpc_port" usage:"gRPC server port (ext_authz, token exchange)"`

	// HTTPPort is the port for HTTP services (gRPC-gateway transcoding)
	HTTPPort int `koanf:"http_port" usage:"HTTP server port (gRPC-gateway transcoding)"`
}

// AuthzServerConfig configures the ext_authz authorization server
type AuthzServerConfig struct {
	// TokenTypes specifies which token types to issue and how to deliver them
	TokenTypes []TokenTypeConfig `koanf:"token_types"`
}

// TokenTypeConfig specifies a token type to issue via ext_authz
type TokenTypeConfig struct {
	// Type is the OAuth token type URN
	// Examples:
	//   - "urn:ietf:params:oauth:token-type:txn_token" (transaction token)
	//   - "urn:ietf:params:oauth:token-type:access_token" (access token)
	//   - "urn:ietf:params:oauth:token-type:jwt" (JWT)
	Type string `koanf:"type"`

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string `koanf:"header_name"`
}

// ExchangeServerConfig configures the token exchange server
type ExchangeServerConfig struct {
	// ClaimsFilter determines which request_context claims actors can provide
	ClaimsFilter ClaimsFilterConfig `koanf:"claims_filter"`
}

// TrustStoreConfig configures the trust store and its validators
type TrustStoreConfig struct {
	// Type selects the trust store implementation
	// Options: "stub_store", "filtered_store"
	Type string `koanf:"type" usage:"trust store type: stub_store, filtered_store"`

	// Validators is the list of validators to add to the store
	Validators []NamedValidatorConfig `koanf:"validators"`

	// Filter configuration (only used when Type is "filtered_store")
	Filter *ValidatorFilterConfig `koanf:"filter"`
}

// NamedValidatorConfig is a validator with a name (for FilteredStore)
type NamedValidatorConfig struct {
	// Name uniquely identifies this validator
	Name string `koanf:"name"`

	// ValidatorConfig contains the actual validator configuration
	ValidatorConfig `koanf:",squash"`
}

// ValidatorConfig configures a credential validator
type ValidatorConfig struct {
	// Type selects the validator implementation
	// Options: "jwt_validator", "json_validator", "stub_validator"
	Type string `koanf:"type"`

	// JWT Validator fields
	Issuer          string `koanf:"issuer"`
	JWKSURL         string `koanf:"jwks_url"`
	TrustDomain     string `koanf:"trust_domain"`
	RefreshInterval string `koanf:"refresh_interval"` // Duration string like "15m"
	// Audiences is an optional allowlist for JWT aud claims (jwt_validator only).
	// Empty disables enforcement (backward compatible).
	Audiences []string `koanf:"audiences"`

	// JSON Validator fields
	// (TrustDomain is shared)

	// Stub Validator fields
	CredentialTypes []string `koanf:"credential_types"` // e.g., ["bearer", "jwt"]
}

// ValidatorFilterConfig configures validator filtering for actors
type ValidatorFilterConfig struct {
	// Type selects the filter implementation
	// Options: "cel", "any", "passthrough"
	Type string `koanf:"type" usage:"validator filter type: cel, any, passthrough"`

	// CEL filter fields
	Script string `koanf:"script" usage:"CEL script for validator filtering"`

	// Any filter fields (composite filter - allows if any sub-filter allows)
	Filters []ValidatorFilterConfig `koanf:"filters"`
}

// DataSourceConfig configures a data source
type DataSourceConfig struct {
	// Name uniquely identifies this data source
	Name string `koanf:"name"`

	// Type selects the data source implementation
	// Options: "lua", "static"
	Type string `koanf:"type"`

	// Lua data source fields
	ScriptFile string         `koanf:"script_file"` // Path to Lua script
	Script     string         `koanf:"script"`      // Inline Lua script (alternative to ScriptFile)
	Config     map[string]any `koanf:"config"`      // Lua: values available to script via config.get()

	// Static data source fields
	Data map[string]any `koanf:"data"` // Fixed JSON returned on every fetch

	// HTTP configuration
	HTTPConfig *HTTPConfig `koanf:"http"`

	// CacheKeyFunc names the Lua global that implements cache key masking. When non-empty,
	// the data source is built as datasource.CacheableLuaDataSource (script must define
	// fetch and this function). Observer wiring matches a plain Lua data source.
	CacheKeyFunc string `koanf:"cache_key_func"`

	// LuaCacheTTL is a duration string (e.g. "5m") for CacheableLuaDataSource.CacheTTL.
	// Empty uses the datasource package default when creating a cacheable Lua source.
	LuaCacheTTL string `koanf:"lua_cache_ttl"`

	// Caching configuration
	Caching *CachingConfig `koanf:"caching"`
}

// HTTPConfig configures HTTP client for Lua data sources
type HTTPConfig struct {
	// Timeout for HTTP requests (default: 30s)
	Timeout string `koanf:"timeout"` // Duration string like "30s"
}

// CachingConfig configures caching for a data source
type CachingConfig struct {
	// Type selects the caching implementation
	// Options: "in_memory", "distributed", "none"
	Type string `koanf:"type"`

	// TTL is the cache time-to-live
	TTL string `koanf:"ttl"` // Duration string like "5m"

	// Distributed caching fields
	GroupName string `koanf:"group_name"` // For groupcache
	CacheSize int64  `koanf:"cache_size"` // Cache size in bytes
}

// ClaimMapperConfig configures a claim mapper
type ClaimMapperConfig struct {
	// Type selects the mapper implementation
	// Options: "cel", "passthrough", "request_attributes", "stub"
	Type string `koanf:"type"`

	// Optional name for the mapper
	Name string `koanf:"name"`

	// CEL mapper fields
	ScriptFile string `koanf:"script_file"` // Path to CEL script file
	Script     string `koanf:"script"`      // Inline CEL script (alternative to ScriptFile)

	// Stub mapper fields
	Claims map[string]any `koanf:"claims"`
}

// IssuerConfig configures a token issuer
type IssuerConfig struct {
	// TokenType is the OAuth token type URN this issuer handles
	// Examples:
	//   - "urn:ietf:params:oauth:token-type:txn_token" (transaction token)
	//   - "urn:ietf:params:oauth:token-type:access_token" (access token)
	//   - "urn:ietf:params:oauth:token-type:jwt" (JWT)
	TokenType string `koanf:"token_type"`

	// Type selects the issuer implementation
	// Options: "stub", "unsigned", "transaction_token"
	Type string `koanf:"type"`

	// Common fields
	IssuerURL string `koanf:"issuer_url"`
	TTL       string `koanf:"ttl"` // Duration string like "5m"

	// SignerID references a named signer from the global signers config
	// Used for transaction tokens to configure the signer
	SignerID string `koanf:"signer_id"`

	// Transaction token issuer fields (stub, transaction_token types)
	// These mappers build the "tctx" and "req_ctx" claims
	TransactionContextMappers []ClaimMapperConfig `koanf:"transaction_context"`
	RequestContextMappers     []ClaimMapperConfig `koanf:"request_context"`

	// Simple issuer fields (unsigned type)
	// These mappers build the token's claim structure
	ClaimMappers []ClaimMapperConfig `koanf:"claim_mappers"`

	// Stub issuer fields (deprecated - use mappers instead)
	IncludeRequestContext bool `koanf:"include_request_context"`
}

// KeyProviderConfig configures a key provider
type KeyProviderConfig struct {
	// ID uniquely identifies this key provider
	ID string `koanf:"id"`

	// Type selects the key provider implementation
	// Options: "memory", "aws_kms", "disk"
	Type string `koanf:"type"`

	// KeyType is the cryptographic key type this provider creates
	// Options: "EC-P256", "EC-P384", "RSA-2048", "RSA-4096"
	KeyType string `koanf:"key_type"`

	// Algorithm is the signing algorithm to use with the keys
	// Optional. Defaults based on KeyType (e.g., "ES256" for EC-P256, "RS256" for RSA-2048)
	// Options: "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", etc.
	Algorithm string `koanf:"algorithm"`

	// AWS KMS fields
	Region      string `koanf:"region"`       // AWS region (e.g., "us-east-1")
	AliasPrefix string `koanf:"alias_prefix"` // KMS alias prefix (e.g., "alias/parsec/")

	// Disk key provider fields
	KeysPath string `koanf:"keys_path"` // Path to directory for storing keys
}

// SignerConfig configures a signer
type SignerConfig struct {
	// ID uniquely identifies this signer
	ID string `koanf:"id"`

	// Type selects the signer implementation
	// Options: "dual_slot"
	Type string `koanf:"type"`

	// Namespace is an optional logical namespace for keys (defaults to ID if not set)
	Namespace string `koanf:"namespace"`

	// KeyProviderID references a named key provider from the global key_providers config
	KeyProviderID string `koanf:"key_provider_id"`

	// Rotation parameters for dual_slot signer
	KeyTTL            string `koanf:"key_ttl"`            // Duration string like "24h"
	RotationThreshold string `koanf:"rotation_threshold"` // Duration string like "6h"
	GracePeriod       string `koanf:"grace_period"`       // Duration string like "2h"
	CheckInterval     string `koanf:"check_interval"`     // Duration string like "1m"
	PrepareTimeout    string `koanf:"prepare_timeout"`    // Duration string like "1m"
}

// ClaimsFilterConfig configures the claims filter registry
type ClaimsFilterConfig struct {
	// Type selects the filter registry implementation
	// Options: "stub", "cel", "allowlist"
	Type string `koanf:"type" usage:"claims filter type: stub, cel, allowlist"`

	// CEL-based filter
	Script string `koanf:"script" usage:"CEL script for claims filtering"`

	// Allowlist-based filter
	AllowedClaims []string `koanf:"allowed_claims"`

	// Per-actor rules
	ActorRules map[string][]string `koanf:"actor_rules"` // Map of actor pattern to allowed claims
}

// FixtureConfig configures a fixture for hermetic testing
type FixtureConfig struct {
	// Type selects the fixture type
	// Options: "http_rule", "jwks"
	Type string `koanf:"type"`

	// HTTP rule fields (when Type is "http_rule")
	Request  FixtureRequest  `koanf:"request"`
	Response FixtureResponse `koanf:"response"`

	// JWKS fields (when Type is "jwks")
	Issuer    string `koanf:"issuer"`    // Issuer URL (iss claim)
	JWKSURL   string `koanf:"jwks_url"`  // URL where JWKS will be served
	KeyID     string `koanf:"key_id"`    // Optional key identifier (defaults to "test-key-1")
	Algorithm string `koanf:"algorithm"` // Optional algorithm (defaults to "RS256")
}

// FixtureRequest defines request matching criteria for HTTP fixtures
type FixtureRequest struct {
	// Method is the HTTP method to match (e.g., "GET", "POST", "*" for any)
	Method string `koanf:"method"`

	// URL is the URL to match (exact or pattern based on URLType)
	URL string `koanf:"url"`

	// URLType specifies how to match the URL
	// Options: "exact" (default), "pattern" (regex)
	URLType string `koanf:"url_type"`

	// Headers are optional headers to match
	Headers map[string]string `koanf:"headers"`
}

// FixtureResponse defines the HTTP response to return for a fixture
type FixtureResponse struct {
	// StatusCode is the HTTP status code (e.g., 200, 404)
	StatusCode int `koanf:"status"`

	// Headers are optional response headers
	Headers map[string]string `koanf:"headers"`

	// Body is the response body content
	Body string `koanf:"body"`
}

// ObservabilityConfig configures application observability
type ObservabilityConfig struct {
	// Type selects the observer implementation
	// Options: "logging", "noop", "metrics", "composite"
	Type string `koanf:"type" usage:"observer type: logging, noop, metrics, composite"`

	// LogLevel sets the default log level for logging observer
	// Options: "debug", "info", "warn", "error"
	// Default: "info"
	LogLevel string `koanf:"log_level" usage:"default log level: debug, info, warn, error"`

	// LogFormat sets the log format
	// Options: "json", "text"
	// Default: "json"
	LogFormat string `koanf:"log_format" usage:"log format: json, text"`

	// Event-specific logging configuration
	TokenIssuance   *EventLoggingConfig `koanf:"token_issuance"`
	TokenExchange   *EventLoggingConfig `koanf:"token_exchange"`
	AuthzCheck      *EventLoggingConfig `koanf:"authz_check"`
	DataSourceCache *EventLoggingConfig `koanf:"datasource_cache"`
	LuaDataSource   *EventLoggingConfig `koanf:"lua_datasource"`
	KeyRotation     *EventLoggingConfig `koanf:"key_rotation"`
	KeyProvider     *EventLoggingConfig `koanf:"key_provider"`
	TrustValidation *EventLoggingConfig `koanf:"trust_validation"`
	JWKSCache       *EventLoggingConfig `koanf:"jwks_cache"`
	ServerLifecycle *EventLoggingConfig `koanf:"server_lifecycle"`

	// Composite observer fields - allows multiple observers
	Observers []ObservabilityConfig `koanf:"observers"`
}

// EventLoggingConfig configures logging for a specific event type
type EventLoggingConfig struct {
	// LogLevel overrides the default log level for this event
	// Options: "debug", "info", "warn", "error"
	LogLevel string `koanf:"log_level" usage:"event-specific log level: debug, info, warn, error"`

	// LogFormat overrides the default log format for this event
	// Options: "json", "text"
	LogFormat string `koanf:"log_format" usage:"event-specific log format: json, text"`

	// Enabled controls whether this event type is logged
	// Default: true
	Enabled *bool `koanf:"enabled" usage:"enable/disable logging for this event type"`
}
