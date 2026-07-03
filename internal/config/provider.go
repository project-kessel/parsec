package config

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/probe/otel"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// Provider constructs all application components from configuration.
// Create one with NewProvider.
type Provider struct {
	config *Config

	logCtx          *LoggerContext
	obs             observer.Observer
	obsErr          error
	obsBuilt        bool
	metricsProv     *otel.Provider
	metricsErr      error
	metricsBuilt    bool
	bootstrapFields map[string]string

	// Lazily constructed components (cached after first call)
	httpClientRegistry   *httpclient.Registry
	trustStore           trust.Store
	dataSourceRegistry   *service.DataSourceRegistry
	issuerRegistry       service.Registry
	claimsFilterRegistry server.ClaimsFilterRegistry
	tokenService         *service.TokenService
	httpFixtureProvider  httpfixture.FixtureProvider
	httpFixtureBuilt     bool
}

// NewProvider creates a new provider from configuration.
func NewProvider(config *Config) *Provider {
	return &Provider{
		config:          config,
		bootstrapFields: make(map[string]string),
	}
}

func (p *Provider) loggerContext() (*LoggerContext, error) {
	if p.logCtx != nil {
		return p.logCtx, nil
	}

	lc, err := NewLoggerContext(p.config.Observability)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger context: %w", err)
	}

	p.logCtx = &lc
	return p.logCtx, nil
}

// Logger returns the application logger built from configuration.
func (p *Provider) Logger() (zerolog.Logger, error) {
	lc, err := p.loggerContext()
	if err != nil {
		return zerolog.Nop(), err
	}
	return lc.Logger, nil
}

// Observer returns the central observer, lazily created from configuration.
// Internally constructs all observability resources (logger, metrics provider)
// and wires them into the appropriate observer implementations.
// [MuxConfigurers] and [BootstrapFields] may be populated as a side-effect.
func (p *Provider) Observer() (observer.Observer, error) {
	if p.obsBuilt {
		return p.obs, p.obsErr
	}
	p.obsBuilt = true

	obs, err := p.buildObserver(p.config.Observability, nil)
	if err != nil {
		p.obsErr = fmt.Errorf("failed to create observer: %w", err)
		return nil, p.obsErr
	}

	p.obs = obs
	return obs, nil
}

// BootstrapFields returns key-value pairs contributed during the
// bootstrapping phase for inclusion in the startup log event
// (e.g. metrics_endpoint → /metrics). Any Provider method may
// contribute fields during component construction.
func (p *Provider) BootstrapFields() map[string]string {
	return p.bootstrapFields
}

// buildObserver recursively constructs an observer from config. parentLogCtx
// is nil for the root observer and non-nil for composite children.
func (p *Provider) buildObserver(cfg *ObservabilityConfig, parentLogCtx *LoggerContext) (observer.Observer, error) {
	if cfg == nil {
		return observer.NoOp(), nil
	}

	switch cfg.Type {
	case "logging":
		lc, err := p.resolveLogCtx(cfg, parentLogCtx)
		if err != nil {
			return nil, err
		}
		return newLoggingObserver(cfg, lc)

	case "noop", "":
		return observer.NoOp(), nil

	case "metrics":
		mp, err := p.metricsProvider()
		if err != nil {
			return nil, err
		}
		if mp == nil {
			return observer.NoOp(), nil
		}
		endpoint := "/metrics"
		p.bootstrapFields["metrics_endpoint"] = endpoint
		return otel.NewObserver(mp, endpoint)

	case "composite":
		return p.buildCompositeObserver(cfg, parentLogCtx)

	default:
		return nil, fmt.Errorf("unknown observability type: %s (supported: logging, noop, metrics, composite)", cfg.Type)
	}
}

func (p *Provider) buildCompositeObserver(cfg *ObservabilityConfig, parentLogCtx *LoggerContext) (observer.Observer, error) {
	if len(cfg.Observers) == 0 {
		return nil, fmt.Errorf("composite observer requires at least one sub-observer")
	}

	lc, err := p.resolveLogCtx(cfg, parentLogCtx)
	if err != nil {
		return nil, err
	}

	var children []observer.Observer
	for i, subCfg := range cfg.Observers {
		childLogCtx, err := deriveLoggerContext(lc, &subCfg)
		if err != nil {
			return nil, fmt.Errorf("observer %d: %w", i, err)
		}
		obs, err := p.buildObserver(&subCfg, &childLogCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to create observer %d: %w", i, err)
		}
		children = append(children, obs)
	}

	return observer.CompositeAll(children), nil
}

// resolveLogCtx returns the appropriate LoggerContext for observer
// construction: the parent override if provided, otherwise the root context.
func (p *Provider) resolveLogCtx(cfg *ObservabilityConfig, parentLogCtx *LoggerContext) (LoggerContext, error) {
	if parentLogCtx != nil {
		return deriveLoggerContext(*parentLogCtx, cfg)
	}
	lc, err := p.loggerContext()
	if err != nil {
		return LoggerContext{}, err
	}
	return *lc, nil
}

// TrustStore returns the configured trust store.
func (p *Provider) TrustStore() (trust.Store, error) {
	if p.trustStore != nil {
		return p.trustStore, nil
	}

	obs, err := p.Observer()
	if err != nil {
		return nil, err
	}

	registry, err := p.HTTPClientRegistry()
	if err != nil {
		return nil, err
	}

	store, err := NewTrustStore(p.config.TrustStore, registry, obs)
	if err != nil {
		return nil, fmt.Errorf("failed to create trust store: %w", err)
	}

	p.trustStore = store
	return store, nil
}

// DataSourceRegistry returns the configured data source registry
func (p *Provider) DataSourceRegistry() (*service.DataSourceRegistry, error) {
	if p.dataSourceRegistry != nil {
		return p.dataSourceRegistry, nil
	}

	obs, err := p.Observer()
	if err != nil {
		return nil, err
	}

	httpRegistry, err := p.HTTPClientRegistry()
	if err != nil {
		return nil, err
	}

	registry, err := NewDataSourceRegistry(p.config.DataSources, httpRegistry, obs)
	if err != nil {
		return nil, fmt.Errorf("failed to create data source registry: %w", err)
	}

	p.dataSourceRegistry = registry
	return registry, nil
}

// IssuerRegistry returns the configured issuer registry
func (p *Provider) IssuerRegistry() (service.Registry, error) {
	if p.issuerRegistry != nil {
		return p.issuerRegistry, nil
	}

	obs, err := p.Observer()
	if err != nil {
		return nil, err
	}

	registry, err := NewIssuerRegistry(*p.config, obs)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer registry: %w", err)
	}

	p.issuerRegistry = registry
	return registry, nil
}

// ExchangeServerClaimsFilterRegistry returns the claims filter registry for the exchange server
func (p *Provider) ExchangeServerClaimsFilterRegistry() (server.ClaimsFilterRegistry, error) {
	if p.claimsFilterRegistry != nil {
		return p.claimsFilterRegistry, nil
	}

	// Get claims filter config from exchange server config
	var claimsFilterCfg ClaimsFilterConfig
	if p.config.ExchangeServer != nil {
		claimsFilterCfg = p.config.ExchangeServer.ClaimsFilter
	}

	registry, err := NewClaimsFilterRegistry(claimsFilterCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create claims filter registry: %w", err)
	}

	p.claimsFilterRegistry = registry
	return registry, nil
}

// TokenService returns the configured token service
func (p *Provider) TokenService() (*service.TokenService, error) {
	if p.tokenService != nil {
		return p.tokenService, nil
	}

	// Build dependencies
	dataSourceRegistry, err := p.DataSourceRegistry()
	if err != nil {
		return nil, err
	}

	issuerRegistry, err := p.IssuerRegistry()
	if err != nil {
		return nil, err
	}

	obs, err := p.Observer()
	if err != nil {
		return nil, err
	}

	tokenService := service.NewTokenService(
		p.config.TrustDomain,
		dataSourceRegistry,
		issuerRegistry,
		obs,
	)

	p.tokenService = tokenService
	return tokenService, nil
}

// metricsProvider returns the shared metrics provider, lazily created and
// cached. Returns (nil, nil) when called for a non-metrics observer type;
// the caller decides whether that's an error. The creation result (including
// errors) is cached so repeated calls return the same outcome.
func (p *Provider) metricsProvider() (*otel.Provider, error) {
	if p.metricsBuilt {
		return p.metricsProv, p.metricsErr
	}
	p.metricsBuilt = true

	mp, err := otel.New()
	if err != nil {
		p.metricsErr = fmt.Errorf("failed to create metrics provider: %w", err)
		return nil, p.metricsErr
	}
	p.metricsProv = mp
	return mp, nil
}

// GRPCPort returns the configured gRPC port.
func (p *Provider) GRPCPort() int {
	return p.config.Server.GRPCPort
}

// HTTPPort returns the configured HTTP port.
func (p *Provider) HTTPPort() int {
	return p.config.Server.HTTPPort
}

// TrustDomain returns the configured trust domain
func (p *Provider) TrustDomain() string {
	return p.config.TrustDomain
}

// HTTPTransport returns an HTTP RoundTripper configured with fixtures if available
// Returns nil if no special transport is needed (caller should use http.DefaultTransport)
func (p *Provider) HTTPTransport() http.RoundTripper {
	fixtureProvider := p.HTTPFixtureProvider()
	if fixtureProvider == nil {
		return nil
	}
	return httpfixture.NewTransport(httpfixture.TransportConfig{
		Provider: fixtureProvider,
		Strict:   true,
	})
}

// HTTPFixtureProvider returns the fixture provider for hermetic testing
// Returns nil if no fixtures are configured (normal production mode)
func (p *Provider) HTTPFixtureProvider() httpfixture.FixtureProvider {
	if p.httpFixtureBuilt {
		return p.httpFixtureProvider
	}

	provider, err := BuildHTTPFixtureProvider(p.config.Fixtures, nil)
	if err != nil {
		// In production mode, fixture errors should fail fast
		// This is a configuration error, not a runtime error
		panic(fmt.Sprintf("failed to build HTTP fixture provider: %v", err))
	}

	p.httpFixtureProvider = provider
	p.httpFixtureBuilt = true
	return p.httpFixtureProvider
}

// HTTPClientRegistry returns the HTTP client registry, lazily built from
// configuration. All named clients and the implicit "default" are available.
func (p *Provider) HTTPClientRegistry() (*httpclient.Registry, error) {
	if p.httpClientRegistry != nil {
		return p.httpClientRegistry, nil
	}

	fixtureTransport := p.HTTPTransport()
	registry, err := NewHTTPClientRegistry(p.config.HTTPClients, fixtureTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client registry: %w", err)
	}

	p.httpClientRegistry = registry
	return registry, nil
}

// AuthzCheckPolicy returns the configured authz check policy for ext_authz.
// When the policy section is present, uses its type and token_types.
// Falls back to legacy top-level token_types for backward compatibility.
// Defaults to a StaticAuthenticatedPolicy with the default transaction token
// spec when nothing is configured.
func (p *Provider) AuthzCheckPolicy() (server.AuthzCheckPolicy, error) {
	if p.config.AuthzServer == nil {
		return server.NewStaticAuthenticatedPolicy(nil), nil
	}

	policyCfg := p.config.AuthzServer.Policy

	switch policyCfg.Type {
	case "":
		// Legacy case predating the policy config.
		// In this case, use top level token types and
		// implicitly use the static_authenticated policy.

		// If there is any policy config, though, error. It means type is missing.
		if len(policyCfg.TokenTypes) > 0 {
			return nil, fmt.Errorf("authz_server.policy.type is required when policy section is defined")
		}

		tokenTypes, err := buildTokenTypeSpecs(p.config.AuthzServer.TokenTypes)
		if err != nil {
			return nil, err
		}
		return server.NewStaticAuthenticatedPolicy(tokenTypes), nil
	case "static_authenticated":
		// Prevent ambiguity with legacy fallback path.
		if len(p.config.AuthzServer.TokenTypes) > 0 {
			return nil, fmt.Errorf("authz_server.token_types and authz_server.policy are mutually exclusive; use policy.token_types instead")
		}
		tokenTypes, err := buildTokenTypeSpecs(policyCfg.TokenTypes)
		if err != nil {
			return nil, err
		}
		return server.NewStaticAuthenticatedPolicy(tokenTypes), nil
	default:
		return nil, fmt.Errorf("unknown authz check policy type: %q", policyCfg.Type)
	}
}

// buildTokenTypeSpecs converts config token type entries to server.TokenTypeSpec values.
func buildTokenTypeSpecs(cfgs []TokenTypeConfig) ([]server.TokenTypeSpec, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	specs := make([]server.TokenTypeSpec, 0, len(cfgs))
	for _, ttCfg := range cfgs {
		if ttCfg.Type == "" {
			return nil, fmt.Errorf("token type is required")
		}
		if ttCfg.HeaderName == "" {
			return nil, fmt.Errorf("header_name is required for token type %s", ttCfg.Type)
		}
		specs = append(specs, server.TokenTypeSpec{
			Type:       service.TokenType(ttCfg.Type),
			HeaderName: ttCfg.HeaderName,
		})
	}
	return specs, nil
}

// CredentialSources returns the global credential extraction sources shared by
// all extraction paths (ext_authz subject, ext_authz actor, exchange caller).
// Returns DefaultCredentialSources when unset.
func (p *Provider) CredentialSources() (server.CredentialSources, error) {
	if len(p.config.CredentialSources) == 0 {
		return server.DefaultCredentialSources(), nil
	}

	return newCredentialSources(p.config.CredentialSources)
}
