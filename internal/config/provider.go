package config

import (
	"fmt"
	"net/http"

	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// Provider constructs all application components from configuration
// This is the main entry point for building a configured parsec instance
type Provider struct {
	config *Config

	// Lazily constructed components (cached after first call)
	trustStore           trust.Store
	dataSourceRegistry   *service.DataSourceRegistry
	issuerRegistry       service.Registry
	claimsFilterRegistry server.ClaimsFilterRegistry
	tokenService         *service.TokenService
	httpFixtureProvider  httpfixture.FixtureProvider
	httpFixtureBuilt     bool
	observer             service.ApplicationObserver
}

// NewProvider creates a new provider from configuration
func NewProvider(config *Config) *Provider {
	return &Provider{
		config: config,
	}
}

// SetObserver sets the application observer for all components built by this provider.
// Must be called before TokenService() or any method that depends on the observer.
func (p *Provider) SetObserver(observer service.ApplicationObserver) {
	p.observer = observer
}

// Observer returns the configured application observer.
// If SetObserver was called, returns that observer.
// Otherwise, creates a default observer from config.
func (p *Provider) Observer() (service.ApplicationObserver, error) {
	if p.observer != nil {
		return p.observer, nil
	}

	// Build from config (fallback when SetObserver was not called)
	observer, err := NewObserver(p.config.Observability)
	if err != nil {
		return nil, fmt.Errorf("failed to create observer: %w", err)
	}

	p.observer = observer
	return observer, nil
}

// TrustStore returns the configured trust store
func (p *Provider) TrustStore() (trust.Store, error) {
	if p.trustStore != nil {
		return p.trustStore, nil
	}

	transport := p.HTTPTransport()
	store, err := NewTrustStore(p.config.TrustStore, transport)
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

	transport := p.HTTPTransport()
	registry, err := NewDataSourceRegistry(p.config.DataSources, transport)
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

	registry, err := NewIssuerRegistry(*p.config)
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

	// Get observer
	observer, err := p.Observer()
	if err != nil {
		return nil, fmt.Errorf("failed to get observer: %w", err)
	}

	// Create token service
	tokenService := service.NewTokenService(
		p.config.TrustDomain,
		dataSourceRegistry,
		issuerRegistry,
		observer, // Application observer for observability
	)

	p.tokenService = tokenService
	return tokenService, nil
}

// ServerConfig returns the server configuration
func (p *Provider) ServerConfig() server.Config {
	return server.Config{
		GRPCPort: p.config.Server.GRPCPort,
		HTTPPort: p.config.Server.HTTPPort,
	}
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

// AuthzServerTokenTypes returns the configured token types for ext_authz
func (p *Provider) AuthzServerTokenTypes() ([]server.TokenTypeSpec, error) {
	// If no authz server config, return nil (will use defaults)
	if p.config.AuthzServer == nil || len(p.config.AuthzServer.TokenTypes) == 0 {
		return nil, nil
	}

	var tokenTypes []server.TokenTypeSpec
	for _, ttCfg := range p.config.AuthzServer.TokenTypes {
		if ttCfg.Type == "" {
			return nil, fmt.Errorf("token type is required")
		}

		if ttCfg.HeaderName == "" {
			return nil, fmt.Errorf("header_name is required for token type %s", ttCfg.Type)
		}

		// Use token type directly as service.TokenType (it's already a URN string)
		tokenTypes = append(tokenTypes, server.TokenTypeSpec{
			Type:       service.TokenType(ttCfg.Type),
			HeaderName: ttCfg.HeaderName,
		})
	}

	return tokenTypes, nil
}
