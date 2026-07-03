package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/project-kessel/parsec/internal/httpclient"
)

const defaultHTTPClientTimeout = 30 * time.Second

// NewHTTPClientRegistry creates an HTTP client registry from configuration.
// If no config entry has name "default", a stock default client is auto-created
// (30s timeout, no auth, no cert source).
func NewHTTPClientRegistry(cfgs []HTTPClientConfig, fixtureTransport http.RoundTripper) (*httpclient.Registry, error) {
	registry := httpclient.NewRegistry(fixtureTransport)

	hasDefault := false
	for _, cfg := range cfgs {
		if cfg.Name == "" {
			return nil, fmt.Errorf("http_clients: entry missing required name")
		}
		if cfg.Name == "default" {
			hasDefault = true
		}

		spec, err := resolveClientSpec(cfg.HTTPClientSpec)
		if err != nil {
			return nil, fmt.Errorf("http_clients[%s]: %w", cfg.Name, err)
		}

		if _, err := registry.Register(httpclient.ClientName(cfg.Name), spec); err != nil {
			return nil, err
		}
	}

	// Auto-create a stock "default" client when none is configured
	if !hasDefault {
		defaultSpec := httpclient.ClientSpec{Timeout: defaultHTTPClientTimeout}
		if _, err := registry.Register("default", defaultSpec); err != nil {
			return nil, fmt.Errorf("http_clients: failed to register default client: %w", err)
		}
	}

	return registry, nil
}

// resolveHTTPClient resolves a consumer's HTTP client from the registry.
// Resolution order:
//  1. If httpClientSpec is set, build an inline (anonymous) client via the registry.
//  2. If httpClientName is set, look it up by name.
//  3. Otherwise, resolve "default" from the registry.
//
// httpClientName and httpClientSpec are mutually exclusive: since it's
// ambiguous which the caller intended, that's rejected as a config error
// rather than silently picking one.
func resolveHTTPClient(httpClientName string, httpClientSpec *HTTPClientSpec, registry *httpclient.Registry) (*http.Client, error) {
	if registry == nil {
		return nil, fmt.Errorf("http client registry is required but was not configured")
	}

	if httpClientName != "" && httpClientSpec != nil {
		return nil, fmt.Errorf("http_client and http are mutually exclusive; use http for an inline client")
	}

	if httpClientSpec != nil {
		spec, err := resolveClientSpec(*httpClientSpec)
		if err != nil {
			return nil, fmt.Errorf("inline http client spec: %w", err)
		}
		return registry.Build(spec)
	}

	name := httpclient.ClientName(httpClientName)
	if name == "" {
		name = "default"
	}
	return registry.Get(name)
}

// resolveClientSpec converts an HTTPClientSpec (config layer) into an
// httpclient.ClientSpec (runtime layer): parses durations, builds CertSource,
// and constructs TransportMiddleware from auth config.
func resolveClientSpec(cfg HTTPClientSpec) (httpclient.ClientSpec, error) {
	var spec httpclient.ClientSpec

	// Parse timeout
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return spec, fmt.Errorf("invalid timeout %q: %w", cfg.Timeout, err)
		}
		spec.Timeout = d
	} else {
		spec.Timeout = defaultHTTPClientTimeout
	}

	// Build CertSource
	if cfg.ClientCertSource != nil {
		cs, err := buildCertSource(*cfg.ClientCertSource)
		if err != nil {
			return spec, err
		}
		spec.CertSource = cs
	}

	// Build TransportMiddleware from HTTP auth
	if cfg.HTTPAuth != nil {
		mw, err := buildTransportMiddleware(*cfg.HTTPAuth)
		if err != nil {
			return spec, err
		}
		spec.TransportMiddleware = mw
	}

	return spec, nil
}

func buildCertSource(cfg CertSourceConfig) (httpclient.CertSource, error) {
	switch cfg.Type {
	case "file":
		if cfg.Cert == "" {
			return nil, fmt.Errorf("client_cert_source[file]: cert path is required")
		}
		if cfg.Key == "" {
			return nil, fmt.Errorf("client_cert_source[file]: key path is required")
		}
		// Load eagerly to fail startup on a missing/mismatched cert-key pair
		// rather than surfacing an opaque failure on the first TLS handshake.
		if _, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key); err != nil {
			return nil, fmt.Errorf("client_cert_source[file]: failed to load cert/key pair (cert=%q, key=%q): %w", cfg.Cert, cfg.Key, err)
		}
		return httpclient.NewFileCertSource(cfg.Cert, cfg.Key), nil
	default:
		return nil, fmt.Errorf("unknown client_cert_source type: %q (supported: file)", cfg.Type)
	}
}

func buildTransportMiddleware(cfg HTTPAuthConfig) (httpclient.TransportMiddleware, error) {
	switch cfg.Type {
	case "bearer":
		if cfg.Token == "" {
			return nil, fmt.Errorf("http_auth[bearer]: token is required")
		}
		return func(base http.RoundTripper) http.RoundTripper {
			return &httpclient.BearerTransport{Token: cfg.Token, Base: base}
		}, nil
	default:
		return nil, fmt.Errorf("unknown http_auth type: %q (supported: bearer)", cfg.Type)
	}
}
