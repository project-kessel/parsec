package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/project-kessel/parsec/internal/httpclient"
)

const defaultHTTPClientTimeout = 30 * time.Second

// NewHTTPClientRegistry creates an HTTP client registry from configuration.
// If no config entry has name "default", a stock default client is auto-created
// (30s timeout, no auth, no cert source).
func NewHTTPClientRegistry(cfgs []HTTPClientConfig, fixtureTransport http.RoundTripper, opts ...httpclient.RegistryOption) (*httpclient.Registry, error) {
	registry := httpclient.NewRegistry(fixtureTransport, opts...)

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

// resolveHTTPClient resolves a consumer's HTTP client from the registry for Lua
// scripts (client plus optional base URL).
func resolveHTTPClient(httpClientName string, httpClientSpec *HTTPClientSpec, registry *httpclient.Registry) (httpclient.LuaClient, error) {
	if registry == nil {
		return httpclient.LuaClient{}, fmt.Errorf("http client registry is required but was not configured")
	}

	if httpClientName != "" && httpClientSpec != nil {
		return httpclient.LuaClient{}, fmt.Errorf("http_client and http are mutually exclusive; use http for an inline client")
	}

	if httpClientSpec != nil {
		spec, err := resolveClientSpec(*httpClientSpec)
		if err != nil {
			return httpclient.LuaClient{}, fmt.Errorf("inline http client spec: %w", err)
		}
		return registry.BuildLua(spec)
	}

	name := httpclient.ClientName(httpClientName)
	if name == "" {
		name = "default"
	}
	return registry.GetLua(name)
}

// resolveClientSpec converts an HTTPClientSpec (config layer) into an
// httpclient.ClientSpec (runtime layer): parses durations, builds CertSource,
// and constructs TransportMiddleware from auth config.
func resolveClientSpec(cfg HTTPClientSpec) (httpclient.ClientSpec, error) {
	var spec httpclient.ClientSpec

	if cfg.BaseURL != "" {
		parsed, err := url.Parse(cfg.BaseURL)
		if err != nil {
			return spec, fmt.Errorf("invalid base_url %q: %w", cfg.BaseURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return spec, fmt.Errorf("invalid base_url %q: must include scheme and host", cfg.BaseURL)
		}
		spec.BaseURL = cfg.BaseURL
	}

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

	spec.RootCAPath = cfg.CACert

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
	case "headers":
		resolved, err := resolveHeaders(cfg.Headers)
		if err != nil {
			return nil, err
		}
		return func(base http.RoundTripper) http.RoundTripper {
			return &httpclient.HeadersTransport{Headers: resolved, Base: base}
		}, nil
	default:
		return nil, fmt.Errorf("unknown http_auth type: %q (supported: bearer, headers)", cfg.Type)
	}
}

func resolveHeaders(headers map[string]any) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, fmt.Errorf("http_auth[headers]: at least one header is required")
	}
	resolved, err := resolveConfigValues(headers)
	if err != nil {
		return nil, fmt.Errorf("http_auth[headers]: %w", err)
	}
	result := make(map[string]string, len(resolved))
	for k, v := range resolved {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("http_auth[headers]: header %q must resolve to a string", k)
		}
		result[k] = s
	}
	return result, nil
}

func resolveConfigValues(m map[string]any) (map[string]any, error) {
	if m == nil {
		return nil, nil
	}
	resolved := make(map[string]any, len(m))
	for key, val := range m {
		sub, ok := val.(map[string]any)
		if ok {
			if envName, hasEnv := sub["env"]; hasEnv {
				name, ok := envName.(string)
				if !ok {
					return nil, fmt.Errorf("config key %q: env must be a string", key)
				}
				v := os.Getenv(name)
				if v == "" {
					return nil, fmt.Errorf("config key %q: env var %q is empty or not set", key, name)
				}
				resolved[key] = v
				continue
			}
		}
		resolved[key] = val
	}
	return resolved, nil
}
