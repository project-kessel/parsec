// Package httpclient provides a named HTTP client registry and factory.
//
// Clients are configured once (via [ClientSpec]) and built by the [Registry],
// which applies global concerns (fixture transports, shared default transport)
// consistently to every client it produces — whether named or inline.
//
// The package does not define a new interface for consuming HTTP; it produces
// standard [*http.Client] instances.
package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"
)

// ClientName identifies a named HTTP client in configuration.
type ClientName string

// TransportMiddleware wraps a base RoundTripper, returning a decorated one.
// Used to compose concerns like authentication atop a resolved base transport.
type TransportMiddleware func(base http.RoundTripper) http.RoundTripper

// ClientSpec holds resolved parameters for building an [*http.Client].
// It is the runtime equivalent of the configuration-level HTTPClientSpec,
// with durations parsed and abstractions instantiated.
type ClientSpec struct {
	Timeout             time.Duration
	CertSource          CertSource          // nil = share default transport
	TransportMiddleware TransportMiddleware // nil = no wrapping
	RootCAPath          string              // PEM-encoded CA cert file to trust; empty = system roots
	BaseURL             string              // optional origin for relative Lua URLs; empty = none
}

// RegistryOption configures optional parameters for [NewRegistry].
type RegistryOption func(*registryConfig)

type registryConfig struct {
	observer HTTPClientObserver
}

// WithObserver sets the observer used to instrument outbound HTTP requests.
// If not provided, no instrumentation is applied.
func WithObserver(obs HTTPClientObserver) RegistryOption {
	return func(c *registryConfig) {
		if obs != nil {
			c.observer = obs
		}
	}
}

func resolveRegistryConfig(opts []RegistryOption) registryConfig {
	var c registryConfig
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Registry builds, stores, and provides named HTTP clients.
// It is also the factory for inline (anonymous) clients, ensuring
// global concerns like fixture transports are applied uniformly.
type Registry struct {
	clients          map[ClientName]registeredClient
	fixtureTransport http.RoundTripper  // nil in production
	observer         HTTPClientObserver // nil = no instrumentation
}

type registeredClient struct {
	client  *http.Client
	baseURL string
}

// NewRegistry creates a Registry. If fixtureTransport is non-nil, it overrides
// the base transport for every client built by this registry (hermetic mode).
func NewRegistry(fixtureTransport http.RoundTripper, opts ...RegistryOption) *Registry {
	cfg := resolveRegistryConfig(opts)
	return &Registry{
		clients:          make(map[ClientName]registeredClient),
		fixtureTransport: fixtureTransport,
		observer:         cfg.observer,
	}
}

// Register builds a client from spec, stores it by name, and returns it.
// Returns an error if the name is already registered or the spec is invalid.
func (r *Registry) Register(name ClientName, spec ClientSpec) (*http.Client, error) {
	if _, exists := r.clients[name]; exists {
		return nil, fmt.Errorf("httpclient: client %q already registered", name)
	}

	client, err := r.build(string(name), spec)
	if err != nil {
		return nil, fmt.Errorf("httpclient: failed to build client %q: %w", name, err)
	}

	r.clients[name] = registeredClient{client: client, baseURL: spec.BaseURL}
	return client, nil
}

// Get retrieves a named client. Returns an error if not found.
func (r *Registry) Get(name ClientName) (*http.Client, error) {
	rc, ok := r.clients[name]
	if !ok {
		return nil, fmt.Errorf("httpclient: client %q not found", name)
	}
	return rc.client, nil
}

// BaseURL returns the configured base URL for a named client.
// An empty string means no base was set. Returns an error if the name is unknown.
func (r *Registry) BaseURL(name ClientName) (string, error) {
	rc, ok := r.clients[name]
	if !ok {
		return "", fmt.Errorf("httpclient: client %q not found", name)
	}
	return rc.baseURL, nil
}

// Build creates an anonymous [*http.Client] from the given spec, applying
// all global concerns (fixture transport, etc.). The client is NOT stored
// in the registry. Use this for inline-defined clients.
func (r *Registry) Build(spec ClientSpec) (*http.Client, error) {
	return r.build("", spec)
}

func (r *Registry) build(clientName string, spec ClientSpec) (*http.Client, error) {
	// 1. Determine base transport
	var base http.RoundTripper

	if r.fixtureTransport != nil {
		// Hermetic mode: fixture transport overrides everything
		base = r.fixtureTransport
	} else if spec.CertSource != nil || spec.RootCAPath != "" {
		// Clone the default transport so we keep standard behavior
		// (proxy handling, HTTP/2, idle connection reuse, timeouts)
		// and customize TLS settings.
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		if customTransport.TLSClientConfig == nil {
			customTransport.TLSClientConfig = &tls.Config{}
		}
		if spec.CertSource != nil {
			customTransport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := spec.CertSource.Certificate()
				if err != nil {
					return nil, err
				}
				return &cert, nil
			}
		}
		if spec.RootCAPath != "" {
			pem, err := os.ReadFile(spec.RootCAPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert %q: %w", spec.RootCAPath, err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("failed to parse CA cert from %q", spec.RootCAPath)
			}
			customTransport.TLSClientConfig.RootCAs = pool
		}
		base = customTransport
	} else {
		base = http.DefaultTransport
	}

	// 2. Apply transport middleware (e.g. auth)
	transport := base
	if spec.TransportMiddleware != nil {
		transport = spec.TransportMiddleware(base)
	}

	// 3. Apply metrics instrumentation (outermost layer so it captures
	//    the full round-trip including any middleware overhead).
	if r.observer != nil {
		transport = &instrumentedTransport{
			base:       transport,
			observer:   r.observer,
			clientName: clientName,
		}
	}

	return &http.Client{
		Timeout:   spec.Timeout,
		Transport: transport,
	}, nil
}

// instrumentedTransport wraps a base [http.RoundTripper] and records metrics
// for each request via the [HTTPClientObserver].
type instrumentedTransport struct {
	base       http.RoundTripper
	observer   HTTPClientObserver
	clientName string
}

// RoundTrip implements [http.RoundTripper].
func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, probe := t.observer.RequestStarted(req.Context(), t.clientName, req.Method, req.URL.Host)

	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			probe.ConnectionReused(info.Reused)
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)

	defer probe.End()

	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		probe.Error(err)
		return nil, err
	}

	probe.StatusCode(resp.StatusCode)
	probe.ProtocolVersion(resp.Proto)
	return resp, nil
}

// BearerTransport injects a static Authorization: Bearer header into every request.
type BearerTransport struct {
	Token string
	Base  http.RoundTripper
}

// RoundTrip implements [http.RoundTripper].
func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.Token)
	return t.Base.RoundTrip(clone)
}

// HeadersTransport injects a fixed set of headers into every request.
type HeadersTransport struct {
	Headers map[string]string
	Base    http.RoundTripper
}

// RoundTrip implements [http.RoundTripper].
func (t *HeadersTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.Headers {
		clone.Header.Set(k, v)
	}
	return t.Base.RoundTrip(clone)
}
