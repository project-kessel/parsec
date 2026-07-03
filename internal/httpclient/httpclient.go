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
	"fmt"
	"net/http"
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
}

// Registry builds, stores, and provides named HTTP clients.
// It is also the factory for inline (anonymous) clients, ensuring
// global concerns like fixture transports are applied uniformly.
type Registry struct {
	clients          map[ClientName]*http.Client
	fixtureTransport http.RoundTripper // nil in production
}

// NewRegistry creates a Registry. If fixtureTransport is non-nil, it overrides
// the base transport for every client built by this registry (hermetic mode).
func NewRegistry(fixtureTransport http.RoundTripper) *Registry {
	return &Registry{
		clients:          make(map[ClientName]*http.Client),
		fixtureTransport: fixtureTransport,
	}
}

// Register builds a client from spec, stores it by name, and returns it.
// Returns an error if the name is already registered or the spec is invalid.
func (r *Registry) Register(name ClientName, spec ClientSpec) (*http.Client, error) {
	if _, exists := r.clients[name]; exists {
		return nil, fmt.Errorf("httpclient: client %q already registered", name)
	}

	client, err := r.build(spec)
	if err != nil {
		return nil, fmt.Errorf("httpclient: failed to build client %q: %w", name, err)
	}

	r.clients[name] = client
	return client, nil
}

// Get retrieves a named client. Returns an error if not found.
func (r *Registry) Get(name ClientName) (*http.Client, error) {
	client, ok := r.clients[name]
	if !ok {
		return nil, fmt.Errorf("httpclient: client %q not found", name)
	}
	return client, nil
}

// Build creates an anonymous [*http.Client] from the given spec, applying
// all global concerns (fixture transport, etc.). The client is NOT stored
// in the registry. Use this for inline-defined clients.
func (r *Registry) Build(spec ClientSpec) (*http.Client, error) {
	return r.build(spec)
}

func (r *Registry) build(spec ClientSpec) (*http.Client, error) {
	// 1. Determine base transport
	var base http.RoundTripper

	if r.fixtureTransport != nil {
		// Hermetic mode: fixture transport overrides everything
		base = r.fixtureTransport
	} else if spec.CertSource != nil {
		// mTLS: clone the default transport so we keep standard behavior
		// (proxy handling, HTTP/2, idle connection reuse, timeouts) and
		// only add the client-certificate callback.
		mtlsTransport := http.DefaultTransport.(*http.Transport).Clone()
		mtlsTransport.TLSClientConfig = &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := spec.CertSource.Certificate()
				if err != nil {
					return nil, err
				}
				return &cert, nil
			},
		}
		base = mtlsTransport
	} else {
		base = http.DefaultTransport
	}

	// 2. Apply transport middleware (e.g. auth)
	transport := base
	if spec.TransportMiddleware != nil {
		transport = spec.TransportMiddleware(base)
	}

	return &http.Client{
		Timeout:   spec.Timeout,
		Transport: transport,
	}, nil
}

// BearerTransport injects a static Authorization: Bearer header into every request.
type BearerTransport struct {
	Token string
	Base  http.RoundTripper
}

// RoundTrip implements [http.RoundTripper].
func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the caller's request
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.Token)
	return t.Base.RoundTrip(clone)
}
