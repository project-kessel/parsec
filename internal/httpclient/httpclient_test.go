package httpclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBearerTransport_InjectsAuthHeader(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bt := &BearerTransport{
		Token: "my-secret-token",
		Base:  http.DefaultTransport,
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if capturedAuth != "Bearer my-secret-token" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer my-secret-token")
	}
}

func TestHeadersTransport_InjectsHeaders(t *testing.T) {
	var capturedClientID, capturedToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClientID = r.Header.Get("x-rh-clientid")
		capturedToken = r.Header.Get("x-rh-apitoken")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ht := &HeadersTransport{
		Headers: map[string]string{
			"x-rh-clientid": "my-client-id",
			"x-rh-apitoken": "my-api-token",
		},
		Base: http.DefaultTransport,
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := ht.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if capturedClientID != "my-client-id" {
		t.Errorf("x-rh-clientid = %q, want %q", capturedClientID, "my-client-id")
	}
	if capturedToken != "my-api-token" {
		t.Errorf("x-rh-apitoken = %q, want %q", capturedToken, "my-api-token")
	}
}

func TestHeadersTransport_DoesNotMutateOriginalRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ht := &HeadersTransport{
		Headers: map[string]string{"x-rh-apitoken": "secret"},
		Base:    http.DefaultTransport,
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	req.Header.Set("X-Original", "keep-me")

	resp, err := ht.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if req.Header.Get("x-rh-apitoken") != "" {
		t.Error("original request should not have injected headers")
	}
	if req.Header.Get("X-Original") != "keep-me" {
		t.Error("original request headers should be preserved")
	}
}

func TestRegistry_RootCAPathLoadsCA(t *testing.T) {
	certDir := t.TempDir()
	certPath, _ := generateSelfSignedCert(t, certDir)

	r := NewRegistry(nil)
	client, err := r.Build(ClientSpec{
		Timeout:    5 * time.Second,
		RootCAPath: certPath,
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected TLSClientConfig.RootCAs to be set")
	}
}

func TestRegistry_RootCAPathMissingFileErrors(t *testing.T) {
	r := NewRegistry(nil)
	_, err := r.Build(ClientSpec{
		Timeout:    5 * time.Second,
		RootCAPath: filepath.Join(t.TempDir(), "does-not-exist.pem"),
	})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestRegistry_EmptyRootCAPathUsesDefaultTransport(t *testing.T) {
	r := NewRegistry(nil)
	client, err := r.Build(ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if client.Transport != http.DefaultTransport {
		t.Error("empty RootCAPath should share http.DefaultTransport")
	}
}

func TestBearerTransport_DoesNotMutateOriginalRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bt := &BearerTransport{
		Token: "secret",
		Base:  http.DefaultTransport,
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	req.Header.Set("X-Original", "keep-me")

	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if req.Header.Get("Authorization") != "" {
		t.Error("original request should not have Authorization header")
	}
	if req.Header.Get("X-Original") != "keep-me" {
		t.Error("original request headers should be preserved")
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry(nil)

	spec := ClientSpec{Timeout: 10 * time.Second}
	client, err := r.Register("my-client", spec)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if client.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want %v", client.Timeout, 10*time.Second)
	}

	got, err := r.Get("my-client")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != client {
		t.Error("Get returned a different client instance")
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	r := NewRegistry(nil)

	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent client")
	}
}

func TestRegistry_StoresBaseURL(t *testing.T) {
	r := NewRegistry(nil)

	_, err := r.Register("entitlements", ClientSpec{
		Timeout: 5 * time.Second,
		BaseURL: "https://entitlements.example",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got, err := r.BaseURL("entitlements")
	if err != nil {
		t.Fatalf("BaseURL failed: %v", err)
	}
	if got != "https://entitlements.example" {
		t.Errorf("BaseURL = %q, want %q", got, "https://entitlements.example")
	}
}

func TestRegistry_BaseURLUnset(t *testing.T) {
	r := NewRegistry(nil)

	_, err := r.Register("plain", ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got, err := r.BaseURL("plain")
	if err != nil {
		t.Fatalf("BaseURL failed: %v", err)
	}
	if got != "" {
		t.Errorf("BaseURL = %q, want empty", got)
	}
}

func TestRegistry_BaseURLNotFound(t *testing.T) {
	r := NewRegistry(nil)

	if _, err := r.BaseURL("missing"); err == nil {
		t.Fatal("expected error for nonexistent client")
	}
}

func TestRegistry_DuplicateRegisterErrors(t *testing.T) {
	r := NewRegistry(nil)

	spec := ClientSpec{Timeout: 5 * time.Second}
	_, err := r.Register("dup", spec)
	if err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	_, err = r.Register("dup", spec)
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestRegistry_Build_Anonymous(t *testing.T) {
	r := NewRegistry(nil)

	spec := ClientSpec{Timeout: 7 * time.Second}
	client, err := r.Build(spec)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if client.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v, want %v", client.Timeout, 7*time.Second)
	}

	// Anonymous clients are not stored
	_, err = r.Get("anonymous")
	if err == nil {
		t.Error("anonymous clients should not be retrievable")
	}
}

func TestRegistry_FixtureTransportOverridesBase(t *testing.T) {
	var transportUsed bool
	fixtureTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		transportUsed = true
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	r := NewRegistry(fixtureTransport)
	spec := ClientSpec{Timeout: 5 * time.Second}
	client, err := r.Register("fixture-test", spec)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if !transportUsed {
		t.Error("fixture transport was not used")
	}
}

func TestRegistry_FixtureTransportWithMiddleware(t *testing.T) {
	var capturedAuth string
	fixtureTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedAuth = req.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	r := NewRegistry(fixtureTransport)
	spec := ClientSpec{
		Timeout: 5 * time.Second,
		TransportMiddleware: func(base http.RoundTripper) http.RoundTripper {
			return &BearerTransport{Token: "fixture-token", Base: base}
		},
	}

	client, err := r.Build(spec)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if capturedAuth != "Bearer fixture-token" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer fixture-token")
	}
}

func TestRegistry_CertSourceGetsOwnTransport(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, certDir)

	cs := NewFileCertSource(certPath, keyPath)
	r := NewRegistry(nil)

	spec := ClientSpec{
		Timeout:    5 * time.Second,
		CertSource: cs,
	}

	client, err := r.Build(spec)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// The client should have its own transport (not DefaultTransport)
	if client.Transport == http.DefaultTransport {
		t.Error("client with CertSource should have a dedicated transport")
	}
}

func TestRegistry_CertSourcePreservesDefaultTransportSettings(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, certDir)

	cs := NewFileCertSource(certPath, keyPath)
	r := NewRegistry(nil)

	spec := ClientSpec{
		Timeout:    5 * time.Second,
		CertSource: cs,
	}

	client, err := r.Build(spec)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}

	defaultTransport := http.DefaultTransport.(*http.Transport)
	if transport.Proxy == nil {
		t.Error("expected Proxy to be inherited from http.DefaultTransport, got nil")
	}
	if transport.MaxIdleConns != defaultTransport.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d (inherited from http.DefaultTransport)", transport.MaxIdleConns, defaultTransport.MaxIdleConns)
	}
	if transport.IdleConnTimeout != defaultTransport.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v (inherited from http.DefaultTransport)", transport.IdleConnTimeout, defaultTransport.IdleConnTimeout)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("expected TLSClientConfig.GetClientCertificate to be set")
	}
}

func TestFileCertSource_LoadsCertificate(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, certDir)

	cs := NewFileCertSource(certPath, keyPath)
	cert, err := cs.Certificate()
	if err != nil {
		t.Fatalf("Certificate() error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected non-empty certificate chain")
	}
}

func TestFileCertSource_InvalidPathErrors(t *testing.T) {
	cs := NewFileCertSource("/nonexistent/cert.pem", "/nonexistent/key.pem")
	_, err := cs.Certificate()
	if err == nil {
		t.Fatal("expected error for invalid paths")
	}
}

// roundTripFunc adapts a function to the http.RoundTripper interface.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certFile, _ := os.Create(certPath)
	_ = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = certFile.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyFile, _ := os.Create(keyPath)
	_ = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	_ = keyFile.Close()

	return certPath, keyPath
}

// Verify CertSource interface compliance
var _ CertSource = (*FileCertSource)(nil)

// Verify RoundTripper interface compliance
var _ http.RoundTripper = (*BearerTransport)(nil)
var _ http.RoundTripper = (*HeadersTransport)(nil)

// Verify that tls.Certificate is returned correctly
func TestFileCertSource_CertificateIsValid(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, certDir)

	cs := NewFileCertSource(certPath, keyPath)
	cert, err := cs.Certificate()
	if err != nil {
		t.Fatalf("Certificate() error: %v", err)
	}

	// Parse the leaf to verify it's a valid certificate
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
	}

	if leaf.Subject.CommonName != "test" {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "test")
	}
}

// Verify that the returned tls.Certificate has a PrivateKey set
func TestFileCertSource_HasPrivateKey(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, certDir)

	cs := NewFileCertSource(certPath, keyPath)
	cert, err := cs.Certificate()
	if err != nil {
		t.Fatalf("Certificate() error: %v", err)
	}

	if cert.PrivateKey == nil {
		t.Error("expected non-nil PrivateKey")
	}

	// Verify it's the right type
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("PrivateKey type = %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
}

// Suppress unused import warning for tls in tests
var _ = tls.Certificate{}

// --- observer integration tests ---

type spyCtxKey struct{}

type spyObserver struct {
	NoOpHTTPClientObserver
	clientName string
	method     string
	host       string
	probe      *spyProbe
	gotCtx     context.Context
}

func (o *spyObserver) RequestStarted(ctx context.Context, clientName, method, host string) (context.Context, RequestProbe) {
	o.clientName = clientName
	o.method = method
	o.host = host
	o.probe = &spyProbe{}
	o.gotCtx = ctx
	return context.WithValue(ctx, spyCtxKey{}, "observed"), o.probe
}

type spyProbe struct {
	NoOpRequestProbe
	statusCode      int
	errored         bool
	ended           bool
	connReusedSet   bool
	connReusedVal   bool
	protocolVersion string
	protoVersionSet bool
}

func (p *spyProbe) StatusCode(code int)          { p.statusCode = code }
func (p *spyProbe) Error(error)                  { p.errored = true }
func (p *spyProbe) ConnectionReused(reused bool) { p.connReusedSet = true; p.connReusedVal = reused }
func (p *spyProbe) ProtocolVersion(proto string) { p.protoVersionSet = true; p.protocolVersion = proto }
func (p *spyProbe) End()                         { p.ended = true }

func TestRegistry_ObserverCalledOnRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	obs := &spyObserver{}
	r := NewRegistry(nil, WithObserver(obs))

	spec := ClientSpec{Timeout: 5 * time.Second}
	client, err := r.Register("my-api", spec)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	resp, err := client.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	_ = resp.Body.Close()

	if obs.clientName != "my-api" {
		t.Errorf("clientName = %q, want %q", obs.clientName, "my-api")
	}
	if obs.method != "GET" {
		t.Errorf("method = %q, want %q", obs.method, "GET")
	}
	if obs.probe == nil {
		t.Fatal("probe was nil")
	}
	if obs.probe.statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", obs.probe.statusCode)
	}
	if obs.probe.errored {
		t.Error("probe errored unexpectedly")
	}
	if !obs.probe.ended {
		t.Error("probe.End() was not called")
	}
}

func TestRegistry_ObserverCalledOnError(t *testing.T) {
	obs := &spyObserver{}
	r := NewRegistry(nil, WithObserver(obs))

	spec := ClientSpec{Timeout: 1 * time.Millisecond}
	client, err := r.Register("failing-client", spec)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Use an invalid URL to trigger a transport error
	_, err = client.Get("http://192.0.2.1:1/does-not-exist")
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}

	if obs.probe == nil {
		t.Fatal("probe was nil")
	}
	if !obs.probe.errored {
		t.Error("probe.Error was not called")
	}
	if !obs.probe.ended {
		t.Error("probe.End() was not called")
	}
}

func TestRegistry_NoObserver_NoInstrumentation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := NewRegistry(nil) // no observer
	client, err := r.Register("plain-client", ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestRegistry_ObserverWithMiddleware(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	obs := &spyObserver{}
	r := NewRegistry(nil, WithObserver(obs))

	spec := ClientSpec{
		Timeout: 5 * time.Second,
		TransportMiddleware: func(base http.RoundTripper) http.RoundTripper {
			return &BearerTransport{Token: "test-token", Base: base}
		},
	}

	client, err := r.Register("authed-client", spec)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	_ = resp.Body.Close()

	// Auth middleware applied
	if capturedAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer test-token")
	}
	// Observer still called
	if obs.probe == nil {
		t.Fatal("probe was nil")
	}
	if obs.probe.statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", obs.probe.statusCode)
	}
}

func TestRegistry_Build_AnonymousObserver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	obs := &spyObserver{}
	r := NewRegistry(nil, WithObserver(obs))

	client, err := r.Build(ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	_ = resp.Body.Close()

	// Anonymous clients have empty client name
	if obs.clientName != "" {
		t.Errorf("clientName = %q, want empty for anonymous client", obs.clientName)
	}
	if obs.probe.statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", obs.probe.statusCode)
	}
}

func TestRegistry_ObserverReportsConnectionReused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	obs := &spyObserver{}
	r := NewRegistry(nil, WithObserver(obs))

	client, err := r.Register("conn-test", ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// First request: connection should be new
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	_ = resp.Body.Close()

	if !obs.probe.connReusedSet {
		t.Fatal("ConnectionReused was not called on first request")
	}
	if obs.probe.connReusedVal {
		t.Error("first request should report connection as new (reused=false)")
	}

	// Second request to same server: connection should be reused
	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	_ = resp.Body.Close()

	if !obs.probe.connReusedSet {
		t.Fatal("ConnectionReused was not called on second request")
	}
	if !obs.probe.connReusedVal {
		t.Error("second request should report connection as reused (reused=true)")
	}
}

func TestRegistry_ObserverReportsProtocolVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	obs := &spyObserver{}
	r := NewRegistry(nil, WithObserver(obs))

	client, err := r.Register("proto-test", ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	_ = resp.Body.Close()

	if !obs.probe.protoVersionSet {
		t.Fatal("ProtocolVersion was not called")
	}
	if obs.probe.protocolVersion != "HTTP/1.1" {
		t.Errorf("protocolVersion = %q, want %q", obs.probe.protocolVersion, "HTTP/1.1")
	}
}

func TestRegistry_ObserverOmitsProtocolVersionOnError(t *testing.T) {
	errTransport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	obs := &spyObserver{}
	r := NewRegistry(errTransport, WithObserver(obs))

	client, err := r.Register("proto-err", ClientSpec{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err = client.Transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error from transport")
	}

	if obs.probe.protoVersionSet {
		t.Error("ProtocolVersion should not be called on transport error")
	}
}

// Verify interface compliance
var _ HTTPClientObserver = NoOpHTTPClientObserver{}
var _ RequestProbe = NoOpRequestProbe{}
