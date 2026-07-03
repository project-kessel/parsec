package httpclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
