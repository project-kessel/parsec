package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpclient"
)

func TestNewHTTPClientRegistry_DefaultClientAutoCreated(t *testing.T) {
	registry, err := NewHTTPClientRegistry(nil, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, err := registry.Get("default")
	if err != nil {
		t.Fatalf("Get(default) error: %v", err)
	}

	if client.Timeout != defaultHTTPClientTimeout {
		t.Errorf("default client timeout = %v, want %v", client.Timeout, defaultHTTPClientTimeout)
	}
}

func TestNewHTTPClientRegistry_ExplicitDefault(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{
			Name:           "default",
			HTTPClientSpec: HTTPClientSpec{Timeout: "15s"},
		},
	}

	registry, err := NewHTTPClientRegistry(cfgs, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, err := registry.Get("default")
	if err != nil {
		t.Fatalf("Get(default) error: %v", err)
	}

	if client.Timeout != 15*time.Second {
		t.Errorf("default client timeout = %v, want %v", client.Timeout, 15*time.Second)
	}
}

func TestNewHTTPClientRegistry_NamedClient(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{
			Name: "api",
			HTTPClientSpec: HTTPClientSpec{
				Timeout: "10s",
				HTTPAuth: &HTTPAuthConfig{
					Type:  "bearer",
					Token: "my-token",
				},
			},
		},
	}

	registry, err := NewHTTPClientRegistry(cfgs, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, err := registry.Get("api")
	if err != nil {
		t.Fatalf("Get(api) error: %v", err)
	}

	if client.Timeout != 10*time.Second {
		t.Errorf("client timeout = %v, want %v", client.Timeout, 10*time.Second)
	}

	// The transport should be a BearerTransport wrapping DefaultTransport
	bt, ok := client.Transport.(*httpclient.BearerTransport)
	if !ok {
		t.Fatalf("transport type = %T, want *httpclient.BearerTransport", client.Transport)
	}
	if bt.Token != "my-token" {
		t.Errorf("token = %q, want %q", bt.Token, "my-token")
	}
}

func TestNewHTTPClientRegistry_MissingNameErrors(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{HTTPClientSpec: HTTPClientSpec{Timeout: "5s"}},
	}

	_, err := NewHTTPClientRegistry(cfgs, nil)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestNewHTTPClientRegistry_InvalidTimeoutErrors(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{Name: "bad", HTTPClientSpec: HTTPClientSpec{Timeout: "not-a-duration"}},
	}

	_, err := NewHTTPClientRegistry(cfgs, nil)
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestNewHTTPClientRegistry_InvalidAuthTypeErrors(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{
			Name: "bad-auth",
			HTTPClientSpec: HTTPClientSpec{
				HTTPAuth: &HTTPAuthConfig{Type: "unknown"},
			},
		},
	}

	_, err := NewHTTPClientRegistry(cfgs, nil)
	if err == nil {
		t.Fatal("expected error for unknown auth type")
	}
}

func TestNewHTTPClientRegistry_FixtureTransportApplied(t *testing.T) {
	var called bool
	fixture := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	registry, err := NewHTTPClientRegistry(nil, fixture)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, _ := registry.Get("default")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if !called {
		t.Error("fixture transport was not used for default client")
	}
}

func TestResolveHTTPClient_ByName(t *testing.T) {
	registry, _ := NewHTTPClientRegistry([]HTTPClientConfig{
		{Name: "named", HTTPClientSpec: HTTPClientSpec{Timeout: "3s"}},
	}, nil)

	client, err := resolveHTTPClient("named", nil, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", client.Timeout)
	}
}

func TestResolveHTTPClient_Inline(t *testing.T) {
	registry, _ := NewHTTPClientRegistry(nil, nil)

	spec := &HTTPClientSpec{Timeout: "7s"}
	client, err := resolveHTTPClient("", spec, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	if client.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", client.Timeout)
	}
}

func TestResolveHTTPClient_DefaultFallback(t *testing.T) {
	registry, _ := NewHTTPClientRegistry(nil, nil)

	client, err := resolveHTTPClient("", nil, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	if client.Timeout != defaultHTTPClientTimeout {
		t.Errorf("timeout = %v, want %v", client.Timeout, defaultHTTPClientTimeout)
	}
}

func TestResolveHTTPClient_NameAndSpecMutuallyExclusive(t *testing.T) {
	registry, _ := NewHTTPClientRegistry([]HTTPClientConfig{
		{Name: "named", HTTPClientSpec: HTTPClientSpec{Timeout: "99s"}},
	}, nil)

	spec := &HTTPClientSpec{Timeout: "1s"}
	_, err := resolveHTTPClient("named", spec, registry)
	if err == nil {
		t.Fatal("expected error when both http_client and an inline http spec are set")
	}
}

func TestResolveHTTPClient_NilRegistryErrors(t *testing.T) {
	if _, err := resolveHTTPClient("", nil, nil); err == nil {
		t.Fatal("expected error for nil registry when resolving by name")
	}

	spec := &HTTPClientSpec{Timeout: "5s"}
	if _, err := resolveHTTPClient("", spec, nil); err == nil {
		t.Fatal("expected error for nil registry when resolving inline spec")
	}
}

func TestResolveHTTPClient_InlineGetsFixtureTransport(t *testing.T) {
	var called bool
	fixture := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	registry, _ := NewHTTPClientRegistry(nil, fixture)

	spec := &HTTPClientSpec{Timeout: "5s"}
	client, err := resolveHTTPClient("", spec, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if !called {
		t.Error("fixture transport should be applied to inline clients")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBuildCertSource_File_MissingCertPathErrors(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := generateSelfSignedCert(t, dir)

	_, err := buildCertSource(CertSourceConfig{
		Type: "file",
		Cert: filepath.Join(dir, "does-not-exist.pem"),
		Key:  keyPath,
	})
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestBuildCertSource_File_MissingKeyPathErrors(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := generateSelfSignedCert(t, dir)

	_, err := buildCertSource(CertSourceConfig{
		Type: "file",
		Cert: certPath,
		Key:  filepath.Join(dir, "does-not-exist.pem"),
	})
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestBuildCertSource_File_MismatchedPairErrors(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	certPath, _ := generateSelfSignedCert(t, dir1)
	_, keyPath := generateSelfSignedCert(t, dir2)

	_, err := buildCertSource(CertSourceConfig{
		Type: "file",
		Cert: certPath,
		Key:  keyPath,
	})
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
}

func TestBuildCertSource_File_ValidPairSucceeds(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)

	cs, err := buildCertSource(CertSourceConfig{
		Type: "file",
		Cert: certPath,
		Key:  keyPath,
	})
	if err != nil {
		t.Fatalf("buildCertSource() error: %v", err)
	}
	if cs == nil {
		t.Fatal("expected non-nil CertSource")
	}
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
