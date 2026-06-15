package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestCredentialContextFromCheckRequest(t *testing.T) {
	t.Parallel()

	t.Run("extracts headers", func(t *testing.T) {
		t.Parallel()
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"Authorization": "Bearer tok",
							"Cookie":        "a=b",
						},
						Path: "/api/v1/resource",
					},
				},
			},
		}

		tc, err := CredentialContextFromCheckRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tc.Headers["authorization"] != "Bearer tok" {
			t.Errorf("expected lowercase authorization header, got %q", tc.Headers["authorization"])
		}
		if tc.Headers["cookie"] != "a=b" {
			t.Errorf("expected cookie header, got %q", tc.Headers["cookie"])
		}
		if tc.TLSPeer != nil {
			t.Error("expected nil TLSPeer for HTTP check request")
		}
	})

	t.Run("normalizes header keys to lowercase", func(t *testing.T) {
		t.Parallel()
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"X-Custom-Header": "value",
						},
					},
				},
			},
		}

		tc, err := CredentialContextFromCheckRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := tc.Headers["X-Custom-Header"]; ok {
			t.Error("expected original case key to be absent")
		}
		if tc.Headers["x-custom-header"] != "value" {
			t.Errorf("expected lowercase key, got headers: %v", tc.Headers)
		}
	})

	t.Run("returns error for missing HTTP attributes", func(t *testing.T) {
		t.Parallel()
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{},
			},
		}

		_, err := CredentialContextFromCheckRequest(req)
		if err == nil {
			t.Fatal("expected error for missing HTTP attributes")
		}
	})

	t.Run("handles nil headers", func(t *testing.T) {
		t.Parallel()
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Path: "/",
					},
				},
			},
		}

		_, err := CredentialContextFromCheckRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCredentialContextFromGRPC(t *testing.T) {
	t.Parallel()

	t.Run("extracts metadata headers", func(t *testing.T) {
		t.Parallel()
		md := metadata.New(map[string]string{
			"authorization": "Bearer grpc-token",
			"x-custom":      "value",
		})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		tc := CredentialContextFromGRPC(ctx)

		if tc.Headers["authorization"] != "Bearer grpc-token" {
			t.Errorf("expected authorization header, got %q", tc.Headers["authorization"])
		}
		if tc.Headers["x-custom"] != "value" {
			t.Errorf("expected x-custom header, got %q", tc.Headers["x-custom"])
		}
		if tc.TLSPeer != nil {
			t.Error("expected nil TLSPeer without TLS context")
		}
	})

	t.Run("extracts TLS peer certificates", func(t *testing.T) {
		t.Parallel()
		cert := generateSelfSignedCert(t)
		ctx := context.Background()
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert},
				},
			},
		})

		tc := CredentialContextFromGRPC(ctx)

		if tc.TLSPeer == nil {
			t.Fatal("expected TLSPeer to be set")
		}
		if len(tc.TLSPeer.Certificates) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(tc.TLSPeer.Certificates))
		}
		if tc.TLSPeer.Certificates[0] != cert {
			t.Error("expected same certificate reference")
		}
	})

	t.Run("empty context produces empty CredentialContext", func(t *testing.T) {
		t.Parallel()
		tc := CredentialContextFromGRPC(context.Background())

		if tc.Headers != nil {
			t.Errorf("expected nil headers, got %v", tc.Headers)
		}
		if tc.TLSPeer != nil {
			t.Error("expected nil TLSPeer")
		}
	})

	t.Run("peer without TLS does not set TLSPeer", func(t *testing.T) {
		t.Parallel()
		ctx := peer.NewContext(context.Background(), &peer.Peer{})

		tc := CredentialContextFromGRPC(ctx)

		if tc.TLSPeer != nil {
			t.Error("expected nil TLSPeer for non-TLS peer")
		}
	})
}

func generateSelfSignedCert(t *testing.T) *x509.Certificate {
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
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}
