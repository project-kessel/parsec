package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/project-kessel/parsec/internal/trust"
)

// extractActorCredential extracts credentials from the gRPC context
// This identifies the calling actor (e.g., gateway making the request to parsec)
// Returns nil credential and nil error if no actor authentication is present
func extractActorCredential(ctx context.Context) (trust.Credential, error) {
	// 1. Try to extract mTLS certificate from peer
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			// Check if client certificate is present
			if len(tlsInfo.State.PeerCertificates) > 0 {
				clientCert := tlsInfo.State.PeerCertificates[0]

				// Convert certificate to DER encoding
				certDER := clientCert.Raw

				// Build certificate chain
				chain := make([][]byte, len(tlsInfo.State.PeerCertificates)-1)
				for i, cert := range tlsInfo.State.PeerCertificates[1:] {
					chain[i] = cert.Raw
				}

				// Extract issuer identity from certificate
				issuerIdentity := extractIssuerFromCert(clientCert)

				return &trust.MTLSCredential{
					Certificate:    certDER,
					Chain:          chain,
					IssuerIdentity: issuerIdentity,
				}, nil
			}
		}
	}

	// 2. Try to extract bearer token from gRPC metadata as fallback
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
			authHeader := authHeaders[0]
			if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
				return &trust.BearerCredential{
					Token: token,
				}, nil
			}
		}
	}

	// No actor credentials found - this is not an error
	return nil, nil
}

// extractIssuerFromCert extracts an issuer identity from a certificate
// This uses the certificate's issuer DN as the identity
func extractIssuerFromCert(cert *x509.Certificate) string {
	// Use the issuer's Distinguished Name as the identity
	// Format: CN=..., O=..., etc.
	return cert.Issuer.String()
}

// encodeCertToPEM converts a certificate to PEM encoding
// This is a helper function for debugging/logging
//
//nolint:unused // kept for debugging/logging use
func encodeCertToPEM(certDER []byte) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// parseCertFromPEM parses a PEM-encoded certificate
// This is a helper function for testing
//
//nolint:unused // kept for testing use
func parseCertFromPEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
