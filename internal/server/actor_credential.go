package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/project-kessel/parsec/internal/trust"
)

// extractActorCredential extracts an actor credential from the gRPC context.
//
// It first checks for mTLS peer certificates (returned directly as an
// MTLSCredential since there is no MTLSCredentialSource yet). If no TLS
// client cert is present, it builds a CredentialContext and runs through
// the configured CredentialSource chain.
//
// Returns (nil, nil) if no actor authentication is present.
func extractActorCredential(ctx context.Context, sources []CredentialSource) (*CredentialExtraction, error) {
	cc := CredentialContextFromGRPC(ctx)

	// mTLS takes priority. A future MTLSCredentialSource can replace this
	// once the interface supports TLS peer info natively.
	if cc.TLSPeer != nil && len(cc.TLSPeer.Certificates) > 0 {
		return mtlsExtractionFromPeer(cc.TLSPeer), nil
	}

	if cc.Headers == nil {
		return nil, nil
	}

	if len(sources) == 0 {
		sources = defaultActorCredentialSources()
	}

	ext, err := extractCredentialFromSources(cc, sources)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return nil, nil
		}
		return nil, fmt.Errorf("actor credential extraction failed: %w", err)
	}
	return ext, nil
}

// mtlsExtractionFromPeer builds a CredentialExtraction from TLS peer info.
func mtlsExtractionFromPeer(peer *TLSPeerInfo) *CredentialExtraction {
	clientCert := peer.Certificates[0]

	chain := make([][]byte, len(peer.Certificates)-1)
	for i, cert := range peer.Certificates[1:] {
		chain[i] = cert.Raw
	}

	return &CredentialExtraction{
		Credential: &trust.MTLSCredential{
			Certificate:    clientCert.Raw,
			Chain:          chain,
			IssuerIdentity: extractIssuerFromCert(clientCert),
		},
		SourceName: "mtls",
	}
}

func defaultActorCredentialSources() []CredentialSource {
	return []CredentialSource{&BearerCredentialSource{SourceName: "bearer"}}
}

func extractIssuerFromCert(cert *x509.Certificate) string {
	return cert.Issuer.String()
}

//nolint:unused // kept for debugging/logging use
func encodeCertToPEM(certDER []byte) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

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
