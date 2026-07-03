package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/project-kessel/parsec/internal/trust"
)

// actorProbe is the subset of observability methods needed by the shared
// actor authentication flow.
type actorProbe interface {
	ActorCredentialExtracted(cred trust.Credential, headersUsed []string)
	ActorCredentialExtractionFailed(err error)
	ActorValidationSucceeded(actor *trust.Result)
	ActorValidationFailed(err error)
}

// authenticateActor extracts and validates an actor credential from the gRPC
// context, emitting probe events along the way. Returns an anonymous result
// when no actor credential is present.
func authenticateActor(ctx context.Context, sources CredentialSources, store trust.Store, p actorProbe) (*trust.Result, error) {
	result, _, err := authenticateActorWithExtraction(ctx, sources, store, p)
	return result, err
}

// authenticateActorWithExtraction works like authenticateActor but also returns
// the CredentialExtraction (nil when the actor is anonymous). This allows
// callers to build a Principal with credential metadata.
func authenticateActorWithExtraction(ctx context.Context, sources CredentialSources, store trust.Store, p actorProbe) (*trust.Result, *CredentialExtraction, error) {
	ext, err := extractActorCredential(ctx, sources)
	if err != nil {
		p.ActorCredentialExtractionFailed(err)
		return nil, nil, fmt.Errorf("failed to extract actor credential: %w", err)
	}

	if ext != nil {
		p.ActorCredentialExtracted(ext.Credential, ext.HeadersUsed)
		actor, validationErr := store.Validate(ctx, ext.Credential)
		if validationErr != nil {
			p.ActorValidationFailed(validationErr)
			return nil, nil, fmt.Errorf("actor validation failed: %w", validationErr)
		}
		p.ActorValidationSucceeded(actor)
		return actor, ext, nil
	}

	actor := trust.AnonymousResult()
	p.ActorValidationSucceeded(actor)
	return actor, nil, nil
}

// extractActorCredential extracts an actor credential from the gRPC context.
//
// It first checks for mTLS peer certificates (returned directly as an
// MTLSCredential since there is no MTLSCredentialSource yet). If no TLS
// client cert is present, it builds a CredentialContext and runs through
// the configured CredentialSource chain.
//
// Returns (nil, nil) if no actor authentication is present.
func extractActorCredential(ctx context.Context, sources CredentialSources) (*CredentialExtraction, error) {
	cc, err := CredentialContextFromGRPC(ctx)
	if err != nil {
		return nil, err
	}

	// mTLS takes priority. A future MTLSCredentialSource can replace this
	// once the interface supports TLS peer info natively.
	if cc.TLSPeer != nil && len(cc.TLSPeer.Certificates) > 0 {
		return mtlsExtractionFromPeer(cc.TLSPeer), nil
	}

	return sources.Extract(ctx, cc)
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
