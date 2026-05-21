package server

import (
	"fmt"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// CertCredentialSource extracts client certificate material from an HTTP header
// (for example x-forwarded-client-cert set by Envoy).
type CertCredentialSource struct {
	SourceName string
	Header     string
}

func (s *CertCredentialSource) Extract(req *authv3.CheckRequest) (*CredentialExtraction, error) {
	headers, _, err := httpRequestFromCheck(req)
	if err != nil {
		return nil, err
	}

	header := s.Header
	if header == "" {
		header = "x-forwarded-client-cert"
	}
	header = strings.ToLower(header)

	certHeader := headers[header]
	if certHeader == "" {
		return nil, fmt.Errorf("no certificate header")
	}

	return &CredentialExtraction{
		Credential: &trust.BearerCredential{Token: certHeader},
		Headers:    []string{header},
		SourceType: s.sourceName(),
	}, nil
}

func (s *CertCredentialSource) sourceName() string {
	if s.SourceName != "" {
		return s.SourceName
	}
	return CredentialSourceTypeCert
}
