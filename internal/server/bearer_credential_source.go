package server

import (
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// BearerCredentialSource extracts a bearer token from the Authorization header.
type BearerCredentialSource struct {
	SourceName string
}

func (s *BearerCredentialSource) Extract(tc TransportContext) (*CredentialExtraction, error) {
	authHeader := tc.Headers["authorization"]
	if authHeader == "" {
		return nil, nil
	}

	scheme, token, ok := strings.Cut(authHeader, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || token == "" {
		return nil, fmt.Errorf("unsupported authorization scheme")
	}

	return &CredentialExtraction{
		Credential: &trust.BearerCredential{Token: token},
		Headers:    []string{"authorization"},
		SourceName: s.sourceName(),
	}, nil
}

func (s *BearerCredentialSource) sourceName() string {
	if s.SourceName != "" {
		return s.SourceName
	}
	return CredentialSourceTypeBearer
}
