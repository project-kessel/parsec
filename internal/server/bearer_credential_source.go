package server

import (
	"fmt"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// BearerCredentialSource extracts a bearer token from the Authorization header.
type BearerCredentialSource struct {
	SourceName string
}

func (s *BearerCredentialSource) Extract(req *authv3.CheckRequest) (*CredentialExtraction, error) {
	headers, _, err := httpRequestFromCheck(req)
	if err != nil {
		return nil, err
	}

	authHeader := headers["authorization"]
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	scheme, token, ok := strings.Cut(authHeader, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || token == "" {
		return nil, fmt.Errorf("unsupported authorization scheme")
	}

	return &CredentialExtraction{
		Credential: &trust.BearerCredential{Token: token},
		Headers:    []string{"authorization"},
		SourceType: s.sourceName(),
	}, nil
}

func (s *BearerCredentialSource) sourceName() string {
	if s.SourceName != "" {
		return s.SourceName
	}
	return CredentialSourceTypeBearer
}
