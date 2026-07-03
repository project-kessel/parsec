package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// BearerCredentialSource extracts a bearer token from the Authorization header.
type BearerCredentialSource struct {
	SourceName string
}

// NewBearerCredentialSource returns a BearerCredentialSource with the given
// name. The name is required.
func NewBearerCredentialSource(name string) (*BearerCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("bearer credential source: name is required")
	}
	return &BearerCredentialSource{SourceName: name}, nil
}

func (s *BearerCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	authHeader := cc.Headers["authorization"]
	if authHeader == "" {
		return nil, nil
	}

	scheme, token, ok := strings.Cut(authHeader, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return nil, fmt.Errorf("unsupported authorization scheme")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("unsupported authorization scheme")
	}

	return &CredentialExtraction{
		Credential:  &trust.BearerCredential{Token: token},
		HeadersUsed: []string{"authorization"},
		SourceName:  s.SourceName,
	}, nil
}
