package server

import (
	"fmt"
	"net/url"

	"github.com/project-kessel/parsec/internal/trust"
)

// QueryCredentialSource extracts a bearer token from a query parameter.
type QueryCredentialSource struct {
	SourceName    string
	ParameterName string
}

func (s *QueryCredentialSource) Extract(cc CredentialContext) (*CredentialExtraction, error) {
	param := s.ParameterName
	if param == "" {
		param = "token"
	}

	if cc.Path == "" {
		return nil, nil
	}

	parsed, err := url.Parse(cc.Path)
	if err != nil {
		return nil, fmt.Errorf("invalid request path: %w", err)
	}

	token := parsed.Query().Get(param)
	if token == "" {
		return nil, nil
	}

	return &CredentialExtraction{
		Credential:          &trust.BearerCredential{Token: token},
		QueryParamsToRemove: []string{param},
		SourceName:          s.sourceName(),
	}, nil
}

func (s *QueryCredentialSource) sourceName() string {
	if s.SourceName != "" {
		return s.SourceName
	}
	return CredentialSourceTypeQuery
}
