package server

import (
	"fmt"
	"net/url"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// QueryCredentialSource extracts a bearer token from a query parameter.
type QueryCredentialSource struct {
	Param string
}

func (s *QueryCredentialSource) Extract(req *authv3.CheckRequest) (*CredentialExtraction, error) {
	_, path, err := httpRequestFromCheck(req)
	if err != nil {
		return nil, err
	}

	param := s.Param
	if param == "" {
		param = "token"
	}

	if path == "" {
		return nil, fmt.Errorf("no request path")
	}

	parsed, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid request path: %w", err)
	}

	token := parsed.Query().Get(param)
	if token == "" {
		return nil, fmt.Errorf("query parameter %q not found", param)
	}

	return &CredentialExtraction{
		Credential:          &trust.BearerCredential{Token: token},
		QueryParamsToRemove: []string{param},
		SourceType:          "query",
	}, nil
}
