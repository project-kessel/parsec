package server

import (
	"fmt"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// Credential source type strings used in config.
const (
	CredentialSourceTypeBearer = "bearer"
	CredentialSourceTypeCookie = "cookie"
	CredentialSourceTypeCert   = "cert"
	CredentialSourceTypeQuery  = "query"
)

// CredentialSource extracts a subject credential from an ext_authz CheckRequest.
type CredentialSource interface {
	Extract(req *authv3.CheckRequest) (*CredentialExtraction, error)
}

// CredentialExtraction is the result of extracting a credential from a request.
type CredentialExtraction struct {
	Credential          trust.Credential
	Headers             []string          // header names to remove entirely
	HeaderSets          map[string]string // header names to set/override on the upstream request
	QueryParamsToRemove []string          // query parameter names to remove before forwarding upstream
	SourceName          string            // configured credential source name
}

func defaultCredentialSources() []CredentialSource {
	return []CredentialSource{&BearerCredentialSource{SourceName: "bearer"}}
}

func extractCredentialFromSources(req *authv3.CheckRequest, sources []CredentialSource) (*CredentialExtraction, error) {
	if len(sources) == 0 {
		sources = defaultCredentialSources()
	}

	var lastErr error
	for _, src := range sources {
		ext, err := src.Extract(req)
		if err != nil {
			lastErr = err
			continue
		}
		if ext != nil {
			return ext, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no credentials found in configured sources")
}

func httpRequestFromCheck(req *authv3.CheckRequest) (headers map[string]string, path string, err error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return nil, "", fmt.Errorf("no HTTP request attributes")
	}
	return httpReq.GetHeaders(), httpReq.GetPath(), nil
}
