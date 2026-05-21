package server

import (
	"fmt"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// Credential source type strings used in config and CredentialExtraction.SourceType.
const (
	CredentialSourceTypeBearer = "bearer"
	CredentialSourceTypeCookie = "cookie"
	CredentialSourceTypeCert   = "cert"
	CredentialSourceTypeQuery  = "query"
)

var credentialSourceTypes = []string{
	CredentialSourceTypeBearer,
	CredentialSourceTypeCookie,
	CredentialSourceTypeCert,
	CredentialSourceTypeQuery,
}

// CredentialSourceSpec configures a credential extraction source.
type CredentialSourceSpec struct {
	Name          string // unique credential source name
	Type          string
	CookieName    string
	ParameterName string
	Header        string // HTTP header for cert extraction
}

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
	SourceType          string // configured credential source name
}

// NewCredentialSource builds a configured credential source implementation.
func NewCredentialSource(spec CredentialSourceSpec) (CredentialSource, error) {
	if spec.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if spec.Type == "" {
		return nil, fmt.Errorf("type is required")
	}
	switch spec.Type {
	case CredentialSourceTypeBearer:
		return &BearerCredentialSource{SourceName: spec.Name}, nil
	case CredentialSourceTypeCookie:
		if spec.CookieName == "" {
			return nil, fmt.Errorf("cookie_name is required for type %q", spec.Type)
		}
		return &CookieCredentialSource{SourceName: spec.Name, CookieName: spec.CookieName}, nil
	case CredentialSourceTypeQuery:
		if spec.ParameterName == "" {
			return nil, fmt.Errorf("parameter_name is required for type %q", spec.Type)
		}
		return &QueryCredentialSource{SourceName: spec.Name, ParameterName: spec.ParameterName}, nil
	case CredentialSourceTypeCert:
		if spec.Header == "" {
			return nil, fmt.Errorf("header is required for type %q", spec.Type)
		}
		return &CertCredentialSource{SourceName: spec.Name, Header: spec.Header}, nil
	default:
		return nil, fmt.Errorf("unknown type %q (allowed: %s)", spec.Type, strings.Join(credentialSourceTypes, ", "))
	}
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
