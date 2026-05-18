package server

import (
	"fmt"
	"net/url"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// CredentialSource configures where ext_authz extracts subject credentials.
type CredentialSource struct {
	Type   string // bearer, cookie, cert, query
	Name   string // cookie or query parameter name
	Header string // HTTP header for cert extraction
}

type credentialExtraction struct {
	credential            trust.Credential
	headers               []string          // header names to remove entirely
	headerSets            map[string]string // header names to set/override on the upstream request
	queryParamsToRemove   []string          // query parameter names to remove before forwarding upstream
	sourceType            string
}

func defaultCredentialSources() []CredentialSource {
	return []CredentialSource{{Type: "bearer"}}
}

func extractCredentialFromSources(req *authv3.CheckRequest, sources []CredentialSource) (*credentialExtraction, error) {
	if len(sources) == 0 {
		sources = defaultCredentialSources()
	}

	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return nil, fmt.Errorf("no HTTP request attributes")
	}

	headers := httpReq.GetHeaders()
	var lastErr error

	for _, src := range sources {
		ext, err := tryCredentialSource(headers, httpReq.GetPath(), src)
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

func tryCredentialSource(headers map[string]string, path string, src CredentialSource) (*credentialExtraction, error) {
	switch src.Type {
	case "bearer", "":
		return extractBearerFromAuthHeader(headers)
	case "cookie":
		return extractBearerFromCookie(headers, src.Name)
	case "query":
		return extractBearerFromQuery(path, src.Name)
	case "cert":
		return extractCertCredential(headers, src.Header)
	default:
		return nil, fmt.Errorf("unsupported credential source type: %s", src.Type)
	}
}

func extractBearerFromAuthHeader(headers map[string]string) (*credentialExtraction, error) {
	authHeader := headers["authorization"]
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	scheme, token, ok := strings.Cut(authHeader, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || token == "" {
		return nil, fmt.Errorf("unsupported authorization scheme")
	}

	return &credentialExtraction{
		credential: &trust.BearerCredential{Token: token},
		headers:    []string{"authorization"},
		sourceType: "bearer",
	}, nil
}

func extractBearerFromCookie(headers map[string]string, name string) (*credentialExtraction, error) {
	if name == "" {
		name = "cs_jwt"
	}

	cookieHeader := headers["cookie"]
	if cookieHeader == "" {
		return nil, fmt.Errorf("no cookie header")
	}

	token, ok := cookieValue(cookieHeader, name)
	if !ok || token == "" {
		return nil, fmt.Errorf("cookie %q not found", name)
	}

	ext := &credentialExtraction{
		credential: &trust.BearerCredential{Token: token},
		sourceType: "cookie",
	}
	sanitized := sanitizeCookieHeader(cookieHeader, name)
	if sanitized == "" {
		ext.headers = []string{"cookie"}
	} else {
		ext.headerSets = map[string]string{"cookie": sanitized}
	}
	return ext, nil
}

func extractBearerFromQuery(path, param string) (*credentialExtraction, error) {
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

	return &credentialExtraction{
		credential:          &trust.BearerCredential{Token: token},
		queryParamsToRemove: []string{param},
		sourceType:          "query",
	}, nil
}

func extractCertCredential(headers map[string]string, header string) (*credentialExtraction, error) {
	if header == "" {
		header = "x-forwarded-client-cert"
	}
	header = strings.ToLower(header)

	certHeader := headers[header]
	if certHeader == "" && header != "x-rh-certauth-cn" {
		certHeader = headers["x-rh-certauth-cn"]
		if certHeader != "" {
			header = "x-rh-certauth-cn"
		}
	}
	if certHeader == "" {
		return nil, fmt.Errorf("no certificate header")
	}

	return &credentialExtraction{
		credential: &trust.BearerCredential{Token: certHeader},
		headers:    []string{header},
		sourceType: "cert",
	}, nil
}

func cookieValue(cookieHeader, name string) (string, bool) {
	for part := range strings.SplitSeq(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		key, value, ok := strings.Cut(part, "=")
		if ok && key == name {
			return strings.Trim(value, `"`), true
		}
	}
	return "", false
}

// sanitizeCookieHeader rebuilds a Cookie header value without the named cookie.
func sanitizeCookieHeader(cookieHeader, omitName string) string {
	var remaining []string
	for part := range strings.SplitSeq(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, _, ok := strings.Cut(part, "=")
		if ok && key == omitName {
			continue
		}
		remaining = append(remaining, part)
	}
	return strings.Join(remaining, "; ")
}
