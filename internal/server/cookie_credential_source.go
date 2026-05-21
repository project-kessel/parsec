package server

import (
	"fmt"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/trust"
)

// CookieCredentialSource extracts a bearer token from a named cookie.
type CookieCredentialSource struct {
	SourceName string
	CookieName string
}

func (s *CookieCredentialSource) Extract(req *authv3.CheckRequest) (*CredentialExtraction, error) {
	headers, _, err := httpRequestFromCheck(req)
	if err != nil {
		return nil, err
	}

	name := s.CookieName
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

	ext := &CredentialExtraction{
		Credential: &trust.BearerCredential{Token: token},
		SourceName: s.sourceName(),
	}
	sanitized := sanitizeCookieHeader(cookieHeader, name)
	if sanitized == "" {
		ext.Headers = []string{"cookie"}
	} else {
		ext.HeaderSets = map[string]string{"cookie": sanitized}
	}
	return ext, nil
}

func (s *CookieCredentialSource) sourceName() string {
	if s.SourceName != "" {
		return s.SourceName
	}
	return CredentialSourceTypeCookie
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
