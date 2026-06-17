package server

import (
	"context"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// CookieCredentialSource extracts a bearer token from a named cookie.
type CookieCredentialSource struct {
	SourceName string
	CookieName string
}

// NewCookieCredentialSource returns a CookieCredentialSource with the given
// source name and cookie name.
func NewCookieCredentialSource(name, cookieName string) *CookieCredentialSource {
	return &CookieCredentialSource{SourceName: name, CookieName: cookieName}
}

func (s *CookieCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	name := s.CookieName
	if name == "" {
		name = "cs_jwt"
	}

	cookieHeader := cc.Headers["cookie"]
	if cookieHeader == "" {
		return nil, nil
	}

	token, ok := cookieValue(cookieHeader, name)
	if !ok || token == "" {
		return nil, nil
	}

	ext := &CredentialExtraction{
		Credential: &trust.BearerCredential{Token: token},
		SourceName: s.sourceName(),
	}
	sanitized := sanitizeCookieHeader(cookieHeader, name)
	if sanitized == "" {
		ext.HeadersToRemove = []string{"cookie"}
	} else {
		ext.HeadersToSet = map[string]string{"cookie": sanitized}
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
