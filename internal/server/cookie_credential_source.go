package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/project-kessel/parsec/internal/trust"
)

// CookieCredentialSource extracts a bearer token from a named cookie.
type CookieCredentialSource struct {
	SourceName string
	CookieName string
}

// NewCookieCredentialSource returns a CookieCredentialSource with the given
// source name and cookie name. Both are required.
func NewCookieCredentialSource(name, cookieName string) (*CookieCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("cookie credential source: name is required")
	}
	if cookieName == "" {
		return nil, fmt.Errorf("cookie credential source: cookie_name is required")
	}
	return &CookieCredentialSource{SourceName: name, CookieName: cookieName}, nil
}

func (s *CookieCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	token, ok, err := cookieValue(cc.Cookies, s.CookieName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if token == "" {
		return nil, fmt.Errorf("cookie %q present but token is empty", s.CookieName)
	}

	return &CredentialExtraction{
		Credential:  &trust.BearerCredential{Token: token},
		CookiesUsed: []string{s.CookieName},
		SourceName:  s.SourceName,
	}, nil
}

// cookieValue returns the value of the uniquely named cookie. If multiple
// cookies share the same name, it returns an error to reject the ambiguity.
func cookieValue(cookies []*http.Cookie, name string) (string, bool, error) {
	found := false
	var value string
	for _, c := range cookies {
		if c.Name == name {
			if found {
				return "", false, fmt.Errorf("multiple cookies named %q: ambiguous credential", name)
			}
			value = c.Value
			found = true
		}
	}
	return value, found, nil
}
