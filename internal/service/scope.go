package service

import "strings"

// OAuthScope represents an OAuth2 scope to include in an issued token.
// The zero value means omit the scope claim entirely.
type OAuthScope struct {
	value string
}

// OmitScope returns a scope that omits the scope claim from issued tokens.
func OmitScope() OAuthScope {
	return OAuthScope{}
}

// NewOAuthScope parses a raw scope string. Returns false for empty or whitespace-only input.
func NewOAuthScope(raw string) (OAuthScope, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return OAuthScope{}, false
	}
	return OAuthScope{value: trimmed}, true
}

// IsPresent reports whether the scope should be included in an issued token.
func (s OAuthScope) IsPresent() bool {
	return s.value != ""
}

// String returns the scope value, or empty string when not present.
func (s OAuthScope) String() string {
	return s.value
}
