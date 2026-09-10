package httpclient

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseBaseURL validates and parses an origin-form base URL for Lua HTTP
// resolution. Empty input returns (nil, nil). Allowed forms are scheme + host
// with no path, or scheme + host + "/" only. Any other path, query, or
// fragment is rejected so relative Lua URLs join predictably as {base}/path.
// Scheme must be http or https; user info (user:password@) is not allowed.
func ParseBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base_url %q: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid base_url %q: must include scheme and host", raw)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid base_url %q: scheme must be http or https", raw)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("invalid base_url %q: must not include user info", raw)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("invalid base_url %q: must be origin-form (scheme and host only, no path)", raw)
	}
	if parsed.RawQuery != "" {
		return nil, fmt.Errorf("invalid base_url %q: must not include query parameters", raw)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid base_url %q: must not include a fragment", raw)
	}
	return parsed, nil
}
