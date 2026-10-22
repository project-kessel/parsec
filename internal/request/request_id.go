package request

import "strings"

// defaultRequestIDHeaders is the industry-standard default when no
// deployment-specific headers are configured.
var defaultRequestIDHeaders = []string{"x-request-id"}

// RequestIDConfig holds the ordered list of header names used to extract
// and propagate request correlation identifiers. The first match wins on
// extraction; the first entry is the canonical header set on responses.
type RequestIDConfig struct {
	Headers []string
}

// DefaultRequestIDConfig returns a config with the industry-standard
// x-request-id header. Returns a copy to prevent caller mutations from
// affecting future defaults.
func DefaultRequestIDConfig() RequestIDConfig {
	headers := make([]string, len(defaultRequestIDHeaders))
	copy(headers, defaultRequestIDHeaders)
	return RequestIDConfig{Headers: headers}
}

// CanonicalHeader returns the first (canonical) header name, used for
// response propagation.
func (c RequestIDConfig) CanonicalHeader() string {
	if len(c.Headers) == 0 {
		return defaultRequestIDHeaders[0]
	}
	return c.Headers[0]
}

// DefaultRequestIDHeaders returns a copy of the default header list.
func DefaultRequestIDHeaders() []string {
	headers := make([]string, len(defaultRequestIDHeaders))
	copy(headers, defaultRequestIDHeaders)
	return headers
}

// ValidRequestID returns value when it is a safe correlation identifier,
// otherwise an empty string. Allowed characters: alphanumerics and ._:-
func ValidRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return ""
	}
	return value
}

// HeaderValue returns the value for name from headers, case-insensitively.
func HeaderValue(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	if value := headers[name]; value != "" {
		return value
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
