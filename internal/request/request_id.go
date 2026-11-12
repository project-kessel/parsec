package request

import "strings"

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
