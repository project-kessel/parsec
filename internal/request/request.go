// Package request provides common request-related types used across the Parsec system.
//
// This package contains types that represent HTTP/RPC request context and attributes,
// which are used by multiple packages including trust validation and token issuance.
package request

import "github.com/project-kessel/parsec/internal/claims"

// RequestAttributes contains attributes about the incoming request
// This is used for both token issuance context and validator filtering decisions
// All fields are exported and JSON-serializable
type RequestAttributes struct {
	// Method is the HTTP method or RPC method name
	Method string `json:"method,omitempty"`

	// Path is the request path/resource being accessed
	Path string `json:"path,omitempty"`

	// IPAddress is the client IP address
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the client user agent
	UserAgent string `json:"user_agent,omitempty"`

	// Headers contains relevant HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// Additional arbitrary context
	// This can include:
	// - "host": The HTTP host header
	// - "context_extensions": Envoy's context extensions (map[string]string)
	// - Custom application-specific context
	// Note: No omitempty tag to ensure this field is always present in JSON,
	// even when empty, for CEL filter expressions to work correctly
	Additional map[string]any `json:"additional"`
}

// FromClaims constructs RequestAttributes from filtered claims
// This is used when the client provides request_context claims that have been filtered
// The function maps well-known claim names to RequestAttributes fields
func FromClaims(filteredClaims claims.Claims) *RequestAttributes {
	attrs := &RequestAttributes{
		Additional: make(map[string]any),
	}

	if filteredClaims == nil {
		return attrs
	}

	// Map well-known claim names to struct fields
	if method := filteredClaims.GetString("method"); method != "" {
		attrs.Method = method
	}
	if path := filteredClaims.GetString("path"); path != "" {
		attrs.Path = path
	}
	if ipAddress := filteredClaims.GetString("ip_address"); ipAddress != "" {
		attrs.IPAddress = ipAddress
	}
	if userAgent := filteredClaims.GetString("user_agent"); userAgent != "" {
		attrs.UserAgent = userAgent
	}

	// Handle headers if present
	if headersRaw, ok := filteredClaims["headers"]; ok {
		if headersMap, ok := headersRaw.(map[string]any); ok {
			attrs.Headers = make(map[string]string)
			for k, v := range headersMap {
				if str, ok := v.(string); ok {
					attrs.Headers[k] = str
				}
			}
		}
	}

	// Add all other claims to Additional
	knownFields := map[string]bool{
		"method":     true,
		"path":       true,
		"ip_address": true,
		"user_agent": true,
		"headers":    true,
	}

	for key, value := range filteredClaims {
		if !knownFields[key] {
			attrs.Additional[key] = value
		}
	}

	return attrs
}
