package request

import (
	"path"
	"strings"
)

// ParseMatchPath validates a raw request path for optional-auth matching.
// It strips the query string and rejects non-canonical input (percent-encoding,
// dot-segments, double slashes). It does NOT normalize the path — the returned
// string is the validated input, not path.Clean output. In particular, trailing
// slashes are preserved because several 3scale patterns require or optionally
// match them (e.g. ^/api/pulp/api/v3/status/$).
// Returns ("", false) for non-canonical input.
func ParseMatchPath(raw string) (string, bool) {
	p := raw
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}

	if strings.Contains(p, "%") || strings.Contains(p, "//") || !isCleanPath(p) {
		return "", false
	}

	return p, true
}

// isCleanPath reports whether p equals its path.Clean form, treating a
// trailing slash as valid (path.Clean would strip it).
func isCleanPath(p string) bool {
	stem := p
	if len(p) > 1 && p[len(p)-1] == '/' {
		stem = p[:len(p)-1]
	}
	cleaned := path.Clean(stem)
	if cleaned == "." {
		cleaned = "/"
	}
	return cleaned == stem
}
