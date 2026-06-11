package request

import (
	"path"
	"strings"
)

// ParseMatchPath canonicalizes a path for optional-auth matching.
// Returns ("", false) for non-canonical input.
func ParseMatchPath(raw string) (string, bool) {
	p := raw
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}

	if strings.Contains(p, "%") {
		return "", false
	}

	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if cleaned != p {
		return "", false
	}
	return cleaned, true
}
