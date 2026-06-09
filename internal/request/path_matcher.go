package request

import (
	"fmt"
	"path"
	"strings"
)

const (
	MatchExact  = "exact"
	MatchPrefix = "prefix"
	MatchGlob   = "glob"
)

// PathPattern defines a single path pattern with its matching strategy.
type PathPattern struct {
	Path  string
	Match string // "exact" (default), "prefix", or "glob"
}

type compiledPattern struct {
	path      string
	matchType string
}

// PathMatcher evaluates request paths against a set of compiled patterns.
// A nil *PathMatcher is safe to call; Matches always returns false.
type PathMatcher struct {
	patterns []compiledPattern
}

// NewPathMatcher compiles patterns and validates them at startup.
// Returns an error if any pattern is invalid (bad match type, missing leading
// slash, malformed glob). Returns nil when patterns is empty.
func NewPathMatcher(patterns []PathPattern) (*PathMatcher, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	compiled := make([]compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		matchType := p.Match
		if matchType == "" {
			matchType = MatchExact
		}

		if !strings.HasPrefix(p.Path, "/") {
			return nil, fmt.Errorf("pattern %q must start with /", p.Path)
		}

		switch matchType {
		case MatchExact, MatchPrefix:
			// no extra validation needed
		case MatchGlob:
			if _, err := path.Match(p.Path, "/"); err != nil {
				return nil, fmt.Errorf("invalid glob pattern %q: %w", p.Path, err)
			}
		default:
			return nil, fmt.Errorf("unknown match type %q for pattern %q (must be exact, prefix, or glob)", matchType, p.Path)
		}

		compiled = append(compiled, compiledPattern{path: p.Path, matchType: matchType})
	}

	return &PathMatcher{patterns: compiled}, nil
}

// Matches returns true if the request path matches any configured pattern.
// A nil receiver always returns false.
func (m *PathMatcher) Matches(requestPath string) bool {
	if m == nil {
		return false
	}

	for _, p := range m.patterns {
		switch p.matchType {
		case MatchExact:
			if requestPath == p.path {
				return true
			}
		case MatchPrefix:
			if requestPath == p.path {
				return true
			}
			if strings.HasPrefix(requestPath, p.path) && len(requestPath) > len(p.path) {
				if p.path[len(p.path)-1] == '/' {
					return true
				}
				next := requestPath[len(p.path)]
				if next == '/' || next == '?' {
					return true
				}
			}
		case MatchGlob:
			if matched, _ := path.Match(p.path, requestPath); matched {
				return true
			}
		}
	}

	return false
}
