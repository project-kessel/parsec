package request

import (
	"fmt"
	"strings"
)

const (
	MatchExact  = "exact"
	MatchPrefix = "prefix"
	MatchGlob   = "glob"
	MatchRegex  = "regex"
)

// PathPattern defines a single path pattern with its matching strategy.
type PathPattern struct {
	Path  string
	Match string // "exact" (default), "prefix", "glob", or "regex"
}

// pathPatternMatcher evaluates a single compiled pattern against a request path.
type pathPatternMatcher interface {
	matches(requestPath string) bool
}

// PathMatcher evaluates request paths against a set of compiled patterns.
// A nil *PathMatcher is safe to call; MatchesPath always returns false.
type PathMatcher struct {
	patterns []pathPatternMatcher
}

// NewPathMatcher compiles patterns and validates them at startup.
// Returns an error if any pattern is invalid. Returns nil when patterns is empty.
func NewPathMatcher(patterns []PathPattern) (*PathMatcher, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	compiled := make([]pathPatternMatcher, 0, len(patterns))
	for _, p := range patterns {
		matcher, err := compilePathPattern(p)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, matcher)
	}

	return &PathMatcher{patterns: compiled}, nil
}

// MatchesPath returns true when requestPath matches any configured pattern.
// requestPath must be canonical (see ParseMatchPath).
func (m *PathMatcher) MatchesPath(requestPath string) bool {
	if m == nil {
		return false
	}

	for _, p := range m.patterns {
		if p.matches(requestPath) {
			return true
		}
	}

	return false
}

func compilePathPattern(p PathPattern) (pathPatternMatcher, error) {
	matchType := p.Match
	if matchType == "" {
		matchType = MatchExact
	}

	if matchType != MatchRegex && !strings.HasPrefix(p.Path, "/") {
		return nil, fmt.Errorf("pattern %q must start with /", p.Path)
	}

	switch matchType {
	case MatchExact:
		return exactMatcher{path: p.Path}, nil
	case MatchPrefix:
		return newPrefixMatcher(p.Path)
	case MatchGlob:
		return newGlobMatcher(p.Path)
	case MatchRegex:
		return newRegexMatcher(p.Path)
	default:
		return nil, fmt.Errorf("unknown match type %q for pattern %q (must be exact, prefix, glob, or regex)", matchType, p.Path)
	}
}
