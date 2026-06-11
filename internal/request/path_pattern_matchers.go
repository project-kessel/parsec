package request

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type exactMatcher struct {
	path string
}

func (m exactMatcher) matches(requestPath string) bool {
	return requestPath == m.path
}

type prefixMatcher struct {
	prefix string
}

func newPrefixMatcher(prefix string) (prefixMatcher, error) {
	if strings.HasSuffix(prefix, "-") {
		return prefixMatcher{}, fmt.Errorf("prefix pattern %q must end with / or use match: regex for suffix-continuation paths", prefix)
	}
	return prefixMatcher{prefix: prefix}, nil
}

func (m prefixMatcher) matches(requestPath string) bool {
	return hasPathPrefix(requestPath, m.prefix)
}

func hasPathPrefix(requestPath, prefix string) bool {
	if requestPath == prefix {
		return true
	}
	if !strings.HasPrefix(requestPath, prefix) || len(requestPath) <= len(prefix) {
		return false
	}
	if prefix[len(prefix)-1] == '/' {
		return true
	}
	return requestPath[len(prefix)] == '/'
}

type globMatcher struct {
	pattern string
}

func newGlobMatcher(pattern string) (globMatcher, error) {
	if _, err := path.Match(pattern, "/"); err != nil {
		return globMatcher{}, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
	}
	return globMatcher{pattern: pattern}, nil
}

func (m globMatcher) matches(requestPath string) bool {
	matched, _ := path.Match(m.pattern, requestPath)
	return matched
}

type regexMatcher struct {
	re *regexp.Regexp
}

func newRegexMatcher(pattern string) (regexMatcher, error) {
	if !strings.HasPrefix(pattern, "^/") {
		return regexMatcher{}, fmt.Errorf("regex pattern %q must start with ^/", pattern)
	}
	if !strings.HasSuffix(pattern, "$") {
		return regexMatcher{}, fmt.Errorf("regex pattern %q must end with $", pattern)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return regexMatcher{}, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}
	return regexMatcher{re: re}, nil
}

func (m regexMatcher) matches(requestPath string) bool {
	return m.re.MatchString(requestPath)
}
