package server

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// HeaderSpec configures a single header for extraction.
type HeaderSpec struct {
	Name string

	// Match is an optional regular expression the header value must satisfy.
	// When a configured header is present but its value does not match, the
	// whole source declines, letting later sources in the chain handle the
	// request. Use it to distinguish protocols that share a header (e.g. an
	// Authorization header that only belongs to this source when User-Agent
	// identifies a particular client).
	Match string

	// Strip reports whether the header is removed from the request forwarded
	// upstream. Nil means true. Set it to false for headers that are matched
	// on but not secret, and that upstream services still need.
	Strip *bool
}

// headerMatcher is the compiled form of a [HeaderSpec].
type headerMatcher struct {
	name  string
	match *regexp.Regexp
	strip bool
}

// HeaderCredentialSource extracts a configurable set of headers from a request
// and passes them to validators as a generic HeaderCredential.
//
// When none of the configured headers are present, Extract returns (nil, nil),
// allowing coexistence with other credential sources in the same chain. A
// header that is present but fails its [HeaderSpec.Match] declines the same
// way.
type HeaderCredentialSource struct {
	SourceName string
	headers    []headerMatcher
}

func NewHeaderCredentialSource(name string, headers []HeaderSpec) (*HeaderCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("header credential source: name is required")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("header credential source: at least one header is required")
	}
	compiled := make([]headerMatcher, len(headers))
	for i, h := range headers {
		lowered := strings.ToLower(h.Name)
		m := headerMatcher{name: lowered, strip: h.Strip == nil || *h.Strip}
		if h.Match != "" {
			re, err := regexp.Compile(h.Match)
			if err != nil {
				return nil, fmt.Errorf("header credential source: invalid match for header %s: %w", lowered, err)
			}
			m.match = re
		}
		compiled[i] = m
	}
	return &HeaderCredentialSource{SourceName: name, headers: compiled}, nil
}

func (s *HeaderCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	extracted := make(map[string]string, len(s.headers))
	var headersUsed []string

	for _, h := range s.headers {
		v := cc.Headers[h.name]
		if v == "" {
			continue
		}
		if h.match != nil && !h.match.MatchString(v) {
			// Present but not ours: decline so the chain can fall through.
			return nil, nil
		}
		extracted[h.name] = v
		if h.strip {
			headersUsed = append(headersUsed, h.name)
		}
	}

	if len(extracted) == 0 {
		return nil, nil
	}

	if len(extracted) != len(s.headers) {
		var missing []string
		for _, h := range s.headers {
			if _, ok := extracted[h.name]; !ok {
				missing = append(missing, h.name)
			}
		}
		return nil, fmt.Errorf("missing required headers: %v (all configured headers must be present when any are)", missing)
	}

	return &CredentialExtraction{
		Credential:  &trust.HeaderCredential{Headers: extracted},
		HeadersUsed: headersUsed,
		SourceName:  s.SourceName,
	}, nil
}
