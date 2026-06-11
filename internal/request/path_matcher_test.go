package request

import (
	"strings"
	"testing"
)

func TestNewPathMatcher_Validation(t *testing.T) {
	tests := []struct {
		name     string
		patterns []PathPattern
		wantErr  string
	}{
		{
			name:     "empty patterns returns nil",
			patterns: nil,
		},
		{
			name:     "valid exact pattern",
			patterns: []PathPattern{{Path: "/openapi.json", Match: "exact"}},
		},
		{
			name:     "valid prefix pattern",
			patterns: []PathPattern{{Path: "/api/docs/", Match: "prefix"}},
		},
		{
			name:     "valid glob pattern",
			patterns: []PathPattern{{Path: "/api/*.json", Match: "glob"}},
		},
		{
			name:     "match defaults to exact",
			patterns: []PathPattern{{Path: "/openapi.json"}},
		},
		{
			name:     "missing leading slash",
			patterns: []PathPattern{{Path: "openapi.json", Match: "exact"}},
			wantErr:  `must start with /`,
		},
		{
			name:     "valid regex pattern",
			patterns: []PathPattern{{Path: `^/api/openapi\.json$`, Match: "regex"}},
		},
		{
			name:     "unknown match type",
			patterns: []PathPattern{{Path: "/foo", Match: "pattern"}},
			wantErr:  `unknown match type "pattern"`,
		},
		{
			name:     "invalid glob syntax",
			patterns: []PathPattern{{Path: "/api/[invalid", Match: "glob"}},
			wantErr:  `invalid glob pattern`,
		},
		{
			name:     "unsafe prefix suffix continuation",
			patterns: []PathPattern{{Path: "/api/pulp-content/public-", Match: "prefix"}},
			wantErr:  `suffix-continuation`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewPathMatcher(tt.patterns)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tt.patterns) == 0 && m != nil {
				t.Fatal("expected nil matcher for empty patterns")
			}
		})
	}
}

func TestPathMatcher_NilReceiver(t *testing.T) {
	var m *PathMatcher
	if m.MatchesPath("/anything") {
		t.Error("nil matcher should never match")
	}
}

func TestPathMatcher_Exact(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: "/openapi.json", Match: "exact"},
		{Path: "/healthz", Match: "exact"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/openapi.json", true},
		{"/healthz", true},
		{"/openapi.json/extra", false},
		{"/OPENAPI.JSON", false},
		{"/api/resource", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := m.MatchesPath(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathMatcher_Prefix(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: "/api/docs/", Match: "prefix"},
		{Path: "/api/docs", Match: "prefix"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/api/docs/", true},
		{"/api/docs/openapi.json", true},
		{"/api/docs/v2/schema", true},
		{"/api/docs", true},
		{"/api/docs-admin", false},
		{"/api/documentation/", false},
		{"/other", false},
	}

	for _, tt := range tests {
		if got := m.MatchesPath(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathMatcher_Glob(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: "/api/*.json", Match: "glob"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/api/openapi.json", true},
		{"/api/schema.json", true},
		{"/api/.json", true},
		{"/api/nested/file.json", false},
		{"/api/openapi.yaml", false},
		{"/other/file.json", false},
	}

	for _, tt := range tests {
		if got := m.MatchesPath(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathMatcher_GRPCPaths(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: "/test.v1.FooService/Bar", Match: "exact"},
		{Path: "/grpc.health.v1.Health/", Match: "prefix"},
		{Path: "/test.v1.MetadataService/*", Match: "glob"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/test.v1.FooService/Bar", true},
		{"/test.v1.FooService/Baz", false},
		{"/grpc.health.v1.Health/Check", true},
		{"/grpc.health.v1.Health/Watch", true},
		{"/test.v1.MetadataService/GetSchema", true},
		{"/test.v1.MetadataService/ListMethods", true},
		{"/test.v1.SecureService/DoWork", false},
	}

	for _, tt := range tests {
		if got := m.MatchesPath(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathMatcher_MultiplePatterns(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: "/openapi.json"},
		{Path: "/api/docs/", Match: "prefix"},
		{Path: "/api/*.json", Match: "glob"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/openapi.json", true},
		{"/api/docs/index.html", true},
		{"/api/schema.json", true},
		{"/api/resource", false},
	}

	for _, tt := range tests {
		if got := m.MatchesPath(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathMatcher_Regex_Validation(t *testing.T) {
	tests := []struct {
		name     string
		patterns []PathPattern
		wantErr  string
	}{
		{
			name: "valid anchored regex",
			patterns: []PathPattern{
				{Path: `^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`, Match: MatchRegex},
			},
		},
		{
			name: "missing start anchor",
			patterns: []PathPattern{
				{Path: `/api/openapi.json$`, Match: MatchRegex},
			},
			wantErr: "must start with ^/",
		},
		{
			name: "missing end anchor",
			patterns: []PathPattern{
				{Path: `^/api/openapi.json`, Match: MatchRegex},
			},
			wantErr: "must end with $",
		},
		{
			name: "invalid regex syntax",
			patterns: []PathPattern{
				{Path: `^/api/[invalid$`, Match: MatchRegex},
			},
			wantErr: "invalid regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPathMatcher(tt.patterns)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseMatchPath(t *testing.T) {
	tests := []struct {
		raw      string
		wantPath string
		wantOK   bool
	}{
		{"/openapi.json?version=2", "/openapi.json", true},
		{"/openapi.json", "/openapi.json", true},
		{"/api/docs/../secret", "", false},
		{"/openapi%2ejson", "", false},
		{"/openapi.json/", "", false},
		{"/api//docs", "", false},
		{"/api/docs/%2e%2e/secret", "", false},
		{"/api/docs/../secret?foo=bar", "", false},
	}

	for _, tt := range tests {
		gotPath, gotOK := ParseMatchPath(tt.raw)
		if gotOK != tt.wantOK {
			t.Errorf("ParseMatchPath(%q) ok = %v, want %v", tt.raw, gotOK, tt.wantOK)
			continue
		}
		if gotOK && gotPath != tt.wantPath {
			t.Errorf("ParseMatchPath(%q) path = %q, want %q", tt.raw, gotPath, tt.wantPath)
		}
	}
}

func TestPathMatcher_Regex(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: `^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`, Match: MatchRegex},
		{Path: `^/api/content-sources/v[0-9]+(\.[0-9]+)?/repository_gpg_key/[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$`, Match: MatchRegex},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/api/insights/v1/openapi.json", true},
		{"/api/insights/v1.2/openapi.json", true},
		{"/api/foo/vNOTVERSION/openapi.json", false},
		{"/api/insights/v1/openapi.json/extra", false},
		{"/secret/openapi.json", false},
		{"/api/content-sources/v1/repository_gpg_key/12345678-1234-1234-1234-123456789012", true},
		{"/api/content-sources/v1/repository_gpg_key/not-a-uuid", false},
		{"/api/content-sources/v1/repository_gpg_key/1234567-1234-1234-1234-123456789012", false},
	}

	for _, tt := range tests {
		if got := m.MatchesPath(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
