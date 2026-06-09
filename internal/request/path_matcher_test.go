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
			name:     "unknown match type",
			patterns: []PathPattern{{Path: "/foo", Match: "regex"}},
			wantErr:  `unknown match type "regex"`,
		},
		{
			name:     "invalid glob syntax",
			patterns: []PathPattern{{Path: "/api/[invalid", Match: "glob"}},
			wantErr:  `invalid glob pattern`,
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
	if m.Matches("/anything") {
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
		if got := m.Matches(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathMatcher_Prefix(t *testing.T) {
	m, err := NewPathMatcher([]PathPattern{
		{Path: "/api/docs/", Match: "prefix"},
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
		{"/api/docs", false},
		{"/api/documentation/", false},
		{"/other", false},
	}

	for _, tt := range tests {
		if got := m.Matches(tt.path); got != tt.want {
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
		if got := m.Matches(tt.path); got != tt.want {
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
		if got := m.Matches(tt.path); got != tt.want {
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
		if got := m.Matches(tt.path); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
