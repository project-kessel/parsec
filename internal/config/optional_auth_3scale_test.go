package config

import (
	"path/filepath"
	"regexp"
	"testing"
)

func loadThreeScaleProductionConfig(t *testing.T) *Config {
	t.Helper()

	configPath := filepath.Join("..", "..", "configs", "examples", "optional-auth-3scale-production.yaml")
	loader, err := NewLoader(configPath)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	cfg, err := loader.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return cfg
}

func compileOptionalAuthRegexes(t *testing.T, cfg *Config) []*regexp.Regexp {
	t.Helper()

	compiled := make([]*regexp.Regexp, 0, len(cfg.AuthzServer.OptionalAuthPaths))
	for _, p := range cfg.AuthzServer.OptionalAuthPaths {
		re, err := regexp.Compile(p.Path)
		if err != nil {
			t.Fatalf("compile %q: %v", p.Path, err)
		}
		compiled = append(compiled, re)
	}
	return compiled
}

func matchesAnyCompiledRegex(path string, patterns []*regexp.Regexp) bool {
	for _, re := range patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func TestOptionalAuthPathMatcher_LoadsThreeScaleProductionYAML(t *testing.T) {
	cfg := loadThreeScaleProductionConfig(t)

	if cfg.AuthzServer == nil {
		t.Fatal("expected authz_server config")
	}
	if got := len(cfg.AuthzServer.OptionalAuthPaths); got != 25 {
		t.Fatalf("optional_auth_paths len=%d, want 25", got)
	}

	m, err := NewOptionalAuthPathMatcher(cfg.AuthzServer)
	if err != nil {
		t.Fatalf("NewOptionalAuthPathMatcher: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil matcher")
	}
}

func TestOptionalAuthPathMatcher_ThreeScaleProductionParity(t *testing.T) {
	cfg := loadThreeScaleProductionConfig(t)
	m, err := NewOptionalAuthPathMatcher(cfg.AuthzServer)
	if err != nil {
		t.Fatalf("NewOptionalAuthPathMatcher: %v", err)
	}

	compiled := compileOptionalAuthRegexes(t, cfg)

	paths := []string{
		"/r/insights/platform/prod/v1/openapi.json",
		"/r/insights/platform/stage/v2.1/openapi.json",
		"/api/insights/v1/openapi.json",
		"/api/approval/v1/stageaction/approve",
		"/api/insights/v2/kcs/report",
		"/api/approval/static/logo.png",
		"/api/commit-tracker/github",
		"/api/cloudigrade/v2/azure-offer-template",
		"/api/cloudigrade/v2/azure-offer-template/",
		"/api/vmaas/hosts",
		"/api/tower-analytics/v1/generate_pdf/report.pdf",
		"/api/insights-results-aggregator/v1/info",
		"/api/insights-results-aggregator/v1/info/",
		"/api/provisioning/v1/azure_offering_template",
		"/api/chrome-service/v1/static/app.js",
		"/api/cost-management/v1/recommendations/openshift/openapi.json",
		"/api/content-sources/v1/repository_gpg_key/12345678-ABCD-1234-ABCD-123456789012",
		"/api/pulp/api/v3/status/",
		"/api/pulp/api/v3/docs/api.json",
		"/api/pulp-content/public-repo/content",
		"/api/pulp/public-repo/content",
		"/api/migration-assessment/report",
		"/api/migration-advisor-dev/advice",
		"/api/pypi/public-index/simple",
		"/api/distributors/acme/v1/openapi.json",
		"/api/distributors/acme/v2/docs",
		"/api/distributors/openapi.json",
		"/api/distributors/docs",
		"/api/insights/vx/openapi.json",
		"/api/foo/vNOTVERSION/openapi.json",
		"/api/content-sources/v1/repository_gpg_key/not-a-uuid",
		"/api/distributors/openapi.json/extra",
		"/api/vmaas",
		"/api/approval/static",
		"/api/secure/resource",
		"/r/insights/platform/prod/v1/openapi.json/extra",
		"/api/distributors/acme/v10/openapi.json",
	}

	for _, path := range paths {
		want := matchesAnyCompiledRegex(path, compiled)
		got := m.MatchesPath(path)
		if got != want {
			t.Errorf("path %q: config=%v, yaml_regex=%v", path, got, want)
		}
	}
}

func TestProvider_OptionalAuthPathMatcher(t *testing.T) {
	cfg := loadThreeScaleProductionConfig(t)
	p := NewProvider(cfg)

	m, err := p.OptionalAuthPathMatcher()
	if err != nil {
		t.Fatalf("OptionalAuthPathMatcher: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil matcher from provider")
	}
	if !m.MatchesPath("/api/insights/v1/openapi.json") {
		t.Error("expected provider-built matcher to match 3scale path")
	}
}
