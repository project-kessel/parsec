package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/project-kessel/parsec/internal/service"
)

var testDefaultTypes = []service.TokenType{service.TokenTypeTransactionToken}

func TestNewIssuancePolicy_NilConfig(t *testing.T) {
	policy, err := NewIssuancePolicy(nil, testDefaultTypes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Error("expected nil policy for nil config")
	}
}

func TestNewIssuancePolicy_NoPolicyConfigured(t *testing.T) {
	cfg := &AuthzServerConfig{}
	policy, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Error("expected nil policy when no issuance_policy configured")
	}
}

func TestNewIssuancePolicy_CelInlineScript(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:   "cel",
			Script: `subject.subject != ""`,
		},
	}
	policy, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestNewIssuancePolicy_CelScriptFile(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "policy.cel")

	err := os.WriteFile(scriptPath, []byte(`subject.subject != ""`), 0644)
	if err != nil {
		t.Fatalf("failed to write script file: %v", err)
	}

	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:       "cel",
			ScriptFile: scriptPath,
		},
	}
	policy, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy from script file")
	}
}

func TestNewIssuancePolicy_CelBothScriptAndFile(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:       "cel",
			Script:     `true`,
			ScriptFile: "/some/path/policy.cel",
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error when both script and script_file are specified")
	}
}

func TestNewIssuancePolicy_CelEmptyScript(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type: "cel",
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error for empty CEL script")
	}
}

func TestNewIssuancePolicy_CelInvalidScript(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:   "cel",
			Script: `this is not valid CEL !!!`,
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected compile error for invalid CEL script")
	}
}

func TestNewIssuancePolicy_CelScriptFileNotFound(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:       "cel",
			ScriptFile: "/nonexistent/path/policy.cel",
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error for missing script file")
	}
}

func TestNewIssuancePolicy_PathPassthrough(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type: "path_passthrough",
			Patterns: []PathPatternConfig{
				{Path: `^/health$`, Outcome: "passthrough"},
				{Path: `^/admin/`, Outcome: "deny"},
			},
		},
	}
	policy, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestNewIssuancePolicy_PathPassthroughNoPatterns(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:     "path_passthrough",
			Patterns: []PathPatternConfig{},
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error for empty patterns")
	}
}

func TestNewIssuancePolicy_PathPassthroughEmptyPath(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type: "path_passthrough",
			Patterns: []PathPatternConfig{
				{Path: "", Outcome: "passthrough"},
			},
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestNewIssuancePolicy_PathPassthroughEmptyOutcome(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type: "path_passthrough",
			Patterns: []PathPatternConfig{
				{Path: `^/health$`, Outcome: ""},
			},
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error for empty outcome")
	}
}

func TestNewIssuancePolicy_UnsupportedType(t *testing.T) {
	cfg := &AuthzServerConfig{
		IssuancePolicy: &IssuancePolicyConfig{
			Type:   "lua",
			Script: `return true`,
		},
	}
	_, err := NewIssuancePolicy(cfg, testDefaultTypes)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}
