package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewAnonymousSubjectPolicy_NilConfig(t *testing.T) {
	policy, err := NewAnonymousSubjectPolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Error("expected nil policy for nil config")
	}
}

func TestNewAnonymousSubjectPolicy_NoPolicyConfigured(t *testing.T) {
	cfg := &AuthzServerConfig{}
	policy, err := NewAnonymousSubjectPolicy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Error("expected nil policy when no anonymous_subject_policy configured")
	}
}

func TestNewAnonymousSubjectPolicy_InlineScript(t *testing.T) {
	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type:   "cel",
			Script: `request.path.startsWith("/public/")`,
		},
	}

	policy, err := NewAnonymousSubjectPolicy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestNewAnonymousSubjectPolicy_InvalidScript(t *testing.T) {
	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type:   "cel",
			Script: `this is not valid CEL !!!`,
		},
	}

	_, err := NewAnonymousSubjectPolicy(cfg)
	if err == nil {
		t.Fatal("expected compile error for invalid CEL script")
	}
}

func TestNewAnonymousSubjectPolicy_ScriptFile(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "policy.cel")

	err := os.WriteFile(scriptPath, []byte(`request.path.startsWith("/public/")`), 0644)
	if err != nil {
		t.Fatalf("failed to write test script file: %v", err)
	}

	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type:       "cel",
			ScriptFile: scriptPath,
		},
	}

	policy, err := NewAnonymousSubjectPolicy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy from script file")
	}
}

func TestNewAnonymousSubjectPolicy_ScriptFileNotFound(t *testing.T) {
	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type:       "cel",
			ScriptFile: "/nonexistent/path/policy.cel",
		},
	}

	_, err := NewAnonymousSubjectPolicy(cfg)
	if err == nil {
		t.Fatal("expected error for missing script file")
	}
}

func TestNewAnonymousSubjectPolicy_EmptyScript(t *testing.T) {
	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type: "cel",
		},
	}

	_, err := NewAnonymousSubjectPolicy(cfg)
	if err == nil {
		t.Fatal("expected error for empty script")
	}
}

func TestNewAnonymousSubjectPolicy_UnsupportedType(t *testing.T) {
	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type:   "lua",
			Script: `return true`,
		},
	}

	_, err := NewAnonymousSubjectPolicy(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestNewAnonymousSubjectPolicy_BothScriptAndScriptFile(t *testing.T) {
	cfg := &AuthzServerConfig{
		AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
			Type:       "cel",
			Script:     `request.path == "/health"`,
			ScriptFile: "/some/path/policy.cel",
		},
	}

	_, err := NewAnonymousSubjectPolicy(cfg)
	if err == nil {
		t.Fatal("expected error when both script and script_file are set")
	}
}

func TestProvider_AnonymousSubjectPolicy(t *testing.T) {
	t.Run("nil authz server config", func(t *testing.T) {
		cfg := &Config{}
		p := NewProvider(cfg)

		policy, err := p.AnonymousSubjectPolicy()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if policy != nil {
			t.Error("expected nil policy for nil authz config")
		}
	})

	t.Run("with CEL policy", func(t *testing.T) {
		cfg := &Config{
			AuthzServer: &AuthzServerConfig{
				AnonymousSubjectPolicy: &AnonymousSubjectPolicyConfig{
					Type:   "cel",
					Script: `request.path == "/health"`,
				},
			},
		}
		p := NewProvider(cfg)

		policy, err := p.AnonymousSubjectPolicy()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if policy == nil {
			t.Fatal("expected non-nil policy from provider")
		}
	})
}
