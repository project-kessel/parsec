package config

import (
	"fmt"
	"os"

	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
)

// NewIssuancePolicy builds an IssuancePolicy from configuration.
// Returns (nil, nil) when no policy is configured -- the caller should leave
// the default AlwaysIssuePolicy in place.
func NewIssuancePolicy(cfg *AuthzServerConfig, defaultTypes []service.TokenType) (server.IssuancePolicy, error) {
	if cfg == nil || cfg.IssuancePolicy == nil {
		return nil, nil
	}

	polCfg := cfg.IssuancePolicy

	switch polCfg.Type {
	case "cel":
		return buildCelIssuancePolicy(polCfg, defaultTypes)
	case "path_passthrough":
		return buildPathPassthroughPolicy(polCfg, defaultTypes)
	default:
		return nil, fmt.Errorf("issuance_policy: unsupported type %q (supported: \"cel\", \"path_passthrough\")", polCfg.Type)
	}
}

func buildCelIssuancePolicy(cfg *IssuancePolicyConfig, defaultTypes []service.TokenType) (server.IssuancePolicy, error) {
	if cfg.Script != "" && cfg.ScriptFile != "" {
		return nil, fmt.Errorf("issuance_policy: cannot specify both script and script_file")
	}

	script := cfg.Script
	if cfg.ScriptFile != "" {
		content, err := os.ReadFile(cfg.ScriptFile)
		if err != nil {
			return nil, fmt.Errorf("reading issuance policy script file: %w", err)
		}
		script = string(content)
	}

	if script == "" {
		return nil, fmt.Errorf("issuance_policy: either script or script_file must be provided for type \"cel\"")
	}

	return server.NewCelIssuancePolicy(script, defaultTypes, "")
}

func buildPathPassthroughPolicy(cfg *IssuancePolicyConfig, defaultTypes []service.TokenType) (server.IssuancePolicy, error) {
	if len(cfg.Patterns) == 0 {
		return nil, fmt.Errorf("issuance_policy: path_passthrough requires at least one pattern")
	}

	rules := make([]server.PathPatternRule, len(cfg.Patterns))
	for i, p := range cfg.Patterns {
		if p.Path == "" {
			return nil, fmt.Errorf("issuance_policy: pattern %d: path is required", i)
		}
		if p.Outcome == "" {
			return nil, fmt.Errorf("issuance_policy: pattern %d: outcome is required", i)
		}
		rules[i] = server.PathPatternRule{
			Path:    p.Path,
			Outcome: p.Outcome,
		}
	}

	return server.NewPathPassthroughPolicy(rules, defaultTypes, "")
}
