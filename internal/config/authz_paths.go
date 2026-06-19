package config

import (
	"fmt"
	"os"

	"github.com/project-kessel/parsec/internal/server"
)

// NewAnonymousSubjectPolicy builds an AnonymousSubjectPolicy from configuration.
// Returns (nil, nil) when no policy is configured -- the caller should leave the
// default DenyAllPolicy in place.
func NewAnonymousSubjectPolicy(cfg *AuthzServerConfig) (server.AnonymousSubjectPolicy, error) {
	if cfg == nil || cfg.AnonymousSubjectPolicy == nil {
		return nil, nil
	}

	polCfg := cfg.AnonymousSubjectPolicy

	if polCfg.Type != "" && polCfg.Type != "cel" {
		return nil, fmt.Errorf("anonymous_subject_policy: unsupported type %q (only \"cel\" is supported)", polCfg.Type)
	}

	if polCfg.Script != "" && polCfg.ScriptFile != "" {
		return nil, fmt.Errorf("anonymous_subject_policy: cannot specify both script and script_file")
	}

	script := polCfg.Script
	if polCfg.ScriptFile != "" {
		content, err := os.ReadFile(polCfg.ScriptFile)
		if err != nil {
			return nil, fmt.Errorf("reading anonymous subject policy script file: %w", err)
		}
		script = string(content)
	}

	if script == "" {
		return nil, fmt.Errorf("anonymous_subject_policy: either script or script_file must be provided")
	}

	return server.NewCelAnonymousSubjectPolicy(script)
}
