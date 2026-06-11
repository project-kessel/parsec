package config

import (
	"fmt"

	"github.com/project-kessel/parsec/internal/request"
)

func NewOptionalAuthPathMatcher(cfg *AuthzServerConfig) (*request.PathMatcher, error) {
	if cfg == nil || len(cfg.OptionalAuthPaths) == 0 {
		return nil, nil
	}

	patterns := make([]request.PathPattern, len(cfg.OptionalAuthPaths))
	for i, p := range cfg.OptionalAuthPaths {
		patterns[i] = request.PathPattern{
			Path:  p.Path,
			Match: p.Match,
		}
	}

	m, err := request.NewPathMatcher(patterns)
	if err != nil {
		return nil, fmt.Errorf("optional_auth_paths: %w", err)
	}
	return m, nil
}
