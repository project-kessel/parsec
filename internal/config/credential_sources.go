package config

import (
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/server"
)

var credentialSourceTypes = []string{"bearer", "cookie"}

func newCredentialSources(cfgs []CredentialSourceConfig) ([]server.CredentialSource, error) {
	sources := make([]server.CredentialSource, 0, len(cfgs))
	seen := make(map[string]struct{}, len(cfgs))
	for i, cfg := range cfgs {
		if cfg.Name == "" {
			return nil, fmt.Errorf("credential_sources[%d]: name is required", i)
		}
		if _, exists := seen[cfg.Name]; exists {
			return nil, fmt.Errorf("duplicate credential source name: %s", cfg.Name)
		}
		seen[cfg.Name] = struct{}{}

		src, err := newCredentialSource(cfg)
		if err != nil {
			return nil, fmt.Errorf("credential_sources[%d]: %w", i, err)
		}
		sources = append(sources, src)
	}
	return sources, nil
}

func newCredentialSource(cfg CredentialSourceConfig) (server.CredentialSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if cfg.Type == "" {
		return nil, fmt.Errorf("type is required")
	}
	switch cfg.Type {
	case "bearer":
		return &server.BearerCredentialSource{SourceName: cfg.Name}, nil
	case "cookie":
		if cfg.CookieName == "" {
			return nil, fmt.Errorf("cookie_name is required for type %q", cfg.Type)
		}
		return &server.CookieCredentialSource{SourceName: cfg.Name, CookieName: cfg.CookieName}, nil
	default:
		return nil, fmt.Errorf("unknown type %q (allowed: %s)", cfg.Type, strings.Join(credentialSourceTypes, ", "))
	}
}
