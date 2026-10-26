package config

import (
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/server"
)

var credentialSourceTypes = []string{
	server.CredentialSourceTypeBearer,
	server.CredentialSourceTypeCookie,
	server.CredentialSourceTypeBasicAuth,
	server.CredentialSourceTypeHeader,
	server.CredentialSourceTypeForwardedClientCert,
}

func newCredentialSources(cfgs []CredentialSourceConfig) (server.CredentialSources, error) {
	sources := make([]server.CredentialSource, 0, len(cfgs))
	seen := make(map[string]struct{}, len(cfgs))
	for i, cfg := range cfgs {
		if cfg.Name == "" {
			return server.CredentialSources{}, fmt.Errorf("credential_sources[%d]: name is required", i)
		}
		if _, exists := seen[cfg.Name]; exists {
			return server.CredentialSources{}, fmt.Errorf("duplicate credential source name: %s", cfg.Name)
		}
		seen[cfg.Name] = struct{}{}

		src, err := newCredentialSource(cfg)
		if err != nil {
			return server.CredentialSources{}, fmt.Errorf("credential_sources[%d]: %w", i, err)
		}
		sources = append(sources, src)
	}
	return server.NewCredentialSources(sources...), nil
}

func newCredentialSource(cfg CredentialSourceConfig) (server.CredentialSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if cfg.Type == "" {
		return nil, fmt.Errorf("type is required")
	}
	switch cfg.Type {
	case server.CredentialSourceTypeBearer:
		return server.NewBearerCredentialSource(cfg.Name)
	case server.CredentialSourceTypeCookie:
		return server.NewCookieCredentialSource(cfg.Name, cfg.CookieName)
	case server.CredentialSourceTypeBasicAuth:
		return server.NewBasicAuthCredentialSource(cfg.Name)
	case server.CredentialSourceTypeHeader:
		headers := make([]server.HeaderSpec, len(cfg.Headers))
		for i, h := range cfg.Headers {
			headers[i] = server.HeaderSpec{Name: h.Name, Match: h.Match, Strip: h.Strip}
		}
		return server.NewHeaderCredentialSource(cfg.Name, headers)
	case server.CredentialSourceTypeForwardedClientCert:
		return server.NewForwardedClientCertCredentialSource(cfg.Name, cfg.SubjectHeader, cfg.IssuerHeader)
	default:
		return nil, fmt.Errorf("unknown type %q (allowed: %s)", cfg.Type, strings.Join(credentialSourceTypes, ", "))
	}
}
