package server

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// ScopeSource identifies which rule produced a resolved scope.
type ScopeSource int

const (
	ScopeSourceOmit ScopeSource = iota
	ScopeSourceRequestHeader
	ScopeSourceRequestQuery
	ScopeSourceTrustDomain
	ScopeSourceDefault
)

func (s ScopeSource) String() string {
	switch s {
	case ScopeSourceRequestHeader:
		return "request_header"
	case ScopeSourceRequestQuery:
		return "request_query"
	case ScopeSourceTrustDomain:
		return "trust_domain"
	case ScopeSourceDefault:
		return "default"
	default:
		return "omit"
	}
}

// ScopeResolution is the result of resolving OAuth2 scope for an ext_authz request.
type ScopeResolution struct {
	Scope  service.OAuthScope
	Source ScopeSource
}

const (
	requestAttrRequestedScope      = "requested_scope"
	requestAttrResolvedScopeSource = "resolved_scope_source"
)

// enrichRequestScope records scope metadata on request attributes for token mappers.
// When source is ScopeSourceOmit, resolved_scope_source is not set.
func enrichRequestScope(reqAttrs *request.RequestAttributes, resolution ScopeResolution) {
	if !resolution.Scope.IsPresent() && resolution.Source == ScopeSourceOmit {
		return
	}
	if reqAttrs.Additional == nil {
		reqAttrs.Additional = make(map[string]any)
	}
	if resolution.Scope.IsPresent() {
		reqAttrs.Additional[requestAttrRequestedScope] = resolution.Scope.String()
	}
	if resolution.Source != ScopeSourceOmit {
		reqAttrs.Additional[requestAttrResolvedScopeSource] = resolution.Source.String()
	}
}

// ScopePolicyConfig is the startup input for building a ScopePolicy.
// Provider maps YAML config into this struct to keep server free of config imports.
type ScopePolicyConfig struct {
	DefaultScope      string
	ByTrustDomain     map[string]string
	RequestHeader     string
	RequestQueryParam string
}

// ScopePolicy holds immutable scope resolution rules for ext_authz.
type ScopePolicy struct {
	defaultScope      service.OAuthScope
	byTrustDomain     map[string]service.OAuthScope
	requestHeader     string
	requestQueryParam string
}

// ParseScopePolicy validates and builds a ScopePolicy from startup configuration.
// An empty config produces a zero policy that always omits scope.
func ParseScopePolicy(cfg ScopePolicyConfig) (ScopePolicy, error) {
	policy := ScopePolicy{
		byTrustDomain: make(map[string]service.OAuthScope),
	}

	if cfg.DefaultScope != "" {
		scope, err := parseConfiguredScope(cfg.DefaultScope, "authz_server.scope.default")
		if err != nil {
			return ScopePolicy{}, err
		}
		policy.defaultScope = scope
	}

	for trustDomain, rawScope := range cfg.ByTrustDomain {
		normalizedTrustDomain := strings.TrimSpace(trustDomain)
		if normalizedTrustDomain == "" {
			return ScopePolicy{}, fmt.Errorf("authz_server.scope.by_trust_domain contains empty trust domain key")
		}
		scope, err := parseConfiguredScope(rawScope, fmt.Sprintf("authz_server.scope.by_trust_domain[%q]", normalizedTrustDomain))
		if err != nil {
			return ScopePolicy{}, err
		}
		policy.byTrustDomain[normalizedTrustDomain] = scope
	}

	header := strings.TrimSpace(cfg.RequestHeader)
	queryParam := strings.TrimSpace(cfg.RequestQueryParam)
	if (cfg.RequestHeader != "" && header == "") || (cfg.RequestQueryParam != "" && queryParam == "") {
		return ScopePolicy{}, fmt.Errorf("authz_server.scope.from_request: header/query_param must not be whitespace-only")
	}
	policy.requestHeader = strings.ToLower(header)
	policy.requestQueryParam = queryParam

	return policy, nil
}

// Resolve determines OAuth2 scope for token issuance using configured precedence:
// request header → request query param → by_trust_domain → default → omit.
func (p ScopePolicy) Resolve(reqAttrs *request.RequestAttributes, subject *trust.Result) ScopeResolution {
	if scope, ok := p.scopeFromRequestHeader(reqAttrs); ok {
		return ScopeResolution{Scope: scope, Source: ScopeSourceRequestHeader}
	}
	if scope, ok := p.scopeFromRequestQuery(reqAttrs); ok {
		return ScopeResolution{Scope: scope, Source: ScopeSourceRequestQuery}
	}
	if subject != nil {
		if scope, ok := p.byTrustDomain[subject.TrustDomain]; ok {
			return ScopeResolution{Scope: scope, Source: ScopeSourceTrustDomain}
		}
	}
	if p.defaultScope.IsPresent() {
		return ScopeResolution{Scope: p.defaultScope, Source: ScopeSourceDefault}
	}
	return ScopeResolution{Scope: service.OmitScope(), Source: ScopeSourceOmit}
}

func (p ScopePolicy) scopeFromRequestHeader(reqAttrs *request.RequestAttributes) (service.OAuthScope, bool) {
	if p.requestHeader == "" || reqAttrs == nil || len(reqAttrs.Headers) == 0 {
		return service.OAuthScope{}, false
	}
	value, ok := reqAttrs.Headers[p.requestHeader]
	if !ok {
		return service.OAuthScope{}, false
	}
	return service.NewOAuthScope(value)
}

func (p ScopePolicy) scopeFromRequestQuery(reqAttrs *request.RequestAttributes) (service.OAuthScope, bool) {
	if p.requestQueryParam == "" || reqAttrs == nil || reqAttrs.Path == "" {
		return service.OAuthScope{}, false
	}

	parsed, err := url.Parse(reqAttrs.Path)
	if err != nil {
		return service.OAuthScope{}, false
	}

	return service.NewOAuthScope(parsed.Query().Get(p.requestQueryParam))
}

func parseConfiguredScope(raw, fieldPath string) (service.OAuthScope, error) {
	scope, ok := service.NewOAuthScope(raw)
	if !ok {
		return service.OAuthScope{}, fmt.Errorf("%s must not be empty or whitespace-only", fieldPath)
	}
	return scope, nil
}
