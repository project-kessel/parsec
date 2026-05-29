package server

import (
	"maps"
	"testing"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func newScopePolicyFromMaps(defaultScope string, byTrustDomain map[string]string, requestHeader, requestQueryParam string) (ScopePolicy, error) {
	var byTrustDomainCopy map[string]string
	if byTrustDomain != nil {
		byTrustDomainCopy = maps.Clone(byTrustDomain)
	}
	return ParseScopePolicy(ScopePolicyConfig{
		DefaultScope:      defaultScope,
		ByTrustDomain:     byTrustDomainCopy,
		RequestHeader:     requestHeader,
		RequestQueryParam: requestQueryParam,
	})
}

func TestScopeSource_String(t *testing.T) {
	tests := []struct {
		source ScopeSource
		want   string
	}{
		{ScopeSourceOmit, "omit"},
		{ScopeSourceRequestHeader, "request_header"},
		{ScopeSourceRequestQuery, "request_query"},
		{ScopeSourceTrustDomain, "trust_domain"},
		{ScopeSourceDefault, "default"},
		{ScopeSource(99), "omit"},
	}
	for _, tt := range tests {
		if got := tt.source.String(); got != tt.want {
			t.Errorf("ScopeSource(%d).String() = %q, want %q", tt.source, got, tt.want)
		}
	}
}

func TestParseScopePolicy_normalizesTrustDomainKeys(t *testing.T) {
	policy, err := newScopePolicyFromMaps("", map[string]string{
		" customer.example.com ": "customer:access",
	}, "", "")
	if err != nil {
		t.Fatalf("newScopePolicyFromMaps: %v", err)
	}

	resolved := policy.Resolve(&request.RequestAttributes{Additional: make(map[string]any)}, testSubject("customer.example.com"))
	if resolved.Source != ScopeSourceTrustDomain {
		t.Fatalf("Source = %v, want TrustDomain", resolved.Source)
	}
	if resolved.Scope.String() != "customer:access" {
		t.Fatalf("Scope = %q, want customer:access", resolved.Scope.String())
	}
}

func testScopePolicy(t *testing.T) ScopePolicy {
	t.Helper()
	policy, err := newScopePolicyFromMaps(
		"default-scope",
		map[string]string{
			"customer.example.com": "customer:access",
			"prod.example.com":     "prod:access",
		},
		"x-oauth-scope",
		"scope",
	)
	if err != nil {
		t.Fatalf("newScopePolicyFromMaps: %v", err)
	}
	return policy
}

func testSubject(trustDomain string) *trust.Result {
	return &trust.Result{
		Subject:     "user-1",
		TrustDomain: trustDomain,
	}
}

// Law: request header overrides trust domain mapping and default.
func TestScopePolicy_Precedence_requestHeaderOverridesAll(t *testing.T) {
	policy := testScopePolicy(t)
	reqAttrs := &request.RequestAttributes{
		Path: "/api?scope=query-scope",
		Headers: map[string]string{
			"x-oauth-scope": "header-scope",
		},
		Additional: make(map[string]any),
	}

	resolved := policy.Resolve(reqAttrs, testSubject("customer.example.com"))
	if resolved.Source != ScopeSourceRequestHeader {
		t.Fatalf("Source = %v, want RequestHeader", resolved.Source)
	}
	if resolved.Scope.String() != "header-scope" {
		t.Fatalf("Scope = %q, want header-scope", resolved.Scope.String())
	}
}

// Law: query param overrides trust domain and default when header is absent.
func TestScopePolicy_Precedence_queryOverridesTrustDomainAndDefault(t *testing.T) {
	policy := testScopePolicy(t)
	reqAttrs := &request.RequestAttributes{
		Path:       "/api?scope=query-scope",
		Headers:    map[string]string{},
		Additional: make(map[string]any),
	}

	resolved := policy.Resolve(reqAttrs, testSubject("customer.example.com"))
	if resolved.Source != ScopeSourceRequestQuery {
		t.Fatalf("Source = %v, want RequestQuery", resolved.Source)
	}
	if resolved.Scope.String() != "query-scope" {
		t.Fatalf("Scope = %q, want query-scope", resolved.Scope.String())
	}
}

// Law: trust domain mapping overrides default when request sources are absent.
func TestScopePolicy_Precedence_trustDomainOverridesDefault(t *testing.T) {
	policy := testScopePolicy(t)
	reqAttrs := &request.RequestAttributes{
		Path:       "/api/resource",
		Additional: make(map[string]any),
	}

	resolved := policy.Resolve(reqAttrs, testSubject("customer.example.com"))
	if resolved.Source != ScopeSourceTrustDomain {
		t.Fatalf("Source = %v, want TrustDomain", resolved.Source)
	}
	if resolved.Scope.String() != "customer:access" {
		t.Fatalf("Scope = %q, want customer:access", resolved.Scope.String())
	}
}

// Law: default applies when no request source or trust domain match exists.
func TestScopePolicy_Precedence_defaultWhenNoMatch(t *testing.T) {
	policy := testScopePolicy(t)
	reqAttrs := &request.RequestAttributes{
		Path:       "/api/resource",
		Additional: make(map[string]any),
	}

	resolved := policy.Resolve(reqAttrs, testSubject("unknown.example.com"))
	if resolved.Source != ScopeSourceDefault {
		t.Fatalf("Source = %v, want Default", resolved.Source)
	}
	if resolved.Scope.String() != "default-scope" {
		t.Fatalf("Scope = %q, want default-scope", resolved.Scope.String())
	}
}

// Law: zero policy omits scope when nothing is configured.
func TestScopePolicy_Precedence_omitWhenNothingConfigured(t *testing.T) {
	var policy ScopePolicy
	reqAttrs := &request.RequestAttributes{
		Path:       "/api/resource",
		Additional: make(map[string]any),
	}

	resolved := policy.Resolve(reqAttrs, testSubject("customer.example.com"))
	if resolved.Source != ScopeSourceOmit {
		t.Fatalf("Source = %v, want Omit", resolved.Source)
	}
	if resolved.Scope.IsPresent() {
		t.Fatalf("Scope should be omitted, got %q", resolved.Scope.String())
	}
}

func TestParseScopePolicy_nilConfigReturnsZeroPolicy(t *testing.T) {
	policy, err := ParseScopePolicy(ScopePolicyConfig{})
	if err != nil {
		t.Fatalf("ParseScopePolicy: %v", err)
	}

	resolved := policy.Resolve(&request.RequestAttributes{Additional: make(map[string]any)}, testSubject("any"))
	if resolved.Source != ScopeSourceOmit {
		t.Fatalf("Source = %v, want Omit", resolved.Source)
	}
}

func TestParseScopePolicy_normalizesHeaderName(t *testing.T) {
	policy, err := ParseScopePolicy(ScopePolicyConfig{
		RequestHeader: "X-OAuth-Scope",
	})
	if err != nil {
		t.Fatalf("ParseScopePolicy: %v", err)
	}

	reqAttrs := &request.RequestAttributes{
		Headers:    map[string]string{"x-oauth-scope": "from-header"},
		Additional: make(map[string]any),
	}
	resolved := policy.Resolve(reqAttrs, nil)
	if resolved.Scope.String() != "from-header" {
		t.Fatalf("Scope = %q, want from-header", resolved.Scope.String())
	}
}

func TestParseScopePolicy_rejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  ScopePolicyConfig
	}{
		{
			name: "whitespace default",
			cfg:  ScopePolicyConfig{DefaultScope: "   "},
		},
		{
			name: "empty trust domain key",
			cfg:  ScopePolicyConfig{ByTrustDomain: map[string]string{"": "scope"}},
		},
		{
			name: "whitespace trust domain scope",
			cfg:  ScopePolicyConfig{ByTrustDomain: map[string]string{"prod.example.com": "  "}},
		},
		{
			name: "empty from_request block",
			cfg:  ScopePolicyConfig{RequestHeader: " ", RequestQueryParam: " "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseScopePolicy(tt.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScopePolicy_malformedPathFallsThrough(t *testing.T) {
	policy, err := newScopePolicyFromMaps("default-scope", nil, "", "scope")
	if err != nil {
		t.Fatalf("newScopePolicyFromMaps: %v", err)
	}

	reqAttrs := &request.RequestAttributes{
		Path:       "://bad-url",
		Additional: make(map[string]any),
	}
	resolved := policy.Resolve(reqAttrs, nil)
	if resolved.Source != ScopeSourceDefault {
		t.Fatalf("Source = %v, want Default", resolved.Source)
	}
}

func TestScopePolicy_emptyHeaderValueFallsThrough(t *testing.T) {
	policy, err := newScopePolicyFromMaps("default-scope", nil, "x-oauth-scope", "")
	if err != nil {
		t.Fatalf("newScopePolicyFromMaps: %v", err)
	}

	reqAttrs := &request.RequestAttributes{
		Headers:    map[string]string{"x-oauth-scope": "   "},
		Additional: make(map[string]any),
	}
	resolved := policy.Resolve(reqAttrs, nil)
	if resolved.Source != ScopeSourceDefault {
		t.Fatalf("Source = %v, want Default", resolved.Source)
	}
}

func mustOAuthScope(t *testing.T, raw string) service.OAuthScope {
	t.Helper()
	scope, ok := service.NewOAuthScope(raw)
	if !ok {
		t.Fatalf("NewOAuthScope(%q) returned false", raw)
	}
	return scope
}

func TestEnrichRequestScope_omitLeavesAdditionalUntouched(t *testing.T) {
	reqAttrs := &request.RequestAttributes{Additional: map[string]any{"existing": "value"}}
	enrichRequestScope(reqAttrs, ScopeResolution{Scope: service.OmitScope(), Source: ScopeSourceOmit})

	if _, ok := reqAttrs.Additional[requestAttrRequestedScope]; ok {
		t.Fatal("requested_scope should not be set for omit")
	}
	if _, ok := reqAttrs.Additional[requestAttrResolvedScopeSource]; ok {
		t.Fatal("resolved_scope_source should not be set for omit")
	}
	if reqAttrs.Additional["existing"] != "value" {
		t.Fatal("pre-existing key should be preserved")
	}
}

func TestEnrichRequestScope_presentWithNonOmitSourceSetsBothKeys(t *testing.T) {
	reqAttrs := &request.RequestAttributes{Additional: make(map[string]any)}
	enrichRequestScope(reqAttrs, ScopeResolution{
		Scope:  mustOAuthScope(t, "read write"),
		Source: ScopeSourceDefault,
	})

	if got := reqAttrs.Additional[requestAttrRequestedScope]; got != "read write" {
		t.Fatalf("requested_scope = %v, want %q", got, "read write")
	}
	if got := reqAttrs.Additional[requestAttrResolvedScopeSource]; got != "default" {
		t.Fatalf("resolved_scope_source = %v, want %q", got, "default")
	}
}

func TestEnrichRequestScope_nilAdditionalMapIsCreated(t *testing.T) {
	reqAttrs := &request.RequestAttributes{}
	enrichRequestScope(reqAttrs, ScopeResolution{
		Scope:  mustOAuthScope(t, "admin"),
		Source: ScopeSourceTrustDomain,
	})

	if reqAttrs.Additional == nil {
		t.Fatal("Additional map should have been created")
	}
	if got := reqAttrs.Additional[requestAttrRequestedScope]; got != "admin" {
		t.Fatalf("requested_scope = %v, want %q", got, "admin")
	}
	if got := reqAttrs.Additional[requestAttrResolvedScopeSource]; got != "trust_domain" {
		t.Fatalf("resolved_scope_source = %v, want %q", got, "trust_domain")
	}
}

func TestEnrichRequestScope_presentWithOmitSourceSetsOnlyScope(t *testing.T) {
	reqAttrs := &request.RequestAttributes{Additional: make(map[string]any)}
	enrichRequestScope(reqAttrs, ScopeResolution{
		Scope:  mustOAuthScope(t, "read"),
		Source: ScopeSourceOmit,
	})

	if got := reqAttrs.Additional[requestAttrRequestedScope]; got != "read" {
		t.Fatalf("requested_scope = %v, want %q", got, "read")
	}
	if _, ok := reqAttrs.Additional[requestAttrResolvedScopeSource]; ok {
		t.Fatal("resolved_scope_source should not be set when source is Omit")
	}
}
