package server

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// Principal wraps a trust.Result with an explicit anonymous flag and
// credential metadata. This avoids representing anonymous identity as an
// empty trust.Result, which is too implicit for policy decisions.
type Principal struct {
	Result           *trust.Result
	Anonymous        bool
	CredentialType   trust.CredentialType
	CredentialSource string
}

// AuthzCheckPolicyInput carries the principals and request context that the
// authz check policy uses to make its decision.
type AuthzCheckPolicyInput struct {
	Subject Principal
	Actor   Principal
	Request *request.RequestAttributes
}

// AuthzCheckAction is the outcome an [AuthzCheckPolicy] selects.
type AuthzCheckAction string

const (
	// AuthzCheckIssue means the server should build an IssueRequest and call
	// TokenService.IssueTokens.
	AuthzCheckIssue AuthzCheckAction = "issue"

	// AuthzCheckAllowWithoutIssue means the server should return OK without
	// issuing tokens. Credential headers are still sanitized when present.
	AuthzCheckAllowWithoutIssue AuthzCheckAction = "allow_without_issue"

	// AuthzCheckDeny means the server should return an authorization denial
	// without calling token issuers or datasources.
	AuthzCheckDeny AuthzCheckAction = "deny"
)

// AuthzCheckDecision is the result of evaluating an [AuthzCheckPolicy].
// For Issue decisions, TokenTypes and Scope control the shape of the token
// request. For Deny decisions, Reason is included in the denial response.
type AuthzCheckDecision struct {
	Action     AuthzCheckAction
	TokenTypes []TokenTypeSpec
	Scope      string
	Reason     string
}

// AuthzCheckPolicy decides, given the ext_authz inputs, the shape of the
// token request and whether to invoke issuance at all.
//
// Implementations must use the returned error only for evaluation failures
// (e.g. a CEL compilation error), not for policy denials. Deny is a normal
// policy outcome expressed via AuthzCheckDeny. The server fails closed on
// both, but observability must distinguish "policy denied this request"
// from "policy failed to evaluate."
type AuthzCheckPolicy interface {
	Decide(ctx context.Context, in AuthzCheckPolicyInput) (AuthzCheckDecision, error)
}

// DefaultTokenTypeSpecs returns the default token types issued when none are
// configured: a single transaction token delivered via the Transaction-Token
// header.
func DefaultTokenTypeSpecs() []TokenTypeSpec {
	return []TokenTypeSpec{
		{
			Type:       service.TokenTypeTransactionToken,
			HeaderName: "Transaction-Token",
		},
	}
}

// newPrincipal builds a Principal from a validated trust.Result and the
// credential extraction that produced it.
func newPrincipal(result *trust.Result, ext *CredentialExtraction) Principal {
	return Principal{
		Result:           result,
		CredentialType:   ext.Credential.Type(),
		CredentialSource: ext.SourceName,
	}
}

// anonymousPrincipal returns a Principal representing an anonymous
// (unauthenticated) identity.
func anonymousPrincipal() Principal {
	return Principal{
		Result:    trust.AnonymousResult(),
		Anonymous: true,
	}
}

const anonymousSubjectDenyReason = "anonymous subjects not allowed"

// normalizeRequestPath strips the query string from an HTTP path so RE2
// anchors match the path component only (Envoy :path may include ?query).
func normalizeRequestPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

func requestPath(attrs *request.RequestAttributes) string {
	if attrs == nil {
		return ""
	}
	return normalizeRequestPath(attrs.Path)
}

func matchesAnyPattern(patterns []*regexp.Regexp, path string) bool {
	for _, re := range patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// CompilePathPatterns compiles a list of RE2 regex strings into anchored
// regexps suitable for full-path matching. Each pattern is wrapped in
// ^(?:...)$ to enforce full-match semantics.
func CompilePathPatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for i, pattern := range patterns {
		re, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return nil, fmt.Errorf("allow_anonymous_without_issue_paths[%d]: invalid RE2 regex %q: %w", i, pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// CompileHostPatterns compiles host regex strings into case-insensitive,
// anchored regexps suitable for full-host matching.
func CompileHostPatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for i, pattern := range patterns {
		re, err := regexp.Compile("^(?i:(?:" + pattern + "))$")
		if err != nil {
			return nil, fmt.Errorf("allow_anonymous_without_issue_rules[%d].hosts: invalid RE2 regex %q: %w", i, pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// StaticAuthenticatedPolicy is an AuthzCheckPolicy that denies anonymous
// subjects and issues a statically configured set of token types for
// authenticated subjects. Optionally, configured path patterns allow
// anonymous access without issuing tokens on matching URL paths.
type StaticAuthenticatedPolicy struct {
	tokenTypes            []TokenTypeSpec
	anonymousRequestRules []AnonymousRequestRule
}

type staticAuthenticatedConfig struct {
	anonymousRequestRules []AnonymousRequestRule
}

type AnonymousRequestRule struct{ Hosts, Paths []*regexp.Regexp }

// StaticAuthenticatedOption configures optional behavior for
// [NewStaticAuthenticatedPolicy].
type StaticAuthenticatedOption func(*staticAuthenticatedConfig)

// WithAllowAnonymousWithoutIssuePaths configures path patterns that allow
// anonymous access without issuing tokens. Patterns must be pre-compiled
// via [CompilePathPatterns].
func WithAllowAnonymousWithoutIssuePaths(patterns []*regexp.Regexp) StaticAuthenticatedOption {
	return func(c *staticAuthenticatedConfig) {
		c.anonymousRequestRules = append(c.anonymousRequestRules, AnonymousRequestRule{Paths: patterns})
	}
}

func WithAllowAnonymousWithoutIssueRules(rules []AnonymousRequestRule) StaticAuthenticatedOption {
	return func(c *staticAuthenticatedConfig) {
		c.anonymousRequestRules = append(c.anonymousRequestRules, rules...)
	}
}

// NewStaticAuthenticatedPolicy creates a policy that denies anonymous subjects
// and issues the given token types for authenticated subjects. If tokenTypes
// is empty, DefaultTokenTypeSpecs is used. Use [WithAllowAnonymousWithoutIssuePaths]
// to allow anonymous access on specific URL path patterns.
func NewStaticAuthenticatedPolicy(tokenTypes []TokenTypeSpec, opts ...StaticAuthenticatedOption) *StaticAuthenticatedPolicy {
	if len(tokenTypes) == 0 {
		tokenTypes = DefaultTokenTypeSpecs()
	}

	var cfg staticAuthenticatedConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	return &StaticAuthenticatedPolicy{
		tokenTypes:            tokenTypes,
		anonymousRequestRules: cfg.anonymousRequestRules,
	}
}

func requestHost(attrs *request.RequestAttributes) string {
	if attrs == nil || attrs.Additional == nil {
		return ""
	}
	host, _ := attrs.Additional["host"].(string)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.Trim(host, "[]")
	}
	return strings.ToLower(host)
}

func matchesAnonymousRule(rule AnonymousRequestRule, host, path string) bool {
	return (len(rule.Hosts) == 0 || matchesAnyPattern(rule.Hosts, host)) && matchesAnyPattern(rule.Paths, path)
}

// Decide denies anonymous subjects and issues the configured token types for
// authenticated subjects. When allow-anonymous path patterns are configured,
// anonymous requests on matching paths are allowed without issuing tokens.
func (p *StaticAuthenticatedPolicy) Decide(_ context.Context, in AuthzCheckPolicyInput) (AuthzCheckDecision, error) {
	if in.Subject.Anonymous {
		host, path := requestHost(in.Request), requestPath(in.Request)
		for _, rule := range p.anonymousRequestRules {
			if matchesAnonymousRule(rule, host, path) {
				return AuthzCheckDecision{Action: AuthzCheckAllowWithoutIssue}, nil
			}
		}
		return AuthzCheckDecision{
			Action: AuthzCheckDeny,
			Reason: anonymousSubjectDenyReason,
		}, nil
	}

	return AuthzCheckDecision{
		Action:     AuthzCheckIssue,
		TokenTypes: p.tokenTypes,
	}, nil
}
