package server

import (
	"context"

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

// StaticAuthenticatedPolicy is an AuthzCheckPolicy that denies anonymous
// subjects and issues a statically configured set of token types for
// authenticated subjects. This preserves the behavior that existed before
// the policy layer was introduced.
type StaticAuthenticatedPolicy struct {
	tokenTypes []TokenTypeSpec
}

// NewStaticAuthenticatedPolicy creates a policy that denies anonymous subjects
// and issues the given token types for authenticated subjects. If tokenTypes
// is empty, DefaultTokenTypeSpecs is used.
func NewStaticAuthenticatedPolicy(tokenTypes []TokenTypeSpec) *StaticAuthenticatedPolicy {
	if len(tokenTypes) == 0 {
		tokenTypes = DefaultTokenTypeSpecs()
	}
	return &StaticAuthenticatedPolicy{tokenTypes: tokenTypes}
}

// Decide denies anonymous subjects and issues the configured token types for
// authenticated subjects.
func (p *StaticAuthenticatedPolicy) Decide(_ context.Context, in AuthzCheckPolicyInput) (AuthzCheckDecision, error) {
	if in.Subject.Anonymous {
		return AuthzCheckDecision{
			Action: AuthzCheckDeny,
			Reason: "anonymous subjects not allowed",
		}, nil
	}

	return AuthzCheckDecision{
		Action:     AuthzCheckIssue,
		TokenTypes: p.tokenTypes,
	}, nil
}
