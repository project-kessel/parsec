package service

import (
	"context"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// OAuthErrorCode is a wire "error" value for token exchange
// (RFC 6749 §5.2, RFC 8693 §2.2.2).
type OAuthErrorCode string

const (
	OAuthInvalidRequest       OAuthErrorCode = "invalid_request"
	OAuthInvalidTarget        OAuthErrorCode = "invalid_target"
	OAuthInvalidGrant         OAuthErrorCode = "invalid_grant"
	OAuthUnauthorizedClient   OAuthErrorCode = "unauthorized_client"
	OAuthInvalidClient        OAuthErrorCode = "invalid_client"
	OAuthUnsupportedGrantType OAuthErrorCode = "unsupported_grant_type"
	OAuthInvalidScope         OAuthErrorCode = "invalid_scope"
	// OAuthAccessDenied is used for policy-level denials (RFC 6749 §4.1.2.1:
	// "the resource owner or authorization server denied the request"). Maps to
	// HTTP 403 in ext_authz — appropriate for export compliance and similar
	// access-control policies that are not protocol errors.
	OAuthAccessDenied OAuthErrorCode = "access_denied"
)

// AbortReason is a machine-readable reason for Layer B deny helpers.
// Each reason maps to exactly one OAuthErrorCode via OAuthCodeForReason.
type AbortReason string

const (
	AbortReasonInvalidSubject       AbortReason = "invalid_subject"
	AbortReasonInvalidActor         AbortReason = "invalid_actor"
	AbortReasonInvalidAudience      AbortReason = "invalid_audience"
	AbortReasonUnsupportedTokenType AbortReason = "unsupported_token_type"
)

// reasonToOAuthCode maps each Layer B abort reason to its Layer A OAuth code.
// This table is the single source of truth for the reason→code relationship,
// so non-CEL mappers get the same mapping without repeating it.
var reasonToOAuthCode = map[AbortReason]OAuthErrorCode{
	AbortReasonInvalidSubject:       OAuthInvalidRequest,
	AbortReasonInvalidActor:         OAuthInvalidRequest,
	AbortReasonInvalidAudience:      OAuthInvalidTarget,
	AbortReasonUnsupportedTokenType: OAuthInvalidRequest,
}

// OAuthCodeForReason returns the OAuth error code for a Layer B abort reason.
// Unknown reasons default to invalid_request.
func OAuthCodeForReason(reason AbortReason) OAuthErrorCode {
	if code, ok := reasonToOAuthCode[reason]; ok {
		return code
	}
	return OAuthInvalidRequest
}

// MappingAction is the expected outcome of a claim mapper evaluation.
// Analogous to AuthzCheckAction: denials are normal outcomes, not errors.
type MappingAction string

const (
	// MappingAllow means the mapper contributed claims (or nothing) and
	// issuance may proceed.
	MappingAllow MappingAction = "allow"

	// MappingDeny means the mapper rejected the input with an OAuth client
	// error. This is an expected protocol outcome, not an unexpected failure.
	MappingDeny MappingAction = "deny"
)

// MappingDecision is an expected mapper/policy outcome.
// Deny embeds an *ExchangeError carrying OAuth wire fields; Allow leaves it nil.
type MappingDecision struct {
	Action MappingAction
	*ExchangeError
}

// IsAllow reports whether the decision permits continuing mapper merge /
// issuance. Empty Action is treated as Allow.
func (d MappingDecision) IsAllow() bool {
	return d.Action == MappingAllow || d.Action == ""
}

// AsExchangeError returns the embedded ExchangeError for Deny decisions,
// or nil for Allow.
func (d MappingDecision) AsExchangeError() *ExchangeError {
	if d.IsAllow() {
		return nil
	}
	return d.ExchangeError
}

// MappingResult is the structured return value of ClaimMapper.Map.
// Expected OAuth denials are expressed via Decision; error is reserved for
// unexpected failures (fail(), eval bugs, datasource failures, …).
type MappingResult struct {
	Claims   claims.Claims
	Decision MappingDecision
}

// AllowResult returns an Allow MappingResult with the given claims.
func AllowResult(c claims.Claims) MappingResult {
	return MappingResult{
		Claims:   c,
		Decision: MappingDecision{Action: MappingAllow},
	}
}

// DenyOAuth returns a Deny MappingResult for a Layer A OAuth error code.
func DenyOAuth(code OAuthErrorCode, message string) MappingResult {
	return denyResult(code, "", message)
}

// DenyReason returns a Deny MappingResult for a Layer B abort reason.
// The reason is mapped to the appropriate OAuth error code via reasonToOAuthCode.
func DenyReason(reason AbortReason, message string) MappingResult {
	return denyResult(OAuthCodeForReason(reason), reason, message)
}

func denyResult(oauthError OAuthErrorCode, reason AbortReason, message string) MappingResult {
	return MappingResult{
		Decision: MappingDecision{
			Action: MappingDeny,
			ExchangeError: &ExchangeError{
				OAuthError: oauthError,
				Reason:     reason,
				Message:    message,
			},
		},
	}
}

// Merge combines another mapper's result into r (ordered composition).
//
// Rules:
//   - If r is already non-Allow, r is returned unchanged (first non-allow wins).
//   - If other is non-Allow, return a result with other's Decision and no claims
//     (partial allow claims must not linger on a deny).
//   - If both Allow, claims are merged (other overwrites on key conflict).
func (r MappingResult) Merge(other MappingResult) MappingResult {
	if !r.Decision.IsAllow() {
		return r
	}
	if !other.Decision.IsAllow() {
		d := other.Decision
		if d.Action == "" {
			d.Action = MappingDeny
		}
		return MappingResult{Decision: d}
	}

	out := r
	if out.Decision.Action == "" {
		out.Decision.Action = MappingAllow
	}
	if out.Claims == nil {
		out.Claims = make(claims.Claims)
	} else {
		// Copy so Merge does not mutate the receiver's underlying map when
		// callers reuse MappingResult values.
		out.Claims = out.Claims.Copy()
		if out.Claims == nil {
			out.Claims = make(claims.Claims)
		}
	}
	out.Claims.Merge(other.Claims)
	return out
}

// ExchangeError represents a known token-exchange denial: the request was
// understood but issuance was refused for a policy/protocol reason expressible
// as an OAuth error. Unexpected failures use MappingFailure (or plain errors).
type ExchangeError struct {
	Message    string         // error_description
	OAuthError OAuthErrorCode // wire "error"
	Reason     AbortReason    // optional Layer B reason for observability
}

func (e *ExchangeError) Error() string {
	return e.Message
}

// MappingFailure is an unexpected claim-mapping/system failure (CEL fail(),
// eval bugs surfaced as typed failures). It is distinct from ExchangeError:
// transports treat it as Internal, never as an OAuth client error body.
type MappingFailure struct {
	Message string
}

func (e *MappingFailure) Error() string {
	return e.Message
}

// ExchangeResult is the explicit outcome of Issuer.Issue.
// Exactly one of Token or ExchangeErr is non-nil.
type ExchangeResult struct {
	Token       *Token
	ExchangeErr *ExchangeError
}

// ClaimMapper transforms inputs into claims for the token.
// Claim mappers implement policy logic — what information to include in tokens
// and whether issuance should be denied with an OAuth client error.
type ClaimMapper interface {
	// Map produces a MappingResult. Decision carries expected Allow/Deny
	// outcomes; error is only for unexpected failures.
	Map(ctx context.Context, input *MapperInput) (MappingResult, error)
}

// MapperInput contains all inputs available to a claim mapper
type MapperInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Actor identity (attested claims from actor credential)
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// DataSourceRegistry provides access to data sources for lazy fetching
	// Mappers can fetch only the data sources they need
	DataSourceRegistry *DataSourceRegistry

	// DataSourceInput is the input to use when fetching from data sources
	DataSourceInput *DataSourceInput
}
