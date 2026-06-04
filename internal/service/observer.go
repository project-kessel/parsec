package service

import (
	"context"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// TokenServiceObserver creates request-scoped observability probes for token issuance.
// This observer lives at the service level and creates a new probe for each issuance request.
//
// Following the pattern from https://martinfowler.com/articles/domain-oriented-observability.html#IncludingExecutionContext,
// the observer captures execution context at the start of an operation and returns a
// request-scoped probe that doesn't require context to be passed to each method.
type TokenServiceObserver interface {
	// TokenIssuanceStarted creates a new request-scoped probe for token issuance.
	// Returns an instrumented context (e.g., with trace span) and a probe scoped to this request.
	TokenIssuanceStarted(ctx context.Context, subject *trust.Result, actor *trust.Result, scope string, tokenTypes []TokenType) (context.Context, TokenIssuanceProbe)
}

// TokenIssuanceProbe provides request-scoped observability for a single token issuance operation.
// The probe captures execution context at creation and doesn't require it to be passed to each method.
//
// The probe lifecycle:
//  1. Created by TokenServiceObserver.TokenIssuanceStarted()
//  2. Events reported via TokenTypeIssuance* methods
//  3. Terminated with End() - typically deferred
type TokenIssuanceProbe interface {
	// TokenTypeIssuanceStarted is called when issuance begins for a specific token type.
	TokenTypeIssuanceStarted(tokenType TokenType)

	// TokenTypeIssuanceSucceeded is called when a token of a specific type is successfully issued.
	TokenTypeIssuanceSucceeded(tokenType TokenType, token *Token)

	// TokenTypeIssuanceFailed is called when issuance fails for a specific token type.
	TokenTypeIssuanceFailed(tokenType TokenType, err error)

	// IssuerNotFound is called when no issuer is registered for a requested token type.
	IssuerNotFound(tokenType TokenType, err error)

	// End terminates the observation. Should be deferred to ensure cleanup.
	// The probe determines success/failure based on methods called before End().
	End()
}

// TokenExchangeObserver creates request-scoped observability probes for token exchange operations.
// Follows the same pattern as TokenServiceObserver.
type TokenExchangeObserver interface {
	// TokenExchangeStarted creates a new request-scoped probe for a token exchange request.
	// Returns an instrumented context and a probe scoped to this request.
	TokenExchangeStarted(ctx context.Context, grantType string, requestedTokenType string, audience string, scope string) (context.Context, TokenExchangeProbe)
}

// TokenExchangeProbe provides request-scoped observability for a single token exchange operation.
type TokenExchangeProbe interface {
	// ActorCredentialExtracted is called when actor (caller) credentials are
	// successfully extracted from the gRPC context.
	ActorCredentialExtracted(cred trust.Credential, headersUsed []string)

	// ActorCredentialExtractionFailed is called when actor credential extraction fails.
	ActorCredentialExtractionFailed(err error)

	// ActorValidationSucceeded is called when actor credential validation succeeds.
	ActorValidationSucceeded(actor *trust.Result)

	// ActorValidationFailed is called when actor credential validation fails.
	ActorValidationFailed(err error)

	// RequestContextParsed is called when request_context is successfully parsed and filtered.
	RequestContextParsed(attrs *request.RequestAttributes)

	// RequestContextParseFailed is called when request_context parsing fails.
	RequestContextParseFailed(err error)

	// SubjectTokenValidationSucceeded is called when subject token validation succeeds.
	SubjectTokenValidationSucceeded(subject *trust.Result)

	// SubjectTokenValidationFailed is called when subject token validation fails.
	SubjectTokenValidationFailed(err error)

	// End terminates the observation. Should be deferred to ensure cleanup.
	End()
}

// AuthzCheckObserver creates request-scoped observability probes for authorization checks.
// Follows the same pattern as TokenServiceObserver.
type AuthzCheckObserver interface {
	// AuthzCheckStarted creates a new request-scoped probe for an authorization check.
	// Returns an instrumented context and a probe scoped to this request.
	AuthzCheckStarted(ctx context.Context) (context.Context, AuthzCheckProbe)
}

// AuthzCheckProbe provides request-scoped observability for a single authorization check operation.
type AuthzCheckProbe interface {
	// RequestAttributesParsed is called when request attributes are built from the incoming request.
	RequestAttributesParsed(attrs *request.RequestAttributes)

	// ActorCredentialExtracted is called when actor credentials are successfully
	// extracted from the gRPC context.
	ActorCredentialExtracted(cred trust.Credential, headersUsed []string)

	// ActorCredentialExtractionFailed is called when actor credential extraction fails.
	ActorCredentialExtractionFailed(err error)

	// ActorValidationSucceeded is called when actor credential validation succeeds.
	ActorValidationSucceeded(actor *trust.Result)

	// ActorValidationFailed is called when actor credential validation fails.
	ActorValidationFailed(err error)

	// SubjectCredentialExtracted is called when subject credentials are successfully extracted.
	SubjectCredentialExtracted(cred trust.Credential, headersUsed []string)

	// SubjectCredentialExtractionFailed is called when subject credential extraction fails.
	SubjectCredentialExtractionFailed(err error)

	// SubjectValidationSucceeded is called when subject credential validation succeeds.
	SubjectValidationSucceeded(subject *trust.Result)

	// SubjectValidationFailed is called when subject credential validation fails.
	SubjectValidationFailed(err error)

	// End terminates the observation. Should be deferred to ensure cleanup.
	End()
}

// ServiceObserver provides a unified interface for all observability concerns in the application.
// Concrete implementations can implement all three interfaces in a single type.
// Implementations can embed the NoOp* types to get default behavior for methods they don't care about.
type ServiceObserver interface {
	TokenServiceObserver
	TokenExchangeObserver
	AuthzCheckObserver
}

// --- NoOp probe implementations ---

// NoOpTokenIssuanceProbe is a no-op implementation of TokenIssuanceProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpTokenIssuanceProbe struct{}

func (NoOpTokenIssuanceProbe) TokenTypeIssuanceStarted(TokenType)           {}
func (NoOpTokenIssuanceProbe) TokenTypeIssuanceSucceeded(TokenType, *Token) {}
func (NoOpTokenIssuanceProbe) TokenTypeIssuanceFailed(TokenType, error)     {}
func (NoOpTokenIssuanceProbe) IssuerNotFound(TokenType, error)              {}
func (NoOpTokenIssuanceProbe) End()                                         {}

// NoOpTokenExchangeProbe is a no-op implementation of TokenExchangeProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpTokenExchangeProbe struct{}

func (NoOpTokenExchangeProbe) ActorCredentialExtracted(trust.Credential, []string) {}
func (NoOpTokenExchangeProbe) ActorCredentialExtractionFailed(error)               {}
func (NoOpTokenExchangeProbe) ActorValidationSucceeded(*trust.Result)              {}
func (NoOpTokenExchangeProbe) ActorValidationFailed(error)                         {}
func (NoOpTokenExchangeProbe) RequestContextParsed(*request.RequestAttributes)     {}
func (NoOpTokenExchangeProbe) RequestContextParseFailed(error)                     {}
func (NoOpTokenExchangeProbe) SubjectTokenValidationSucceeded(*trust.Result)       {}
func (NoOpTokenExchangeProbe) SubjectTokenValidationFailed(error)                  {}
func (NoOpTokenExchangeProbe) End()                                                {}

// NoOpAuthzCheckProbe is a no-op implementation of AuthzCheckProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpAuthzCheckProbe struct{}

func (NoOpAuthzCheckProbe) RequestAttributesParsed(*request.RequestAttributes)    {}
func (NoOpAuthzCheckProbe) ActorCredentialExtracted(trust.Credential, []string)   {}
func (NoOpAuthzCheckProbe) ActorCredentialExtractionFailed(error)                 {}
func (NoOpAuthzCheckProbe) ActorValidationSucceeded(*trust.Result)                {}
func (NoOpAuthzCheckProbe) ActorValidationFailed(error)                           {}
func (NoOpAuthzCheckProbe) SubjectCredentialExtracted(trust.Credential, []string) {}
func (NoOpAuthzCheckProbe) SubjectCredentialExtractionFailed(error)               {}
func (NoOpAuthzCheckProbe) SubjectValidationSucceeded(*trust.Result)              {}
func (NoOpAuthzCheckProbe) SubjectValidationFailed(error)                         {}
func (NoOpAuthzCheckProbe) End()                                                  {}

// --- NoOp observer implementations ---

type NoOpTokenServiceObserver struct{}

func (NoOpTokenServiceObserver) TokenIssuanceStarted(ctx context.Context, _ *trust.Result, _ *trust.Result, _ string, _ []TokenType) (context.Context, TokenIssuanceProbe) {
	return ctx, NoOpTokenIssuanceProbe{}
}

type NoOpTokenExchangeObserver struct{}

func (NoOpTokenExchangeObserver) TokenExchangeStarted(ctx context.Context, _ string, _ string, _ string, _ string) (context.Context, TokenExchangeProbe) {
	return ctx, NoOpTokenExchangeProbe{}
}

type NoOpAuthzCheckObserver struct{}

func (NoOpAuthzCheckObserver) AuthzCheckStarted(ctx context.Context) (context.Context, AuthzCheckProbe) {
	return ctx, NoOpAuthzCheckProbe{}
}

// NoOpServiceObserver satisfies ServiceObserver with empty probes.
type NoOpServiceObserver struct {
	NoOpTokenServiceObserver
	NoOpTokenExchangeObserver
	NoOpAuthzCheckObserver
}

var _ ServiceObserver = NoOpServiceObserver{}
