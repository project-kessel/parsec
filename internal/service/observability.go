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

// ApplicationObserver provides a unified interface for all observability concerns in the application.
// Concrete implementations can implement all three interfaces in a single type.
// Implementations can embed the NoOp* types to get default behavior for methods they don't care about.
type ApplicationObserver interface {
	TokenServiceObserver
	TokenExchangeObserver
	AuthzCheckObserver
}

// compositeObserver delegates to multiple observers in order.
// Useful for combining logging, metrics, and tracing.
type compositeObserver struct {
	observers []ApplicationObserver
}

// NewCompositeObserver creates an observer that delegates to multiple observers.
// Observers are called in the order provided.
func NewCompositeObserver(observers ...ApplicationObserver) ApplicationObserver {
	return &compositeObserver{observers: observers}
}

func (c *compositeObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []TokenType,
) (context.Context, TokenIssuanceProbe) {
	probes := make([]TokenIssuanceProbe, len(c.observers))
	for i, obs := range c.observers {
		ctx, probes[i] = obs.TokenIssuanceStarted(ctx, subject, actor, scope, tokenTypes)
	}
	return ctx, &compositeTokenIssuanceProbe{probes: probes}
}

func (c *compositeObserver) TokenExchangeStarted(
	ctx context.Context,
	grantType string,
	requestedTokenType string,
	audience string,
	scope string,
) (context.Context, TokenExchangeProbe) {
	probes := make([]TokenExchangeProbe, len(c.observers))
	for i, obs := range c.observers {
		ctx, probes[i] = obs.TokenExchangeStarted(ctx, grantType, requestedTokenType, audience, scope)
	}
	return ctx, &compositeTokenExchangeProbe{probes: probes}
}

func (c *compositeObserver) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, AuthzCheckProbe) {
	probes := make([]AuthzCheckProbe, len(c.observers))
	for i, obs := range c.observers {
		ctx, probes[i] = obs.AuthzCheckStarted(ctx)
	}
	return ctx, &compositeAuthzCheckProbe{probes: probes}
}

// compositeTokenIssuanceProbe delegates to multiple probes in order.
type compositeTokenIssuanceProbe struct {
	probes []TokenIssuanceProbe
}

func (c *compositeTokenIssuanceProbe) TokenTypeIssuanceStarted(tokenType TokenType) {
	for _, probe := range c.probes {
		probe.TokenTypeIssuanceStarted(tokenType)
	}
}

func (c *compositeTokenIssuanceProbe) TokenTypeIssuanceSucceeded(tokenType TokenType, token *Token) {
	for _, probe := range c.probes {
		probe.TokenTypeIssuanceSucceeded(tokenType, token)
	}
}

func (c *compositeTokenIssuanceProbe) TokenTypeIssuanceFailed(tokenType TokenType, err error) {
	for _, probe := range c.probes {
		probe.TokenTypeIssuanceFailed(tokenType, err)
	}
}

func (c *compositeTokenIssuanceProbe) IssuerNotFound(tokenType TokenType, err error) {
	for _, probe := range c.probes {
		probe.IssuerNotFound(tokenType, err)
	}
}

func (c *compositeTokenIssuanceProbe) End() {
	for _, probe := range c.probes {
		probe.End()
	}
}

// compositeTokenExchangeProbe delegates to multiple TokenExchangeProbe instances
type compositeTokenExchangeProbe struct {
	probes []TokenExchangeProbe
}

func (c *compositeTokenExchangeProbe) ActorValidationSucceeded(actor *trust.Result) {
	for _, probe := range c.probes {
		probe.ActorValidationSucceeded(actor)
	}
}

func (c *compositeTokenExchangeProbe) ActorValidationFailed(err error) {
	for _, probe := range c.probes {
		probe.ActorValidationFailed(err)
	}
}

func (c *compositeTokenExchangeProbe) RequestContextParsed(attrs *request.RequestAttributes) {
	for _, probe := range c.probes {
		probe.RequestContextParsed(attrs)
	}
}

func (c *compositeTokenExchangeProbe) RequestContextParseFailed(err error) {
	for _, probe := range c.probes {
		probe.RequestContextParseFailed(err)
	}
}

func (c *compositeTokenExchangeProbe) SubjectTokenValidationSucceeded(subject *trust.Result) {
	for _, probe := range c.probes {
		probe.SubjectTokenValidationSucceeded(subject)
	}
}

func (c *compositeTokenExchangeProbe) SubjectTokenValidationFailed(err error) {
	for _, probe := range c.probes {
		probe.SubjectTokenValidationFailed(err)
	}
}

func (c *compositeTokenExchangeProbe) End() {
	for _, probe := range c.probes {
		probe.End()
	}
}

// compositeAuthzCheckProbe delegates to multiple AuthzCheckProbe instances
type compositeAuthzCheckProbe struct {
	probes []AuthzCheckProbe
}

func (c *compositeAuthzCheckProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	for _, probe := range c.probes {
		probe.RequestAttributesParsed(attrs)
	}
}

func (c *compositeAuthzCheckProbe) ActorValidationSucceeded(actor *trust.Result) {
	for _, probe := range c.probes {
		probe.ActorValidationSucceeded(actor)
	}
}

func (c *compositeAuthzCheckProbe) ActorValidationFailed(err error) {
	for _, probe := range c.probes {
		probe.ActorValidationFailed(err)
	}
}

func (c *compositeAuthzCheckProbe) SubjectCredentialExtracted(cred trust.Credential, headersUsed []string) {
	for _, probe := range c.probes {
		probe.SubjectCredentialExtracted(cred, headersUsed)
	}
}

func (c *compositeAuthzCheckProbe) SubjectCredentialExtractionFailed(err error) {
	for _, probe := range c.probes {
		probe.SubjectCredentialExtractionFailed(err)
	}
}

func (c *compositeAuthzCheckProbe) SubjectValidationSucceeded(subject *trust.Result) {
	for _, probe := range c.probes {
		probe.SubjectValidationSucceeded(subject)
	}
}

func (c *compositeAuthzCheckProbe) SubjectValidationFailed(err error) {
	for _, probe := range c.probes {
		probe.SubjectValidationFailed(err)
	}
}

func (c *compositeAuthzCheckProbe) End() {
	for _, probe := range c.probes {
		probe.End()
	}
}

// NoOpTokenIssuanceProbe is an exported null object implementation of TokenIssuanceProbe.
// Implementations can embed this to get default no-op behavior, allowing new methods
// to be added to the interface without breaking existing implementations.
type NoOpTokenIssuanceProbe struct{}

func (n *NoOpTokenIssuanceProbe) TokenTypeIssuanceStarted(tokenType TokenType)                 {}
func (n *NoOpTokenIssuanceProbe) TokenTypeIssuanceSucceeded(tokenType TokenType, token *Token) {}
func (n *NoOpTokenIssuanceProbe) TokenTypeIssuanceFailed(tokenType TokenType, err error)       {}
func (n *NoOpTokenIssuanceProbe) IssuerNotFound(tokenType TokenType, err error)                {}
func (n *NoOpTokenIssuanceProbe) End()                                                         {}

// NoOpTokenExchangeProbe is an exported null object implementation of TokenExchangeProbe.
// Implementations can embed this to get default no-op behavior.
type NoOpTokenExchangeProbe struct{}

func (n *NoOpTokenExchangeProbe) ActorValidationSucceeded(actor *trust.Result)          {}
func (n *NoOpTokenExchangeProbe) ActorValidationFailed(err error)                       {}
func (n *NoOpTokenExchangeProbe) RequestContextParsed(attrs *request.RequestAttributes) {}
func (n *NoOpTokenExchangeProbe) RequestContextParseFailed(err error)                   {}
func (n *NoOpTokenExchangeProbe) SubjectTokenValidationSucceeded(subject *trust.Result) {}
func (n *NoOpTokenExchangeProbe) SubjectTokenValidationFailed(err error)                {}
func (n *NoOpTokenExchangeProbe) End()                                                  {}

// NoOpAuthzCheckProbe is an exported null object implementation of AuthzCheckProbe.
// Implementations can embed this to get default no-op behavior.
type NoOpAuthzCheckProbe struct{}

func (n *NoOpAuthzCheckProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {}
func (n *NoOpAuthzCheckProbe) ActorValidationSucceeded(actor *trust.Result)             {}
func (n *NoOpAuthzCheckProbe) ActorValidationFailed(err error)                          {}
func (n *NoOpAuthzCheckProbe) SubjectCredentialExtracted(cred trust.Credential, headersUsed []string) {
}
func (n *NoOpAuthzCheckProbe) SubjectCredentialExtractionFailed(err error)      {}
func (n *NoOpAuthzCheckProbe) SubjectValidationSucceeded(subject *trust.Result) {}
func (n *NoOpAuthzCheckProbe) SubjectValidationFailed(err error)                {}
func (n *NoOpAuthzCheckProbe) End()                                             {}

// NoOpApplicationObserver implements ApplicationObserver with no-op behavior.
// Use this as a default when no observability is needed.
type NoOpApplicationObserver struct{}

// NoOpTokenServiceObserver returns an observer that does nothing.
// Use this as a default when no observability is needed.
func NoOpTokenServiceObserver() TokenServiceObserver {
	return &NoOpApplicationObserver{}
}

// NoOpTokenExchangeObserver returns an observer that does nothing.
func NoOpTokenExchangeObserver() TokenExchangeObserver {
	return &NoOpApplicationObserver{}
}

// NoOpAuthzCheckObserver returns an observer that does nothing.
func NoOpAuthzCheckObserver() AuthzCheckObserver {
	return &NoOpApplicationObserver{}
}

// NoOpObserver returns an application observer that does nothing.
func NoOpObserver() ApplicationObserver {
	return &NoOpApplicationObserver{}
}

func (n *NoOpApplicationObserver) TokenIssuanceStarted(ctx context.Context, subject *trust.Result, actor *trust.Result, scope string, tokenTypes []TokenType) (context.Context, TokenIssuanceProbe) {
	return ctx, &NoOpTokenIssuanceProbe{}
}

func (n *NoOpApplicationObserver) TokenExchangeStarted(ctx context.Context, grantType string, requestedTokenType string, audience string, scope string) (context.Context, TokenExchangeProbe) {
	return ctx, &NoOpTokenExchangeProbe{}
}

func (n *NoOpApplicationObserver) AuthzCheckStarted(ctx context.Context) (context.Context, AuthzCheckProbe) {
	return ctx, &NoOpAuthzCheckProbe{}
}
