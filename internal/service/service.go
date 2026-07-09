package service

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// TokenService orchestrates token issuance
// This is the core business logic that brings together data sources
// and issuers to produce tokens
type TokenService struct {
	trustDomain    string
	dataSources    *DataSourceRegistry
	issuerRegistry Registry
	observer       TokenServiceObserver
	issuancePolicy IssuancePolicy
}

// TokenServiceOption configures optional TokenService behavior.
type TokenServiceOption func(*TokenService)

// WithIssuancePolicy sets a policy that is evaluated before any tokens are
// issued. The policy receives the validated subject and may reject issuance
// based on the subject's claims.
func WithIssuancePolicy(p IssuancePolicy) TokenServiceOption {
	return func(ts *TokenService) {
		ts.issuancePolicy = p
	}
}

// NewTokenService creates a new token service
func NewTokenService(
	trustDomain string,
	dataSources *DataSourceRegistry,
	issuerRegistry Registry,
	observer TokenServiceObserver,
	opts ...TokenServiceOption,
) *TokenService {
	if observer == nil {
		observer = NoOpTokenServiceObserver{}
	}
	ts := &TokenService{
		trustDomain:    trustDomain,
		dataSources:    dataSources,
		issuerRegistry: issuerRegistry,
		observer:       observer,
	}
	for _, opt := range opts {
		opt(ts)
	}
	return ts
}

// TrustDomain returns the trust domain for this token service
// The trust domain is used as the audience for all issued tokens
func (ts *TokenService) TrustDomain() string {
	return ts.trustDomain
}

// IssueRequest contains the inputs for token issuance
type IssueRequest struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Actor identity (attested claims from actor credential, e.g., mTLS)
	// May be nil if actor identity is not available
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// TokenTypes specifies which token types to issue
	TokenTypes []TokenType

	// Scope for the tokens
	Scope string
}

// IssueTokens orchestrates the complete token issuance process
// Returns a map of token type to issued token
func (ts *TokenService) IssueTokens(ctx context.Context, req *IssueRequest) (map[TokenType]*Token, error) {
	ctx, p := ts.observer.TokenIssuanceStarted(ctx, req.Subject, req.Actor, req.Scope, req.TokenTypes)
	defer p.End()

	if ts.issuancePolicy != nil {
		if err := ts.issuancePolicy.Evaluate(ctx, req.Subject); err != nil {
			p.IssuancePolicyDenied(err)
			return nil, fmt.Errorf("issuance policy: %w", err)
		}
	}

	// Build issue context with base information needed for all issuers
	// Audience is always the trust domain per transaction token spec
	issueCtx := &IssueContext{
		Subject:            req.Subject,
		Actor:              req.Actor,
		RequestAttributes:  req.RequestAttributes,
		Audience:           ts.trustDomain,
		Scope:              req.Scope,
		DataSourceRegistry: ts.dataSources,
	}

	// Issue tokens for each requested type
	tokens := make(map[TokenType]*Token)
	for _, tokenType := range req.TokenTypes {
		p.TokenTypeIssuanceStarted(tokenType)

		iss, err := ts.issuerRegistry.GetIssuer(tokenType)
		if err != nil {
			p.IssuerNotFound(tokenType, err)
			return nil, fmt.Errorf("no issuer for token type %s: %w", tokenType, err)
		}

		token, err := iss.Issue(ctx, issueCtx)
		if err != nil {
			p.TokenTypeIssuanceFailed(tokenType, err)
			return nil, fmt.Errorf("failed to issue %s: %w", tokenType, err)
		}

		p.TokenTypeIssuanceSucceeded(tokenType, token)
		tokens[tokenType] = token
	}

	return tokens, nil
}
