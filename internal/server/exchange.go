package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// ExchangeServer implements the TokenExchange gRPC service
type ExchangeServer struct {
	parsecv1.UnimplementedTokenExchangeServiceServer

	trustStore              trust.Store
	tokenService            *service.TokenService
	claimsFilterRegistry    ClaimsFilterRegistry
	observer                service.TokenExchangeObserver
	callerCredentialSources CredentialSources
}

// NewExchangeServer creates a new token exchange server.
// callerCredentialSources defines where caller (actor) credentials are extracted from.
func NewExchangeServer(trustStore trust.Store, tokenService *service.TokenService, claimsFilterRegistry ClaimsFilterRegistry, callerCredentialSources CredentialSources, observer service.TokenExchangeObserver) *ExchangeServer {
	if observer == nil {
		observer = service.NoOpTokenExchangeObserver{}
	}

	return &ExchangeServer{
		trustStore:              trustStore,
		tokenService:            tokenService,
		claimsFilterRegistry:    claimsFilterRegistry,
		observer:                observer,
		callerCredentialSources: callerCredentialSources,
	}
}

// Exchange implements the token exchange endpoint (RFC 8693)
func (s *ExchangeServer) Exchange(ctx context.Context, req *parsecv1.ExchangeRequest) (response *parsecv1.ExchangeResponse, returnErr error) {
	ctx = contextWithRequestID(ctx, nil, nil)
	_ = grpc.SetHeader(ctx, metadata.Pairs(requestIDHeader, request.ID(ctx)))

	// RFC 8693 defaults requested_token_type to access_token. Parsec issues a
	// transaction token for that default to preserve its existing behavior.
	requestedTokenType := service.TokenTypeTransactionToken
	if req.RequestedTokenType != "" {
		requestedTokenType = service.TokenType(req.RequestedTokenType)
	}
	reasonCode := "internal_error"

	// Create request-scoped probe
	ctx, p := s.observer.TokenExchangeStarted(ctx, req.GrantType, req.RequestedTokenType, req.Audience, req.Scope)
	defer func() {
		p.RequestCompleted(exchangeRequestCompletion(returnErr, reasonCode, requestedTokenType))
		p.End()
	}()

	// 1. Validate the grant type
	if req.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		reasonCode = "grant_type_unsupported"
		return nil, fmt.Errorf("unsupported grant_type: %s", req.GrantType)
	}

	// 2. Authenticate actor (caller) from gRPC context
	actor, err := authenticateActor(ctx, s.callerCredentialSources, s.trustStore, p)
	if err != nil {
		reasonCode = "credential_invalid"
		return nil, err
	}

	// 3. Parse and filter client-provided request_context claims
	var reqAttrs *request.RequestAttributes
	if req.RequestContext != "" {
		// Parse request_context JSON (plain JSON per transaction token spec §11.1).
		// Legacy parsec clients may still send base64-encoded JSON; parseRequestContextClaims accepts both.
		requestContextClaims, err := parseRequestContextClaims(req.RequestContext)
		if err != nil {
			reasonCode = "invalid_request"
			p.RequestContextParseFailed(err)
			return nil, err
		}

		// Get the claims filter for this actor
		claimsFilter, err := s.claimsFilterRegistry.GetFilter(actor)
		if err != nil {
			reasonCode = auditReasonFromError(err, "internal_error")
			p.RequestContextParseFailed(err)
			return nil, fmt.Errorf("failed to get claims filter for actor: %w", err)
		}

		// Filter the claims based on actor permissions
		filteredClaims := claimsFilter.Filter(requestContextClaims)

		// Convert filtered claims to RequestAttributes
		reqAttrs = request.FromClaims(filteredClaims)
		p.RequestContextParsed(reqAttrs)
	} else {
		// No request_context provided, use empty attributes
		reqAttrs = request.FromClaims(nil)
		p.RequestContextParsed(reqAttrs)
	}

	// Add metadata from the token exchange request itself to Additional
	// These are not client-provided claims but server-side request metadata
	if req.Audience != "" {
		reqAttrs.Additional["requested_audience"] = req.Audience
	}
	if req.Scope != "" {
		reqAttrs.Additional["requested_scope"] = req.Scope
	}

	// 4. Filter trust store based on actor permissions
	filteredStore, err := s.trustStore.ForActor(ctx, actor, reqAttrs)
	if err != nil {
		reasonCode = auditReasonFromError(err, "scheme_not_allowed")
		return nil, fmt.Errorf("failed to filter trust store: %w", err)
	}

	// 5. Validate subject_token
	cred := subjectCredential(req.SubjectToken, req.SubjectTokenType)

	// Validate subject credential against filtered trust store
	result, err := filteredStore.Validate(ctx, cred)
	if err != nil {
		reasonCode = "credential_invalid"
		if errors.Is(err, trust.ErrExpiredToken) {
			reasonCode = "credential_expired"
		}
		p.SubjectTokenValidationFailed(err)
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	p.SubjectTokenValidationSucceeded(result)

	// 7. Validate audience matches trust domain (per transaction token spec)
	// The audience for transaction tokens is always the trust domain
	if req.Audience != "" && req.Audience != s.tokenService.TrustDomain() {
		reasonCode = "policy_denied"
		return nil, fmt.Errorf("requested audience %q does not match trust domain %q",
			req.Audience, s.tokenService.TrustDomain())
	}

	// 8. Issue the token via TokenService
	results, err := s.tokenService.IssueTokens(ctx, &service.IssueRequest{
		Subject:           result,
		Actor:             actor,
		RequestAttributes: reqAttrs,
		TokenTypes:        []service.TokenType{requestedTokenType},
		Scope:             req.Scope,
	})
	if err != nil {
		reasonCode = auditReasonFromError(err, "internal_error")
		return nil, internalGRPCError(err)
	}

	r, ok := results[requestedTokenType]
	if !ok {
		reasonCode = "internal_error"
		return nil, status.Errorf(codes.Internal, "token service did not return requested token type %s", requestedTokenType)
	}
	if r.ExchangeErr != nil {
		reasonCode = "policy_denied"
		return nil, exchangeErrToGRPC(r.ExchangeErr)
	}
	if r.Token == nil {
		reasonCode = "internal_error"
		return nil, status.Errorf(codes.Internal, "token service returned no token for type %s", requestedTokenType)
	}

	// 9. Return response
	reasonCode = ""
	return &parsecv1.ExchangeResponse{
		AccessToken:     r.Token.Value,
		IssuedTokenType: string(requestedTokenType),
		TokenType:       "Bearer",
		ExpiresIn:       int64(r.Token.ExpiresAt.Sub(r.Token.IssuedAt).Seconds()),
		Scope:           req.Scope,
	}, nil
}

// parseRequestContextClaims parses request_context claims.
//
// Supported formats (in order):
//  1. Plain JSON (draft-ietf-oauth-transaction-tokens-11 §11.1)
//  2. Legacy base64-wrapped JSON: standard (padded/unpadded) and base64url (padded/unpadded),
//     for parsec clients and draft-02–06 transaction-token encodings.
func parseRequestContextClaims(raw string) (claims.Claims, error) {
	var requestContextClaims claims.Claims
	if err := json.Unmarshal([]byte(raw), &requestContextClaims); err == nil {
		return requestContextClaims, nil
	}

	decodedJSON, err := decodeLegacyRequestContext(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request_context JSON: %w", err)
	}
	if err := json.Unmarshal(decodedJSON, &requestContextClaims); err != nil {
		return nil, fmt.Errorf("failed to parse request_context JSON: %w", err)
	}
	return requestContextClaims, nil
}

var legacyRequestContextEncodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.RawURLEncoding,
	base64.URLEncoding,
}

func decodeLegacyRequestContext(raw string) ([]byte, error) {
	for _, enc := range legacyRequestContextEncodings {
		decoded, err := enc.DecodeString(raw)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("request_context is neither valid JSON nor a supported legacy base64 encoding")
}
