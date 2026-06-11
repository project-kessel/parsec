package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

var (
	ErrNoCredential                = errors.New("no credential")
	ErrUnsupportedCredentialScheme = errors.New("unsupported credential scheme")
)

// TokenTypeSpec specifies a token type to issue and how to deliver it
type TokenTypeSpec struct {
	// Type is the token type to issue
	Type service.TokenType

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string
}

// AuthzOption configures optional AuthzServer behavior.
type AuthzOption func(*AuthzServer)

func WithOptionalAuthPathMatcher(m *request.PathMatcher) AuthzOption {
	return func(s *AuthzServer) {
		s.optionalAuthMatcher = m
	}
}

// AuthzServer implements Envoy's ext_authz Authorization service
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer

	trustStore   trust.Store
	tokenService *service.TokenService
	observer     service.AuthzCheckObserver

	// TokenTypesToIssue specifies which token types to issue and their headers
	// This could come from configuration in the future
	TokenTypesToIssue []TokenTypeSpec

	optionalAuthMatcher *request.PathMatcher
}

// NewAuthzServer creates a new ext_authz server.
func NewAuthzServer(trustStore trust.Store, tokenService *service.TokenService, tokenTypes []TokenTypeSpec, observer service.AuthzCheckObserver, opts ...AuthzOption) *AuthzServer {
	// Default to transaction tokens if none specified
	if len(tokenTypes) == 0 {
		tokenTypes = []TokenTypeSpec{
			{
				Type:       service.TokenTypeTransactionToken,
				HeaderName: "Transaction-Token",
			},
		}
	}

	// Use null object pattern - default to no-op observer if none provided
	if observer == nil {
		observer = service.NoOpAuthzCheckObserver{}
	}

	s := &AuthzServer{
		trustStore:        trustStore,
		tokenService:      tokenService,
		TokenTypesToIssue: tokenTypes,
		observer:          observer,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Check implements the ext_authz check endpoint
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	ctx, p := s.observer.AuthzCheckStarted(ctx)
	defer p.End()

	reqAttrs := s.buildRequestAttributes(req)
	p.RequestAttributesParsed(reqAttrs)

	cred, headersUsed, err := s.extractCredential(req)
	if err != nil {
		p.SubjectCredentialExtractionFailed(err)
		if errors.Is(err, ErrNoCredential) {
			if resp, ok := s.tryOptionalAuthPassThrough(reqAttrs, p); ok {
				return resp, nil
			}
		}
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	return s.checkWithCredential(ctx, reqAttrs, cred, headersUsed, p)
}

func (s *AuthzServer) checkWithCredential(
	ctx context.Context,
	reqAttrs *request.RequestAttributes,
	cred trust.Credential,
	headersUsed []string,
	p service.AuthzCheckProbe,
) (*authv3.CheckResponse, error) {
	p.SubjectCredentialExtracted(cred, headersUsed)

	actorCred, err := extractActorCredential(ctx)
	if err != nil {
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("failed to extract actor credential: %v", err)), nil
	}

	var actor *trust.Result
	if actorCred != nil {
		var validationErr error
		actor, validationErr = s.trustStore.Validate(ctx, actorCred)
		if validationErr != nil {
			p.ActorValidationFailed(validationErr)
			return s.denyResponse(codes.Unauthenticated,
				fmt.Sprintf("actor validation failed: %v", validationErr)), nil
		}
		p.ActorValidationSucceeded(actor)
	} else {
		actor = trust.AnonymousResult()
		p.ActorValidationSucceeded(actor)
	}

	filteredStore, err := s.trustStore.ForActor(ctx, actor, reqAttrs)
	if err != nil {
		return s.denyResponse(codes.PermissionDenied,
			fmt.Sprintf("failed to filter trust store: %v", err)), nil
	}

	result, err := filteredStore.Validate(ctx, cred)
	if err != nil {
		p.SubjectValidationFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("validation failed: %v", err)), nil
	}
	p.SubjectValidationSucceeded(result)

	tokenTypes := make([]service.TokenType, len(s.TokenTypesToIssue))
	for i, spec := range s.TokenTypesToIssue {
		tokenTypes[i] = spec.Type
	}

	issuedTokens, err := s.tokenService.IssueTokens(ctx, &service.IssueRequest{
		Subject:           result,
		Actor:             actor,
		RequestAttributes: reqAttrs,
		TokenTypes:        tokenTypes,
		// TODO: Get scope from configuration or request
		Scope: "",
	})
	if err != nil {
		return s.denyResponse(codes.Internal, fmt.Sprintf("failed to issue tokens: %v", err)), nil
	}

	responseHeaders := make([]*corev3.HeaderValueOption, 0, len(issuedTokens))
	for _, spec := range s.TokenTypesToIssue {
		if token, ok := issuedTokens[spec.Type]; ok {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   spec.HeaderName,
					Value: token.Value,
				},
			})
		}
	}

	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers:         responseHeaders,
				HeadersToRemove: headersUsed,
			},
		},
	}, nil
}

// extractCredential extracts credentials from the Envoy request
// Returns the credential and the list of headers that were used to extract it
func (s *AuthzServer) extractCredential(req *authv3.CheckRequest) (trust.Credential, []string, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	// TODO: mtls e.g. cert := req.GetAttributes().GetSource().GetCertificate()

	if httpReq == nil {
		return nil, nil, fmt.Errorf("no HTTP request attributes")
	}

	// Look for Authorization header
	authHeader := httpReq.GetHeaders()["authorization"]
	if authHeader == "" {
		return nil, nil, ErrNoCredential
	}

	// Extract bearer token
	if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
		// For bearer tokens, the trust store determines which validator to use
		// based on its configuration (e.g., default validator, token introspection)
		cred := &trust.BearerCredential{
			Token: token,
		}
		// Return the credential and the headers that were used
		headersUsed := []string{"authorization"}
		return cred, headersUsed, nil
	}

	// Future: Handle other authentication schemes
	// - Basic auth: would use "authorization" header
	// - API key in custom header: would track that header name
	// - Cookie-based auth: would track cookie names

	return nil, nil, ErrUnsupportedCredentialScheme
}

func (s *AuthzServer) tryOptionalAuthPassThrough(reqAttrs *request.RequestAttributes, p service.AuthzCheckProbe) (*authv3.CheckResponse, bool) {
	canonPath, ok := request.ParseMatchPath(reqAttrs.Path)
	if !ok || !s.optionalAuthMatcher.MatchesPath(canonPath) {
		return nil, false
	}
	p.OptionalAuthPassThrough(reqAttrs)
	return s.allowResponse(), true
}

// buildRequestAttributes extracts request attributes from the Envoy request
func (s *AuthzServer) buildRequestAttributes(req *authv3.CheckRequest) *request.RequestAttributes {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return &request.RequestAttributes{}
	}

	additional := map[string]any{
		"host": httpReq.GetHost(),
	}

	// Add Envoy context extensions
	// These are custom key-value pairs set by Envoy configuration
	// and provide additional context about the request
	if contextExtensions := req.GetAttributes().GetContextExtensions(); len(contextExtensions) > 0 {
		additional["context_extensions"] = contextExtensions
	}

	return &request.RequestAttributes{
		Method:     httpReq.GetMethod(),
		Path:       httpReq.GetPath(),
		IPAddress:  req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress(),
		UserAgent:  httpReq.GetHeaders()["user-agent"],
		Headers:    httpReq.GetHeaders(),
		Additional: additional,
	}
}

func (s *AuthzServer) allowResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

// denyResponse creates a denial response
func (s *AuthzServer) denyResponse(code codes.Code, message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code:    int32(code),
			Message: message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Body: message,
			},
		},
	}
}
