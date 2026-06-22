package server

import (
	"context"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TokenTypeSpec specifies a token type to issue and how to deliver it
type TokenTypeSpec struct {
	// Type is the token type to issue
	Type service.TokenType

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string
}

// AuthzServer implements Envoy's ext_authz Authorization service
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer

	trustStore        trust.Store
	tokenService      *service.TokenService
	observer          service.AuthzCheckObserver
	credentialSources CredentialSources

	// TokenTypesToIssue specifies which token types to issue and their headers
	TokenTypesToIssue []TokenTypeSpec
}

// NewAuthzServer creates a new ext_authz server.
// credentialSources defines where credentials are extracted from for both
// subject and actor authentication.
func NewAuthzServer(trustStore trust.Store, tokenService *service.TokenService, tokenTypes []TokenTypeSpec, credentialSources CredentialSources, observer service.AuthzCheckObserver) *AuthzServer {
	// Default to transaction tokens if none specified
	if len(tokenTypes) == 0 {
		tokenTypes = []TokenTypeSpec{
			{
				Type:       service.TokenTypeTransactionToken,
				HeaderName: "Transaction-Token",
			},
		}
	}

	if observer == nil {
		observer = service.NoOpAuthzCheckObserver{}
	}

	return &AuthzServer{
		trustStore:        trustStore,
		tokenService:      tokenService,
		TokenTypesToIssue: tokenTypes,
		observer:          observer,
		credentialSources: credentialSources,
	}
}

// Check implements the ext_authz check endpoint
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	// Create request-scoped probe
	ctx, p := s.observer.AuthzCheckStarted(ctx)
	defer p.End()

	// 1. Build request attributes
	reqAttrs := s.buildRequestAttributes(req)
	p.RequestAttributesParsed(reqAttrs)

	// 2. Authenticate actor from gRPC context
	actor, err := authenticateActor(ctx, s.credentialSources, s.trustStore, p)
	if err != nil {
		return s.denyResponse(codes.Unauthenticated,
			fmt.Sprintf("%v", err)), nil
	}

	// 3. Filter trust store based on actor permissions
	filteredStore, err := s.trustStore.ForActor(ctx, actor, reqAttrs)
	if err != nil {
		return s.denyResponse(codes.PermissionDenied,
			fmt.Sprintf("failed to filter trust store: %v", err)), nil
	}

	// 4. Extract subject credentials from request
	cc, err := CredentialContextFromCheckRequest(req)
	if err != nil {
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	ext, err := s.credentialSources.Extract(ctx, cc)
	if err != nil {
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}
	p.SubjectCredentialExtracted(ext.Credential, ext.HeadersToRemove)

	// 5. Validate subject credentials against filtered trust store
	result, err := validateCredential(ctx, filteredStore, ext)
	if err != nil {
		p.SubjectValidationFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("validation failed: %v", err)), nil
	}
	p.SubjectValidationSucceeded(result)

	// 6. Issue tokens via TokenService
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

	// 7. Build response headers from issued tokens and credential sanitization
	responseHeaders := make([]*corev3.HeaderValueOption, 0, len(issuedTokens)+len(ext.HeadersToSet))
	for _, spec := range s.TokenTypesToIssue {
		if token, ok := issuedTokens[spec.Type]; ok {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   spec.HeaderName,
					Value: token.Value,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}
	for name, value := range ext.HeadersToSet {
		responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   name,
				Value: value,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	// 8. Return OK with issued tokens in headers
	// Remove the external credential headers so they don't leak to backend
	// This creates a security boundary - external credentials stay outside
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: responseHeaders,
				// Remove external credential headers - security boundary
				HeadersToRemove: ext.HeadersToRemove,
			},
		},
	}, nil
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
