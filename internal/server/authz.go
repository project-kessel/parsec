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

var ErrUnsupportedCredentialScheme = errors.New("unsupported credential scheme")

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

func WithAnonymousSubjectPolicy(p AnonymousSubjectPolicy) AuthzOption {
	return func(s *AuthzServer) {
		s.anonymousSubjectPolicy = p
	}
}

func WithIssuancePolicy(p IssuancePolicy) AuthzOption {
	return func(s *AuthzServer) {
		s.issuancePolicy = p
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

	anonymousSubjectPolicy AnonymousSubjectPolicy
	issuancePolicy         IssuancePolicy
}

// NewAuthzServer creates a new ext_authz server.
func NewAuthzServer(trustStore trust.Store, tokenService *service.TokenService, tokenTypes []TokenTypeSpec, observer service.AuthzCheckObserver, opts ...AuthzOption) *AuthzServer {
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

	defaultTypes := make([]service.TokenType, len(tokenTypes))
	for i, spec := range tokenTypes {
		defaultTypes[i] = spec.Type
	}

	s := &AuthzServer{
		trustStore:             trustStore,
		tokenService:           tokenService,
		TokenTypesToIssue:      tokenTypes,
		observer:               observer,
		anonymousSubjectPolicy: DenyAllPolicy{},
		issuancePolicy:         NewAlwaysIssuePolicy(defaultTypes),
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

	actor, actorDenyResp := s.extractAndValidateActor(ctx, p)
	if actorDenyResp != nil {
		return actorDenyResp, nil
	}

	cred, headersUsed, err := s.extractCredential(req)
	if err != nil {
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	if cred == nil {
		return s.handleAnonymousSubject(ctx, actor, reqAttrs, p)
	}

	return s.checkWithCredential(ctx, reqAttrs, cred, headersUsed, actor, p)
}

// extractAndValidateActor extracts and validates the actor credential from the
// gRPC context (mTLS peer cert or metadata bearer token). Returns the validated
// actor result, or a deny response if validation fails.
func (s *AuthzServer) extractAndValidateActor(ctx context.Context, p service.AuthzCheckProbe) (*trust.Result, *authv3.CheckResponse) {
	actorCred, err := extractActorCredential(ctx)
	if err != nil {
		return nil, s.denyResponse(codes.Internal,
			fmt.Sprintf("failed to extract actor credential: %v", err))
	}

	var actor *trust.Result
	if actorCred != nil {
		var validationErr error
		actor, validationErr = s.trustStore.Validate(ctx, actorCred)
		if validationErr != nil {
			p.ActorValidationFailed(validationErr)
			return nil, s.denyResponse(codes.Unauthenticated,
				fmt.Sprintf("actor validation failed: %v", validationErr))
		}
		p.ActorValidationSucceeded(actor)
	} else {
		actor = trust.AnonymousResult()
		p.ActorValidationSucceeded(actor)
	}

	return actor, nil
}

// handleAnonymousSubject evaluates the anonymous subject policy when no
// credentials are present. Fires the appropriate observer hooks.
func (s *AuthzServer) handleAnonymousSubject(
	ctx context.Context,
	actor *trust.Result,
	reqAttrs *request.RequestAttributes,
	p service.AuthzCheckProbe,
) (*authv3.CheckResponse, error) {
	p.AnonymousSubjectDetected()

	allowed, err := s.anonymousSubjectPolicy.IsAllowed(ctx, actor, reqAttrs)
	if err != nil {
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("anonymous subject policy evaluation failed: %v", err)), nil
	}

	if allowed {
		p.AnonymousSubjectPolicyAllowed(reqAttrs)
		return s.allowResponse(), nil
	}

	p.AnonymousSubjectPolicyDenied(reqAttrs)
	return s.denyResponse(codes.Unauthenticated, "no credentials provided"), nil
}

func (s *AuthzServer) checkWithCredential(
	ctx context.Context,
	reqAttrs *request.RequestAttributes,
	cred trust.Credential,
	headersUsed []string,
	actor *trust.Result,
	p service.AuthzCheckProbe,
) (*authv3.CheckResponse, error) {
	p.SubjectCredentialExtracted(cred, headersUsed)

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

	decision, err := s.issuancePolicy.Evaluate(ctx, result, actor, reqAttrs)
	if err != nil {
		p.IssuancePolicyDenied(err)
		return s.denyResponse(codes.PermissionDenied,
			fmt.Sprintf("issuance policy denied: %v", err)), nil
	}
	if decision == nil {
		p.IssuancePolicyPassthrough()
		return s.allowResponseWithRemovedHeaders(headersUsed), nil
	}
	p.IssuancePolicyIssue(decision.TokenTypes, decision.Scope)

	issuedTokens, err := s.tokenService.IssueTokens(ctx, &service.IssueRequest{
		Subject:           result,
		Actor:             actor,
		RequestAttributes: reqAttrs,
		TokenTypes:        decision.TokenTypes,
		Scope:             decision.Scope,
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

// extractCredential extracts credentials from the Envoy request.
// Returns (nil, nil, nil) when no Authorization header is present -- absence
// of credentials is not an error, it triggers the anonymous subject path.
func (s *AuthzServer) extractCredential(req *authv3.CheckRequest) (trust.Credential, []string, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	// TODO: mtls e.g. cert := req.GetAttributes().GetSource().GetCertificate()

	if httpReq == nil {
		return nil, nil, fmt.Errorf("no HTTP request attributes")
	}

	authHeader := httpReq.GetHeaders()["authorization"]
	if authHeader == "" {
		return nil, nil, nil
	}

	if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
		cred := &trust.BearerCredential{
			Token: token,
		}
		headersUsed := []string{"authorization"}
		return cred, headersUsed, nil
	}

	// Future: Handle other authentication schemes
	// - Basic auth: would use "authorization" header
	// - API key in custom header: would track that header name
	// - Cookie-based auth: would track cookie names

	return nil, nil, ErrUnsupportedCredentialScheme
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

func (s *AuthzServer) allowResponseWithRemovedHeaders(headersToRemove []string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				HeadersToRemove: headersToRemove,
			},
		},
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
