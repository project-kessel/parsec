package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
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
	policy            AuthzCheckPolicy
}

// NewAuthzServer creates a new ext_authz server.
// policy decides, for each request, whether to issue tokens, allow without
// issue, or deny. If nil, a [StaticAuthenticatedPolicy] with default token types
// is used (preserving pre-policy behavior).
// credentialSources defines where credentials are extracted from for both
// subject and actor authentication.
func NewAuthzServer(trustStore trust.Store, tokenService *service.TokenService, policy AuthzCheckPolicy, credentialSources CredentialSources, observer service.AuthzCheckObserver) *AuthzServer {
	if policy == nil {
		policy = NewStaticAuthenticatedPolicy(nil)
	}

	if observer == nil {
		observer = service.NoOpAuthzCheckObserver{}
	}

	return &AuthzServer{
		trustStore:        trustStore,
		tokenService:      tokenService,
		policy:            policy,
		observer:          observer,
		credentialSources: credentialSources,
	}
}

// Check implements the ext_authz check endpoint
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (response *authv3.CheckResponse, returnErr error) {
	var headers map[string]string
	if req != nil {
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	}
	ctx = contextWithRequestID(ctx, headers, nil)

	// Create request-scoped probe
	ctx, p := s.observer.AuthzCheckStarted(ctx)
	reasonCode := "internal_error"
	var auditTokenTypes []service.TokenType
	defer func() {
		propagateAuthzRequestID(response, request.ID(ctx))
		p.RequestCompleted(authzRequestCompletion(response, reasonCode, auditTokenTypes))
		p.End()
	}()

	// 1. Build request attributes
	reqAttrs := s.buildRequestAttributes(req)
	p.RequestAttributesParsed(reqAttrs)

	// 2. Authenticate actor from gRPC context
	actorResult, actorExt, err := authenticateActorWithExtraction(ctx, s.credentialSources, s.trustStore, p)
	if err != nil {
		reasonCode = "credential_invalid"
		return s.denyResponse(codes.Unauthenticated,
			fmt.Sprintf("%v", err)), nil
	}

	var actorPrin Principal
	if actorExt != nil {
		actorPrin = newPrincipal(actorResult, actorExt)
	} else {
		actorPrin = anonymousPrincipal()
	}

	// 3. Extract subject credential and build subject Principal.
	// Only "no credential found" enters the anonymous path; malformed or
	// invalid credentials are hard failures.
	var subjectPrin Principal
	var subjectExt *CredentialExtraction

	cc, err := CredentialContextFromCheckRequest(req)
	if err != nil {
		reasonCode = "credential_malformed"
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	subjectExt, err = s.credentialSources.Extract(ctx, cc)
	if err != nil {
		reasonCode = "credential_malformed"
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	if subjectExt == nil {
		subjectPrin = anonymousPrincipal()
		p.SubjectAnonymous()
	} else {
		// If we got a credential, filter trust store and validate it
		p.SubjectCredentialExtracted(subjectExt.Credential, subjectExt.HeadersUsed)

		filteredStore, filterErr := s.trustStore.ForActor(ctx, actorResult, reqAttrs)
		if filterErr != nil {
			reasonCode = auditReasonFromError(filterErr, "scheme_not_allowed")
			return s.denyResponse(codes.PermissionDenied,
				fmt.Sprintf("failed to filter trust store: %v", filterErr)), nil
		}

		result, validationErr := filteredStore.Validate(ctx, subjectExt.Credential)
		if validationErr != nil {
			reasonCode = "credential_invalid"
			if errors.Is(validationErr, trust.ErrExpiredToken) {
				reasonCode = "credential_expired"
			}
			p.SubjectValidationFailed(validationErr)
			return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("validation failed: %v", validationErr)), nil
		}
		p.SubjectValidationSucceeded(result)
		subjectPrin = newPrincipal(result, subjectExt)
	}

	// 4. Evaluate authz check policy
	decision, err := s.policy.Decide(ctx, AuthzCheckPolicyInput{
		Subject: subjectPrin,
		Actor:   actorPrin,
		Request: reqAttrs,
	})
	if err != nil {
		reasonCode = auditReasonFromError(err, "internal_error")
		p.PolicyEvaluationFailed(err)
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("policy evaluation failed: %v", err)), nil
	}

	// 5. Handle policy decision
	switch decision.Action {
	case AuthzCheckDeny:
		reasonCode = auditReasonFromText(decision.Reason, "policy_denied")
		p.PolicyDecisionDeny(decision.Reason)
		denyCode := codes.PermissionDenied
		if subjectPrin.Anonymous {
			denyCode = codes.Unauthenticated
			reasonCode = "credential_missing"
		}
		return s.denyResponse(denyCode, decision.Reason), nil

	case AuthzCheckAllowWithoutIssue:
		reasonCode = ""
		p.PolicyDecisionAllowWithoutIssue(decision.Reason)
		rewrite, remove := removeCredentialPresentation(subjectExt, cc.Cookies)
		return s.okResponse(rewrite, remove), nil

	case AuthzCheckIssue:
		p.PolicyDecisionIssue(len(decision.TokenTypes), decision.Scope, decision.Reason)
		rewrite, remove := removeCredentialPresentation(subjectExt, cc.Cookies)
		response, auditTokenTypes, reasonCode, returnErr = s.issueResponse(ctx, decision, subjectPrin, actorPrin, reqAttrs, rewrite, remove)
		return response, returnErr

	default:
		reasonCode = "internal_error"
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("unknown policy action: %s", decision.Action)), nil
	}
}

// issueResponse calls TokenService.IssueTokens and builds an OK response
// with the issued tokens appended to any credential sanitization headers.
func (s *AuthzServer) issueResponse(
	ctx context.Context,
	decision AuthzCheckDecision,
	subject, actor Principal,
	reqAttrs *request.RequestAttributes,
	credHeaders []*corev3.HeaderValueOption,
	headersToRemove []string,
) (*authv3.CheckResponse, []service.TokenType, string, error) {
	tokenTypes := make([]service.TokenType, len(decision.TokenTypes))
	for i, spec := range decision.TokenTypes {
		tokenTypes[i] = spec.Type
	}

	results, err := s.tokenService.IssueTokens(ctx, &service.IssueRequest{
		Subject:           subject.Result,
		Actor:             actor.Result,
		RequestAttributes: reqAttrs,
		TokenTypes:        tokenTypes,
		Scope:             decision.Scope,
	})
	if err != nil {
		response := s.denyResponseWithHTTPStatus(codes.Internal,
			typev3.StatusCode_InternalServerError,
			fmt.Sprintf("failed to issue tokens: %v", err))
		return response, nil, "token_issuance_failed", nil
	}

	// Any token-type denial denies the entire ext_authz request.
	// Iterate in request order for deterministic error selection.
	for _, spec := range decision.TokenTypes {
		if r, ok := results[spec.Type]; ok && r.ExchangeErr != nil {
			grpcCode, httpStatus, msg := exchangeErrToAuthzDenial(r.ExchangeErr)
			response := s.denyResponseWithHTTPStatus(grpcCode, httpStatus, msg)
			return response, nil, "token_issuance_denied", nil
		}
	}

	headers := make([]*corev3.HeaderValueOption, 0, len(credHeaders)+len(results))
	headers = append(headers, credHeaders...)
	for _, spec := range decision.TokenTypes {
		r, ok := results[spec.Type]
		if !ok || r.Token == nil {
			// Fail closed: never return OK without every requested token.
			// A missing/nil token with no ExchangeErr is a programmer error.
			response := s.denyResponseWithHTTPStatus(codes.Internal,
				typev3.StatusCode_InternalServerError,
				fmt.Sprintf("token service returned no token for type %s", spec.Type))
			return response, nil, "token_issuance_failed", nil
		}
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   spec.HeaderName,
				Value: r.Token.Value,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	return s.okResponse(headers, headersToRemove), tokenTypes, "", nil
}

// removeCredentialPresentation builds the Envoy header mutations needed to
// strip credential material from the upstream request. Headers listed in
// ext.HeadersUsed are returned for removal. Cookies listed in ext.CookiesUsed
// are removed from cookies: if all cookies are consumed the cookie header is
// added to the removal list; otherwise a rewritten Cookie header option is
// returned.
//
// Returns (nil, nil) when ext is nil.
func removeCredentialPresentation(ext *CredentialExtraction, cookies []*http.Cookie) ([]*corev3.HeaderValueOption, []string) {
	if ext == nil {
		return nil, nil
	}

	var headers []*corev3.HeaderValueOption
	headersToRemove := append([]string(nil), ext.HeadersUsed...)

	if len(ext.CookiesUsed) > 0 && len(cookies) > 0 {
		sanitized := sanitizeCookieHeader(cookies, ext.CookiesUsed...)
		if sanitized == "" {
			headersToRemove = append(headersToRemove, "cookie")
		} else {
			headers = append(headers, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   "cookie",
					Value: sanitized,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}

	return headers, headersToRemove
}

// sanitizeCookieHeader rebuilds a Cookie header value without the named
// cookies. Returns an empty string when all cookies are omitted.
func sanitizeCookieHeader(cookies []*http.Cookie, omitNames ...string) string {
	omit := make(map[string]struct{}, len(omitNames))
	for _, name := range omitNames {
		omit[name] = struct{}{}
	}

	var remaining []string
	for _, c := range cookies {
		if _, skip := omit[c.Name]; !skip {
			remaining = append(remaining, c.String())
		}
	}
	return strings.Join(remaining, "; ")
}

// okResponse wraps pre-built header options and a removal list into an
// OK [authv3.CheckResponse].
func (s *AuthzServer) okResponse(headers []*corev3.HeaderValueOption, headersToRemove []string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers:         headers,
				HeadersToRemove: headersToRemove,
			},
		},
	}
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

// httpStatusForCode maps a gRPC denial code to the Envoy HTTP status returned
// to the downstream client. Envoy defaults DeniedHttpResponse to 403 when
// Status is unset — always set an explicit status instead.
func httpStatusForCode(code codes.Code) typev3.StatusCode {
	switch code {
	case codes.Unauthenticated:
		return typev3.StatusCode_Unauthorized
	case codes.PermissionDenied:
		return typev3.StatusCode_Forbidden
	case codes.InvalidArgument:
		return typev3.StatusCode_BadRequest
	case codes.Internal:
		return typev3.StatusCode_InternalServerError
	default:
		return typev3.StatusCode_Forbidden
	}
}

// denyResponse creates a denial with an explicit HTTP status derived from the
// gRPC code so Envoy does not fall back to its default 403.
func (s *AuthzServer) denyResponse(code codes.Code, message string) *authv3.CheckResponse {
	return s.denyResponseWithHTTPStatus(code, httpStatusForCode(code), message)
}

// denyResponseWithHTTPStatus creates a denial response with an explicit HTTP
// status on the DeniedHttpResponse so Envoy returns the intended code to the
// downstream client.
func (s *AuthzServer) denyResponseWithHTTPStatus(code codes.Code, httpStatus typev3.StatusCode, message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code:    int32(code),
			Message: message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpStatus},
				Body:   message,
			},
		},
	}
}
