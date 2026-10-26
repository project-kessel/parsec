package server

import (
	"context"
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
	dropHeaders       []string // unconditionally removed from upstream requests
	dropCookies       []string // unconditionally removed from the Cookie header
}

// NewAuthzServer creates a new ext_authz server.
// policy decides, for each request, whether to issue tokens, allow without
// issue, or deny. If nil, a [StaticAuthenticatedPolicy] with default token types
// is used (preserving pre-policy behavior).
// credentialSources defines where credentials are extracted from for both
// subject and actor authentication.
// dropHeaders lists header names that are unconditionally removed from
// upstream requests, regardless of which credential source matched. On the
// Issue path, any entry matching an issued token's header name is excluded
// from removal (see excludeIssuedHeaders) so the issued token is not deleted
// by Envoy's header mutation order.
// dropCookies lists cookie names that are unconditionally removed from the
// Cookie header, regardless of which credential source matched. Unlike
// dropHeaders, cookie names are case-sensitive (RFC 6265) and are not
// lowercased.
func NewAuthzServer(trustStore trust.Store, tokenService *service.TokenService, policy AuthzCheckPolicy, credentialSources CredentialSources, dropHeaders []string, dropCookies []string, observer service.AuthzCheckObserver) *AuthzServer {
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
		dropHeaders:       normalizeDropHeaders(dropHeaders),
		dropCookies:       normalizeDropCookies(dropCookies),
	}
}

// normalizeDropHeaders lowercases and trims header names, dropping blank
// entries. Returns nil when there is nothing to normalize, avoiding a
// zero-length allocation for the common case of no configured drop_headers.
func normalizeDropHeaders(headers []string) []string {
	if len(headers) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(headers))
	for _, h := range headers {
		if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}

// normalizeDropCookies trims cookie names, dropping blank entries. Cookie
// names are case-sensitive per RFC 6265, so unlike normalizeDropHeaders this
// does not lowercase them.
func normalizeDropCookies(cookies []string) []string {
	if len(cookies) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
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
	actorResult, actorExt, err := authenticateActorWithExtraction(ctx, s.credentialSources, s.trustStore, p)
	if err != nil {
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
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	subjectExt, err = s.credentialSources.Extract(ctx, cc)
	if err != nil {
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
			p.PolicyEvaluationFailed(filterErr)
			return s.denyResponse(codes.PermissionDenied,
				fmt.Sprintf("failed to filter trust store: %v", filterErr)), nil
		}

		result, validationErr := filteredStore.Validate(ctx, subjectExt.Credential)
		if validationErr != nil {
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
		p.PolicyEvaluationFailed(err)
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("policy evaluation failed: %v", err)), nil
	}

	// 5. Handle policy decision
	switch decision.Action {
	case AuthzCheckDeny:
		p.PolicyDecisionDeny(decision.Reason)
		denyCode := codes.PermissionDenied
		if subjectPrin.Anonymous {
			denyCode = codes.Unauthenticated
		}
		return s.denyResponse(denyCode, decision.Reason), nil

	case AuthzCheckAllowWithoutIssue:
		p.PolicyDecisionAllowWithoutIssue(decision.Reason)
		rewrite, remove := s.mergeDropHeaders(subjectExt, cc.Cookies)
		return s.okResponse(rewrite, remove), nil

	case AuthzCheckIssue:
		p.PolicyDecisionIssue(len(decision.TokenTypes), decision.Scope, decision.Reason)
		rewrite, remove := s.mergeDropHeaders(subjectExt, cc.Cookies)
		// Exclude headers that will carry issued tokens. Envoy applies
		// Headers (set) before HeadersToRemove, so including an issued
		// token's header name here would delete the token immediately
		// after it is set.
		remove = excludeIssuedHeaders(remove, decision.TokenTypes)
		return s.issueResponse(ctx, p, decision, subjectPrin, actorPrin, reqAttrs, rewrite, remove)

	default:
		p.PolicyEvaluationFailed(fmt.Errorf("unknown policy action: %s", decision.Action))
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("unknown policy action: %s", decision.Action)), nil
	}
}

// issueResponse calls TokenService.IssueTokens and builds an OK response
// with the issued tokens appended to any credential sanitization headers.
func (s *AuthzServer) issueResponse(
	ctx context.Context,
	p service.AuthzCheckProbe,
	decision AuthzCheckDecision,
	subject, actor Principal,
	reqAttrs *request.RequestAttributes,
	credHeaders []*corev3.HeaderValueOption,
	headersToRemove []string,
) (*authv3.CheckResponse, error) {
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
		p.TokenIssuanceFailed(err)
		return s.denyResponseWithHTTPStatus(codes.Internal,
			typev3.StatusCode_InternalServerError,
			fmt.Sprintf("failed to issue tokens: %v", err)), nil
	}

	// Any token-type denial denies the entire ext_authz request.
	// Iterate in request order for deterministic error selection.
	for _, spec := range decision.TokenTypes {
		if r, ok := results[spec.Type]; ok && r.ExchangeErr != nil {
			p.TokenIssuanceDenied(r.ExchangeErr)
			grpcCode, httpStatus, msg := exchangeErrToAuthzDenial(r.ExchangeErr)
			return s.denyResponseWithHTTPStatus(grpcCode, httpStatus, msg), nil
		}
	}

	headers := make([]*corev3.HeaderValueOption, 0, len(credHeaders)+len(results))
	headers = append(headers, credHeaders...)
	for _, spec := range decision.TokenTypes {
		r, ok := results[spec.Type]
		if !ok || r.Token == nil {
			p.TokenIssuanceFailed(fmt.Errorf("token service returned no token for type %s", spec.Type))
			return s.denyResponseWithHTTPStatus(codes.Internal,
				typev3.StatusCode_InternalServerError,
				fmt.Sprintf("token service returned no token for type %s", spec.Type)), nil
		}
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   spec.HeaderName,
				Value: r.Token.Value,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	return s.okResponse(headers, headersToRemove), nil
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

// excludeIssuedHeaders removes, from the removal list, any header name that
// matches a token type about to be issued. Envoy applies Headers (set)
// before HeadersToRemove, so a header present in both lists would be set
// and then immediately deleted, silently dropping the issued token.
func excludeIssuedHeaders(remove []string, tokenTypes []TokenTypeSpec) []string {
	if len(remove) == 0 || len(tokenTypes) == 0 {
		return remove
	}

	issued := make(map[string]struct{}, len(tokenTypes))
	for _, spec := range tokenTypes {
		issued[strings.ToLower(spec.HeaderName)] = struct{}{}
	}

	filtered := make([]string, 0, len(remove))
	for _, h := range remove {
		if _, ok := issued[h]; !ok {
			filtered = append(filtered, h)
		}
	}
	return filtered
}

// mergeDropHeaders combines credential-source-driven header/cookie removal
// with the unconditional drop_headers and drop_cookies deny-lists. Entries
// that already appear in the credential-driven removal are deduplicated.
//
// When the operator includes "cookie" in drop_headers the entire Cookie
// header is removed: any Cookie rewrite from credential sanitization is
// discarded and the partial drop_cookies path is skipped.
func (s *AuthzServer) mergeDropHeaders(ext *CredentialExtraction, cookies []*http.Cookie) ([]*corev3.HeaderValueOption, []string) {
	rewrite, remove := removeCredentialPresentation(ext, cookies)

	cookieDenied := false
	if len(s.dropHeaders) > 0 {
		seen := make(map[string]struct{}, len(remove))
		for _, h := range remove {
			seen[h] = struct{}{}
		}
		for _, h := range s.dropHeaders {
			if h == "cookie" {
				cookieDenied = true
			}
			if _, exists := seen[h]; !exists {
				remove = append(remove, h)
			}
		}
	}

	// When the whole Cookie header is denied via dropHeaders, strip any
	// Cookie rewrite produced by credential sanitization and skip
	// partial-cookie filtering — the header is removed entirely.
	if cookieDenied {
		rewrite = removeHeaderOption(rewrite, "cookie")
		return rewrite, remove
	}

	if len(s.dropCookies) > 0 && len(cookies) > 0 {
		rewrite, remove = applyDropCookies(ext, cookies, s.dropCookies, rewrite, remove)
	}

	return rewrite, remove
}

// applyDropCookies rewrites (or schedules removal of) the Cookie header to
// additionally strip dropCookies entries, on top of any cookie already
// sanitized by the matched credential source (ext.CookiesUsed). This closes
// the gap where a credential presented via an unmatched channel (e.g. a
// cs_jwt cookie alongside a matched Authorization bearer header) would
// otherwise pass through untouched: drop_headers only removes HTTP headers
// by name and cannot reach into the Cookie header's individual values.
func applyDropCookies(ext *CredentialExtraction, cookies []*http.Cookie, dropCookies []string, rewrite []*corev3.HeaderValueOption, remove []string) ([]*corev3.HeaderValueOption, []string) {
	omit := append([]string(nil), dropCookies...)
	if ext != nil {
		omit = append(omit, ext.CookiesUsed...)
	}

	sanitized := sanitizeCookieHeader(cookies, omit...)

	// Discard any cookie rewrite already produced by removeCredentialPresentation;
	// it will be superseded by the combined sanitization below.
	rewrite = removeHeaderOption(rewrite, "cookie")
	remove = removeString(remove, "cookie")

	if sanitized == "" {
		remove = append(remove, "cookie")
		return rewrite, remove
	}

	rewrite = append(rewrite, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "cookie",
			Value: sanitized,
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	})
	return rewrite, remove
}

// removeHeaderOption returns headers with any entry matching key (case-insensitive)
// removed.
func removeHeaderOption(headers []*corev3.HeaderValueOption, key string) []*corev3.HeaderValueOption {
	if len(headers) == 0 {
		return headers
	}
	filtered := make([]*corev3.HeaderValueOption, 0, len(headers))
	for _, h := range headers {
		if !strings.EqualFold(h.GetHeader().GetKey(), key) {
			filtered = append(filtered, h)
		}
	}
	return filtered
}

// removeString returns values with any entry equal to target removed.
func removeString(values []string, target string) []string {
	if len(values) == 0 {
		return values
	}
	filtered := make([]string, 0, len(values))
	for _, v := range values {
		if v != target {
			filtered = append(filtered, v)
		}
	}
	return filtered
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
