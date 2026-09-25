package server

import (
	"context"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
)

// RequestIDConfig is an alias for request.RequestIDConfig so server callers
// can keep using the server package without importing request for the type.
type RequestIDConfig = request.RequestIDConfig

// DefaultRequestIDConfig returns the industry-standard x-request-id config.
func DefaultRequestIDConfig() RequestIDConfig {
	return request.DefaultRequestIDConfig()
}

// contextWithRequestID extracts a request ID from headers or gRPC metadata,
// falling back to a generated UUID. The bool return is true when the ID was
// extracted from an incoming header; false when it was generated locally.
// An incoming value that fails ValidRequestID is treated as generated.
func contextWithRequestID(ctx context.Context, headers map[string]string, generate func() string, reqIDHeaders []string) (context.Context, bool) {
	if len(reqIDHeaders) == 0 {
		reqIDHeaders = request.DefaultRequestIDHeaders()
	}
	for _, name := range reqIDHeaders {
		if id := request.ValidRequestID(request.HeaderValue(headers, name)); id != "" {
			return request.WithID(ctx, id), true
		}
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, name := range reqIDHeaders {
			if values := md.Get(name); len(values) > 0 {
				if id := request.ValidRequestID(values[0]); id != "" {
					return request.WithID(ctx, id), true
				}
			}
		}
	}
	if generate == nil {
		generate = uuid.NewString
	}
	return request.WithID(ctx, request.ValidRequestID(generate())), false
}

func newIncomingHeaderMatcher(reqIDHeaders []string) func(string) (string, bool) {
	if len(reqIDHeaders) == 0 {
		reqIDHeaders = request.DefaultRequestIDHeaders()
	}
	lower := make(map[string]bool, len(reqIDHeaders))
	for _, h := range reqIDHeaders {
		lower[strings.ToLower(h)] = true
	}
	return func(key string) (string, bool) {
		if lower[strings.ToLower(key)] {
			return strings.ToLower(key), true
		}
		return runtime.DefaultHeaderMatcher(key)
	}
}

func newOutgoingHeaderMatcher(reqIDHeaders []string) func(string) (string, bool) {
	if len(reqIDHeaders) == 0 {
		reqIDHeaders = request.DefaultRequestIDHeaders()
	}
	canonical := reqIDHeaders[0]
	return func(key string) (string, bool) {
		if strings.EqualFold(key, canonical) {
			return canonical, true
		}
		return runtime.DefaultHeaderMatcher(key)
	}
}

func propagateAuthzRequestID(response *authv3.CheckResponse, id string, canonicalHeader string) {
	id = request.ValidRequestID(id)
	if response == nil || id == "" {
		return
	}
	if canonicalHeader == "" {
		canonicalHeader = request.DefaultRequestIDHeaders()[0]
	}
	header := &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: canonicalHeader, Value: id},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
	if ok := response.GetOkResponse(); ok != nil {
		ok.Headers = append(ok.Headers, header)
		return
	}
	if denied := response.GetDeniedResponse(); denied != nil {
		denied.Headers = append(denied.Headers, header)
	}
}

func authzRequestCompletion(response *authv3.CheckResponse, reasonCode string, tokenTypes []service.TokenType) service.RequestCompletion {
	completion := service.RequestCompletion{
		Outcome:    service.AuditOutcomeFailure,
		ReasonCode: reasonCode,
		GRPCCode:   int32(codes.Internal),
		HTTPStatus: 500,
		TokenTypes: tokenTypes,
	}
	if response == nil || response.GetStatus() == nil {
		return completion
	}

	code := codes.Code(response.GetStatus().GetCode())
	if reasonCode == "" && code != codes.OK {
		reasonCode = auditReasonFromText(response.GetStatus().GetMessage(), "internal_error")
		completion.ReasonCode = reasonCode
	}
	completion.GRPCCode = int32(code)
	if denied := response.GetDeniedResponse(); denied != nil && denied.GetStatus() != nil {
		completion.HTTPStatus = int(denied.GetStatus().GetCode())
	}
	switch code {
	case codes.OK:
		completion.Outcome = service.AuditOutcomeSuccess
		completion.ReasonCode = ""
		completion.HTTPStatus = 200
	case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument:
		completion.Outcome = service.AuditOutcomeDenied
	default:
		completion.Outcome = service.AuditOutcomeFailure
	}
	if completion.Outcome != service.AuditOutcomeSuccess {
		completion.TokenTypes = nil
	}
	return completion
}

// auditReasonFromError classifies only known failure families. Error text is
// never returned or recorded.
func auditReasonFromError(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	return auditReasonFromText(err.Error(), fallback)
}

func auditReasonFromText(value, fallback string) string {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "jwks"), strings.Contains(value, "dependency"):
		return "dependency_failure"
	default:
		return fallback
	}
}

func exchangeRequestCompletion(err error, reasonCode string, tokenType service.TokenType) service.RequestCompletion {
	completion := service.RequestCompletion{
		Outcome:    service.AuditOutcomeSuccess,
		ReasonCode: reasonCode,
		HTTPStatus: 200,
	}
	if err == nil && tokenType != "" {
		completion.TokenTypes = []service.TokenType{tokenType}
	}
	if err == nil {
		return completion
	}

	code := status.Code(err)
	completion.GRPCCode = int32(code)
	if code == codes.Unknown {
		completion.HTTPStatus = 500
	} else {
		completion.HTTPStatus = int(httpStatusForCode(code))
	}
	switch reasonCode {
	case "invalid_request", "grant_type_unsupported", "credential_missing", "credential_malformed", "credential_invalid", "credential_expired", "scheme_not_allowed", "policy_denied", "compliance_denied", "token_issuance_denied":
		completion.Outcome = service.AuditOutcomeDenied
		return completion
	}
	switch code {
	case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument, codes.FailedPrecondition:
		completion.Outcome = service.AuditOutcomeDenied
	default:
		completion.Outcome = service.AuditOutcomeFailure
	}
	return completion
}
