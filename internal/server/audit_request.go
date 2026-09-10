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

const (
	requestIDHeader         = "x-rh-insights-request-id"
	fallbackRequestIDHeader = "x-request-id"
)

func contextWithRequestID(ctx context.Context, headers map[string]string, generate func() string) context.Context {
	for _, name := range []string{requestIDHeader, fallbackRequestIDHeader} {
		if id := validRequestID(headerValue(headers, name)); id != "" {
			return request.WithID(ctx, id)
		}
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, name := range []string{requestIDHeader, fallbackRequestIDHeader} {
			if values := md.Get(name); len(values) > 0 {
				if id := validRequestID(values[0]); id != "" {
					return request.WithID(ctx, id)
				}
			}
		}
	}
	if generate == nil {
		generate = uuid.NewString
	}
	return request.WithID(ctx, validRequestID(generate()))
}

func headerValue(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	if value := headers[name]; value != "" {
		return value
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func auditIncomingHeaderMatcher(key string) (string, bool) {
	switch strings.ToLower(key) {
	case requestIDHeader, fallbackRequestIDHeader:
		return strings.ToLower(key), true
	default:
		return runtime.DefaultHeaderMatcher(key)
	}
}

func auditOutgoingHeaderMatcher(key string) (string, bool) {
	if strings.EqualFold(key, requestIDHeader) {
		return requestIDHeader, true
	}
	return runtime.DefaultHeaderMatcher(key)
}

func validRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return ""
	}
	return value
}

func propagateAuthzRequestID(response *authv3.CheckResponse, id string) {
	id = validRequestID(id)
	if response == nil || id == "" {
		return
	}
	header := &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: requestIDHeader, Value: id},
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
	case strings.Contains(value, "compliance"):
		if strings.Contains(value, "denied") || strings.Contains(value, "deny") {
			return "compliance_denied"
		}
		return "compliance_failure"
	case strings.Contains(value, "supplemental user"), strings.Contains(value, "bop"):
		return "supplemental_user_data_failure"
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
