package server

import (
	"context"
	"errors"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
)

func TestContextWithRequestIDPrefersFirstConfiguredHeader(t *testing.T) {
	headers := []string{"x-custom-request-id", "x-request-id"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-custom-request-id", "custom-id",
		"x-request-id", "fallback-id",
	))
	ctx, extracted := contextWithRequestID(ctx, nil, func() string { return "generated" }, headers)
	require.True(t, extracted)
	require.Equal(t, "custom-id", request.ID(ctx))
}

func TestContextWithRequestIDUsesDefaultWhenEmpty(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-request-id", "default-id",
	))
	ctx, extracted := contextWithRequestID(ctx, nil, func() string { return "generated" }, nil)
	require.True(t, extracted)
	require.Equal(t, "default-id", request.ID(ctx))
}

func TestDefaultRequestIDConfigUsesXRequestID(t *testing.T) {
	config := DefaultRequestIDConfig()
	require.Equal(t, []string{"x-request-id"}, config.Headers)
	require.Equal(t, "x-request-id", config.CanonicalHeader())

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-request-id", "request-id-123",
	))
	ctx, extracted := contextWithRequestID(ctx, nil, func() string { return "generated" }, config.Headers)
	require.True(t, extracted)
	require.Equal(t, "request-id-123", request.ID(ctx))
}

func TestAuthzRequestCompletionClassifiesTerminalOutcome(t *testing.T) {
	tests := []struct {
		name       string
		response   *authv3.CheckResponse
		reason     string
		want       service.AuditOutcome
		wantStatus int
	}{
		{name: "success", response: &authv3.CheckResponse{Status: &statuspb.Status{Code: int32(codes.OK)}}, want: service.AuditOutcomeSuccess, wantStatus: 200},
		{name: "denied", response: deniedCheckResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden), reason: "policy_denied", want: service.AuditOutcomeDenied, wantStatus: 403},
		{name: "failure", response: deniedCheckResponse(codes.Internal, typev3.StatusCode_InternalServerError), reason: "internal_error", want: service.AuditOutcomeFailure, wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authzRequestCompletion(tt.response, tt.reason, []service.TokenType{"token"})
			require.Equal(t, tt.want, got.Outcome)
			require.Equal(t, tt.wantStatus, got.HTTPStatus)
		})
	}
}

func TestExchangeRequestCompletionClassifiesTerminalOutcome(t *testing.T) {
	require.Equal(t, service.AuditOutcomeSuccess, exchangeRequestCompletion(nil, "", "token").Outcome)
	require.Equal(t, service.AuditOutcomeDenied, exchangeRequestCompletion(status.Error(codes.Unauthenticated, "secret"), "credential_invalid", "token").Outcome)
	require.Equal(t, service.AuditOutcomeDenied, exchangeRequestCompletion(errors.New("secret"), "credential_malformed", "token").Outcome)
	require.Equal(t, service.AuditOutcomeFailure, exchangeRequestCompletion(errors.New("secret"), "internal_error", "token").Outcome)
}

func deniedCheckResponse(code codes.Code, httpCode typev3.StatusCode) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(code)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: httpCode},
			Headers: []*corev3.HeaderValueOption{},
		}},
	}
}

func TestContextWithRequestIDReadsExtAuthzHeaders(t *testing.T) {
	headers := []string{"x-custom-request-id", "x-request-id"}
	ctx, extracted := contextWithRequestID(context.Background(), map[string]string{
		"x-custom-request-id": "ext-authz-id",
	}, func() string { return "generated" }, headers)
	require.True(t, extracted)
	require.Equal(t, "ext-authz-id", request.ID(ctx))
}

func TestContextWithRequestIDGeneratesForUnsafeInput(t *testing.T) {
	headers := []string{"x-request-id"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-request-id", "bad\nvalue",
	))
	ctx, extracted := contextWithRequestID(ctx, nil, func() string { return "generated-id" }, headers)
	require.False(t, extracted, "rejected incoming ID must be treated as generated")
	require.Equal(t, "generated-id", request.ID(ctx))
}

func TestContextWithRequestIDGeneratedWhenMissing(t *testing.T) {
	ctx, extracted := contextWithRequestID(context.Background(), nil, func() string { return "generated-id" }, []string{"x-request-id"})
	require.False(t, extracted)
	require.Equal(t, "generated-id", request.ID(ctx))
}

func TestPropagateAuthzRequestID(t *testing.T) {
	canonical := "x-request-id"
	response := (&AuthzServer{}).okResponse(nil, nil)
	propagateAuthzRequestID(response, "request-123", canonical)
	require.Equal(t, canonical, response.GetOkResponse().GetHeaders()[0].GetHeader().GetKey())
	require.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, response.GetOkResponse().GetHeaders()[0].GetAppendAction())
	require.Equal(t, "request-123", response.GetOkResponse().GetHeaders()[0].GetHeader().GetValue())
}

func TestGeneratedRequestIDIsNotPropagated(t *testing.T) {
	// Mirrors authz.go: only propagate when extracted == true.
	response := (&AuthzServer{}).okResponse(nil, nil)
	_, extracted := contextWithRequestID(context.Background(), nil, func() string { return "generated-id" }, []string{"x-request-id"})
	require.False(t, extracted)
	if extracted {
		propagateAuthzRequestID(response, "generated-id", "x-request-id")
	}
	require.Empty(t, response.GetOkResponse().GetHeaders(), "generated fallback IDs must not be propagated")
}

func TestExtractedRequestIDIsPropagated(t *testing.T) {
	response := (&AuthzServer{}).okResponse(nil, nil)
	ctx, extracted := contextWithRequestID(context.Background(), map[string]string{
		"x-request-id": "upstream-id",
	}, func() string { return "generated-id" }, []string{"x-request-id"})
	require.True(t, extracted)
	if extracted {
		propagateAuthzRequestID(response, request.ID(ctx), "x-request-id")
	}
	require.Len(t, response.GetOkResponse().GetHeaders(), 1)
	require.Equal(t, "upstream-id", response.GetOkResponse().GetHeaders()[0].GetHeader().GetValue())
}

func TestHeaderMatchersPreserveConfiguredRequestIDName(t *testing.T) {
	headers := []string{"x-custom-request-id", "x-request-id"}
	incomingMatcher := newIncomingHeaderMatcher(headers)
	outgoingMatcher := newOutgoingHeaderMatcher(headers)

	incoming, ok := incomingMatcher("X-Custom-Request-Id")
	require.True(t, ok)
	require.Equal(t, "x-custom-request-id", incoming)

	incoming2, ok2 := incomingMatcher("X-Request-Id")
	require.True(t, ok2)
	require.Equal(t, "x-request-id", incoming2)

	outgoing, ok3 := outgoingMatcher("x-custom-request-id")
	require.True(t, ok3)
	require.Equal(t, "x-custom-request-id", outgoing)
}

type capturingAuthzObserver struct {
	service.NoOpAuthzCheckObserver
	completion service.RequestCompletion
}

func (o *capturingAuthzObserver) AuthzCheckStarted(ctx context.Context) (context.Context, service.AuthzCheckProbe) {
	return ctx, &capturingAuthzProbe{observer: o}
}

type capturingAuthzProbe struct {
	service.NoOpAuthzCheckProbe
	observer *capturingAuthzObserver
}

func (p *capturingAuthzProbe) RequestCompleted(completion service.RequestCompletion) {
	p.observer.completion = completion
}

type capturingExchangeObserver struct {
	service.NoOpTokenExchangeObserver
	completion service.RequestCompletion
}

func (o *capturingExchangeObserver) TokenExchangeStarted(ctx context.Context, _, _, _, _ string) (context.Context, service.TokenExchangeProbe) {
	return ctx, &capturingExchangeProbe{observer: o}
}

type capturingExchangeProbe struct {
	service.NoOpTokenExchangeProbe
	observer *capturingExchangeObserver
}

func (p *capturingExchangeProbe) RequestCompleted(completion service.RequestCompletion) {
	p.observer.completion = completion
}
