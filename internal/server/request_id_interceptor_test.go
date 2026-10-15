package server

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
)

// These tests exercise request-ID extraction and propagation through the
// *real* gRPC stack: Server.trackSecurityRequest (the interceptor) populates
// the context, and AuthzServer.Check / ExchangeServer.Exchange read it back
// via request.IDExtracted / request.CanonicalRequestIDHeader.
//
// Unlike the unit tests in audit_request_test.go (which call the extracted
// helper functions directly) and the handler tests in authz_test.go /
// exchange_test.go (which call Check/Exchange directly, bypassing the
// interceptor entirely), these tests go through startTestServer's bufconn
// gRPC server so the interceptor is actually invoked. This guards against a
// regression where the interceptor and handlers disagree on the context key
// or the interceptor is accidentally skipped for one of the two methods.

// responseHeaders returns the propagated headers from whichever CheckResponse
// variant (Ok or Denied) the server returned.
func responseHeaders(resp *authv3.CheckResponse) []*corev3.HeaderValueOption {
	if ok := resp.GetOkResponse(); ok != nil {
		return ok.GetHeaders()
	}
	return resp.GetDeniedResponse().GetHeaders()
}

func TestInterceptor_AuthzCheck_PropagatesExtractedRequestID(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	client := authv3.NewAuthorizationClient(env.GRPCConn)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/resource",
					Headers: map[string]string{
						"x-request-id": "client-supplied-id",
					},
				},
			},
		},
	}

	resp, err := client.Check(env.Ctx, req)
	require.NoError(t, err)

	headers := responseHeaders(resp)
	require.Len(t, headers, 1, "expected exactly one propagated header")
	require.Equal(t, "x-request-id", headers[0].GetHeader().GetKey())
	require.Equal(t, "client-supplied-id", headers[0].GetHeader().GetValue())
}

func TestInterceptor_AuthzCheck_DoesNotPropagateGeneratedRequestID(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	client := authv3.NewAuthorizationClient(env.GRPCConn)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/resource",
					// No x-request-id header: the interceptor must generate
					// a local fallback ID, which must NOT be propagated.
				},
			},
		},
	}

	resp, err := client.Check(env.Ctx, req)
	require.NoError(t, err)

	require.Empty(t, responseHeaders(resp), "locally-generated fallback IDs must not be propagated upstream")
}

func TestInterceptor_Exchange_PropagatesExtractedRequestID(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	client := parsecv1.NewTokenExchangeServiceClient(env.GRPCConn)

	ctx := metadata.AppendToOutgoingContext(env.Ctx, "x-request-id", "client-supplied-id")

	var respHeader metadata.MD
	// An unsupported grant type fails fast, but request-ID propagation
	// happens before grant-type validation, so the header must still be set
	// on the (error) response.
	_, err := client.Exchange(ctx, &parsecv1.ExchangeRequest{
		GrantType: "unsupported-grant-type",
	}, grpc.Header(&respHeader))
	require.Error(t, err, "unsupported grant type is expected to fail")

	require.Equal(t, []string{"client-supplied-id"}, respHeader.Get("x-request-id"),
		"extracted request ID must be propagated even on error responses")
}

func TestInterceptor_Exchange_DoesNotPropagateGeneratedRequestID(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	client := parsecv1.NewTokenExchangeServiceClient(env.GRPCConn)

	var respHeader metadata.MD
	_, err := client.Exchange(env.Ctx, &parsecv1.ExchangeRequest{
		GrantType: "unsupported-grant-type",
	}, grpc.Header(&respHeader))
	require.Error(t, err)

	require.Empty(t, respHeader.Get("x-request-id"),
		"locally-generated fallback IDs must not be propagated upstream")
}
