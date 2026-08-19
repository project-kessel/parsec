package server

import (
	"context"
	"encoding/json"
	"net/http"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/service"
)

const oauthErrorDomain = "oauth"

// oauthDenialStatuses maps an OAuth wire code to the gRPC code and Envoy HTTP
// status used by exchange and ext_authz. Client-auth failures are 401; other
// OAuth client errors are 400 (RFC 8693 / exchange parity).
func oauthDenialStatuses(code service.OAuthErrorCode) (codes.Code, typev3.StatusCode) {
	switch code {
	case service.OAuthInvalidClient, service.OAuthUnauthorizedClient:
		return codes.Unauthenticated, typev3.StatusCode_Unauthorized
	case service.OAuthAccessDenied:
		return codes.PermissionDenied, typev3.StatusCode_Forbidden
	default:
		return codes.InvalidArgument, typev3.StatusCode_BadRequest
	}
}

// exchangeErrToAuthzDenial maps an ExchangeError to ext_authz denial fields:
// gRPC status code, explicit DeniedHttpResponse HTTP status, and body message.
func exchangeErrToAuthzDenial(exchErr *service.ExchangeError) (codes.Code, typev3.StatusCode, string) {
	msg := exchErr.Message
	if msg == "" {
		msg = string(exchErr.OAuthError)
	}
	grpcCode, httpStatus := oauthDenialStatuses(exchErr.OAuthError)
	return grpcCode, httpStatus, msg
}

// exchangeErrToGRPC maps an ExchangeError (known OAuth denial) to a gRPC
// status with ErrorInfo carrying the OAuth wire code. Used by the exchange
// endpoint when ExchangeResult.ExchangeErr is non-nil.
func exchangeErrToGRPC(exchErr *service.ExchangeError) error {
	msg := exchErr.Message
	if msg == "" {
		msg = string(exchErr.OAuthError)
	}

	grpcCode, _ := oauthDenialStatuses(exchErr.OAuthError)
	st := status.New(grpcCode, msg)
	info := &errdetails.ErrorInfo{
		Reason: string(exchErr.OAuthError),
		Domain: oauthErrorDomain,
		Metadata: map[string]string{
			"error_description": msg,
		},
	}
	if exchErr.Reason != "" {
		info.Metadata["abort_reason"] = string(exchErr.Reason)
	}
	detailed, detailErr := st.WithDetails(info)
	if detailErr != nil {
		return st.Err()
	}
	return detailed.Err()
}

// internalGRPCError maps an unexpected error to a gRPC Internal status.
// Used by the exchange endpoint when IssueTokens returns a top-level error.
func internalGRPCError(err error) error {
	return status.Errorf(codes.Internal, "failed to issue token: %v", err)
}

// oauthHTTPErrorHandler writes RFC 6749 §5.2 / RFC 8693 error JSON for OAuth
// errors encoded in gRPC ErrorInfo. All other errors use the default handler.
func oauthHTTPErrorHandler(
	ctx context.Context,
	mux *runtime.ServeMux,
	marshaler runtime.Marshaler,
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	st := status.Convert(err)
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok || info.Domain != oauthErrorDomain {
			continue
		}
		desc := info.Metadata["error_description"]
		if desc == "" {
			desc = st.Message()
		}
		body, marshalErr := json.Marshal(map[string]string{
			"error":             info.Reason,
			"error_description": desc,
		})
		if marshalErr != nil {
			runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(runtime.HTTPStatusFromCode(st.Code()))
		_, _ = w.Write(body)
		return
	}
	runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
}
