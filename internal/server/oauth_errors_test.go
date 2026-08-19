package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/service"
)

func TestExchangeErrToGRPC(t *testing.T) {
	t.Run("invalid_request", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "impersonated tokens are not accepted",
			OAuthError: service.OAuthInvalidRequest,
			Reason:     service.AbortReasonInvalidSubject,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("code: got %v, want InvalidArgument", st.Code())
		}
		if st.Message() != "impersonated tokens are not accepted" {
			t.Errorf("message: got %q", st.Message())
		}
		info := oauthErrorInfo(t, st)
		if info.Reason != string(service.OAuthInvalidRequest) {
			t.Errorf("ErrorInfo.Reason: got %q", info.Reason)
		}
		if info.Metadata["abort_reason"] != string(service.AbortReasonInvalidSubject) {
			t.Errorf("abort_reason: got %q", info.Metadata["abort_reason"])
		}
	})

	t.Run("invalid_target", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "bad audience",
			OAuthError: service.OAuthInvalidTarget,
			Reason:     service.AbortReasonInvalidAudience,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("code: got %v, want InvalidArgument", st.Code())
		}
		info := oauthErrorInfo(t, st)
		if info.Reason != string(service.OAuthInvalidTarget) {
			t.Errorf("ErrorInfo.Reason: got %q", info.Reason)
		}
	})

	t.Run("invalid_client_is_unauthenticated", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "bad client",
			OAuthError: service.OAuthInvalidClient,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.Unauthenticated {
			t.Errorf("code: got %v, want Unauthenticated", st.Code())
		}
	})

	t.Run("no_abort_reason_when_empty", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "bad request",
			OAuthError: service.OAuthInvalidRequest,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		info := oauthErrorInfo(t, st)
		if _, hasReason := info.Metadata["abort_reason"]; hasReason {
			t.Error("Layer A (no reason) should not set abort_reason metadata")
		}
	})
}

func TestExchangeErrToAuthzDenial(t *testing.T) {
	tests := []struct {
		name     string
		oauth    service.OAuthErrorCode
		wantGRPC codes.Code
		wantHTTP typev3.StatusCode
		wantMsg  string
		message  string
	}{
		{
			name:     "invalid_request",
			oauth:    service.OAuthInvalidRequest,
			message:  "impersonated",
			wantGRPC: codes.InvalidArgument,
			wantHTTP: typev3.StatusCode_BadRequest,
			wantMsg:  "impersonated",
		},
		{
			name:     "invalid_target",
			oauth:    service.OAuthInvalidTarget,
			message:  "bad aud",
			wantGRPC: codes.InvalidArgument,
			wantHTTP: typev3.StatusCode_BadRequest,
			wantMsg:  "bad aud",
		},
		{
			name:     "invalid_grant",
			oauth:    service.OAuthInvalidGrant,
			message:  "bad grant",
			wantGRPC: codes.InvalidArgument,
			wantHTTP: typev3.StatusCode_BadRequest,
			wantMsg:  "bad grant",
		},
		{
			name:     "invalid_scope",
			oauth:    service.OAuthInvalidScope,
			message:  "bad scope",
			wantGRPC: codes.InvalidArgument,
			wantHTTP: typev3.StatusCode_BadRequest,
			wantMsg:  "bad scope",
		},
		{
			name:     "unsupported_grant_type",
			oauth:    service.OAuthUnsupportedGrantType,
			message:  "bad grant type",
			wantGRPC: codes.InvalidArgument,
			wantHTTP: typev3.StatusCode_BadRequest,
			wantMsg:  "bad grant type",
		},
		{
			name:     "invalid_client",
			oauth:    service.OAuthInvalidClient,
			message:  "bad client",
			wantGRPC: codes.Unauthenticated,
			wantHTTP: typev3.StatusCode_Unauthorized,
			wantMsg:  "bad client",
		},
		{
			name:     "unauthorized_client",
			oauth:    service.OAuthUnauthorizedClient,
			message:  "not authorized",
			wantGRPC: codes.Unauthenticated,
			wantHTTP: typev3.StatusCode_Unauthorized,
			wantMsg:  "not authorized",
		},
		{
			name:     "access_denied_is_forbidden",
			oauth:    service.OAuthAccessDenied,
			message:  "export compliance check failed",
			wantGRPC: codes.PermissionDenied,
			wantHTTP: typev3.StatusCode_Forbidden,
			wantMsg:  "export compliance check failed",
		},
		{
			name:     "empty_message_falls_back_to_code",
			oauth:    service.OAuthInvalidRequest,
			message:  "",
			wantGRPC: codes.InvalidArgument,
			wantHTTP: typev3.StatusCode_BadRequest,
			wantMsg:  string(service.OAuthInvalidRequest),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcCode, httpStatus, msg := exchangeErrToAuthzDenial(&service.ExchangeError{
				OAuthError: tt.oauth,
				Message:    tt.message,
			})
			if grpcCode != tt.wantGRPC {
				t.Errorf("gRPC: got %v, want %v", grpcCode, tt.wantGRPC)
			}
			if httpStatus != tt.wantHTTP {
				t.Errorf("HTTP: got %v, want %v", httpStatus, tt.wantHTTP)
			}
			if msg != tt.wantMsg {
				t.Errorf("message: got %q, want %q", msg, tt.wantMsg)
			}
		})
	}
}

func TestInternalGRPCError(t *testing.T) {
	t.Run("wraps_error_as_internal", func(t *testing.T) {
		err := internalGRPCError(errors.New("signing failed"))
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("code: got %v, want Internal", st.Code())
		}
		if st.Message() != "failed to issue token: signing failed" {
			t.Errorf("message: got %q", st.Message())
		}
	})

	t.Run("no_oauth_error_info", func(t *testing.T) {
		err := internalGRPCError(errors.New("boom"))
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		for _, d := range st.Details() {
			if _, ok := d.(*errdetails.ErrorInfo); ok {
				t.Fatal("internal errors should not attach OAuth ErrorInfo")
			}
		}
	})
}

func TestOAuthHTTPErrorHandler(t *testing.T) {
	mux := runtime.NewServeMux()
	marshaler := &runtime.JSONPb{}

	t.Run("writes_oauth_json", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "impersonated tokens are not accepted",
			OAuthError: service.OAuthInvalidRequest,
			Reason:     service.AbortReasonInvalidSubject,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/token", nil)
		oauthHTTPErrorHandler(context.Background(), mux, marshaler, rec, req, err)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status: got %d, want 400", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if body["error"] != string(service.OAuthInvalidRequest) {
			t.Errorf("error: got %q", body["error"])
		}
		if body["error_description"] != "impersonated tokens are not accepted" {
			t.Errorf("error_description: got %q", body["error_description"])
		}
	})

	t.Run("invalid_client_writes_401", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "unknown client",
			OAuthError: service.OAuthInvalidClient,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/token", nil)
		oauthHTTPErrorHandler(context.Background(), mux, marshaler, rec, req, err)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status: got %d, want 401", rec.Code)
		}
	})

	t.Run("non_oauth_uses_default", func(t *testing.T) {
		err := status.Error(codes.Internal, "failed to issue token: boom")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/token", nil)
		oauthHTTPErrorHandler(context.Background(), mux, marshaler, rec, req, err)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status: got %d, want 500", rec.Code)
		}
		body, _ := io.ReadAll(rec.Body)
		if len(body) == 0 {
			t.Fatal("expected default error body")
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("default body should be JSON: %v", err)
		}
		if _, ok := parsed["error"]; ok {
			t.Error("non-OAuth errors should not use OAuth error field")
		}
	})
}

func oauthErrorInfo(t *testing.T, st *status.Status) *errdetails.ErrorInfo {
	t.Helper()
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info
		}
	}
	t.Fatal("expected ErrorInfo detail")
	return nil
}
