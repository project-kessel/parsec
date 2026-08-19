package cel

import (
	"errors"
	"fmt"
	"testing"

	"github.com/project-kessel/parsec/internal/service"
)

func TestAbortDecision_MatchesDenyConstructors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want service.MappingDecision
	}{
		{
			name: "layer_a_invalid_request",
			err:  &abortError{decision: service.DenyOAuth(service.OAuthInvalidRequest, "bad request").Decision},
			want: service.DenyOAuth(service.OAuthInvalidRequest, "bad request").Decision,
		},
		{
			name: "layer_b_invalid_audience",
			err:  &abortError{decision: service.DenyReason(service.AbortReasonInvalidAudience, "bad aud").Decision},
			want: service.DenyReason(service.AbortReasonInvalidAudience, "bad aud").Decision,
		},
		{
			name: "layer_a_access_denied",
			err:  &abortError{decision: service.DenyOAuth(service.OAuthAccessDenied, "export compliance check failed").Decision},
			want: service.DenyOAuth(service.OAuthAccessDenied, "export compliance check failed").Decision,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := AbortDecision(fmt.Errorf("eval: %w", tc.err))
			if !ok {
				t.Fatal("expected AbortDecision ok")
			}
			if got.Action != tc.want.Action {
				t.Fatalf("Action: got %q, want %q", got.Action, tc.want.Action)
			}
			if got.ExchangeError == nil || tc.want.ExchangeError == nil {
				t.Fatalf("ExchangeError nil: got=%v, want=%v", got.ExchangeError, tc.want.ExchangeError)
			}
			if got.OAuthError != tc.want.OAuthError || got.Reason != tc.want.Reason || got.Message != tc.want.Message {
				t.Fatalf("decision fields: got {%q, %q, %q}, want {%q, %q, %q}",
					got.OAuthError, got.Reason, got.Message,
					tc.want.OAuthError, tc.want.Reason, tc.want.Message)
			}
		})
	}
}

func TestAbortDecision_RejectsMappingFailure(t *testing.T) {
	t.Parallel()

	_, ok := AbortDecision(&service.MappingFailure{Message: "boom"})
	if ok {
		t.Fatal("fail()-style MappingFailure must not be an abort decision")
	}
}

func TestUnwrapMappingFailure(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("wrap: %w", &service.MappingFailure{Message: "boom"})
	got := UnwrapMappingFailure(err)
	if got == nil || got.Message != "boom" {
		t.Fatalf("UnwrapMappingFailure: got %#v", got)
	}
	if UnwrapMappingFailure(errors.New("other")) != nil {
		t.Fatal("expected nil for non-MappingFailure")
	}
	if UnwrapMappingFailure(&service.ExchangeError{Message: "deny", OAuthError: service.OAuthInvalidRequest}) != nil {
		t.Fatal("ExchangeError must not unwrap as MappingFailure")
	}
}
