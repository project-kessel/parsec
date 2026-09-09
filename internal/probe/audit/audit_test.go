package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestAuthzAuditUsesDefaultParsecPrefixAndSafeContract(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
	ctx := request.WithID(context.Background(), "request-123")
	_, probe := obs.AuthzCheckStarted(ctx)
	probe.RequestAttributesParsed(&request.RequestAttributes{
		Method: "GET",
		Path:   "/api/widgets?access_token=secret-query",
		Headers: map[string]string{
			"authorization": "Bearer secret-token",
			"cookie":        "cross_access_org_id=target-org; session=secret-cookie",
		},
	})
	probe.SubjectCredentialExtracted(&trust.BearerCredential{Token: "secret-token"}, []string{"authorization"})
	probe.SubjectValidationSucceeded(&trust.Result{
		Subject:     "user-123",
		TrustDomain: "sso.example",
		Claims: map[string]any{
			"org_id": "org-123",
			"email":  "secret@example.com",
		},
	})
	probe.RequestCompleted(service.RequestCompletion{
		Outcome:    service.AuditOutcomeSuccess,
		GRPCCode:   0,
		HTTPStatus: 200,
		TokenTypes: []service.TokenType{"rh-identity"},
	})
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 3)
	require.Equal(t, "parsec_request", records[0]["log_type"])
	require.Equal(t, records[0]["log_type"], records[0]["event"])
	require.Equal(t, "1.0", records[0]["schema_version"])
	require.Equal(t, "request-123", records[0]["request_id"])
	require.Equal(t, "success", records[0]["outcome"])
	require.Equal(t, "info", records[0]["level"])
	require.Equal(t, "parsec_rbac_cross_access_audit", records[1]["log_type"])
	require.Equal(t, "parsec_authorize", records[2]["log_type"])

	serialized := output.String()
	require.NotContains(t, serialized, "secret-token")
	require.NotContains(t, serialized, "secret-query")
	require.NotContains(t, serialized, "secret-cookie")
	require.NotContains(t, serialized, "secret@example.com")
}

func TestAuthzAuditEmitsNamedFailureEventsWithoutRawError(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-456"))
	probe.RequestAttributesParsed(&request.RequestAttributes{Method: "GET", Path: "/api/widgets"})
	probe.SubjectValidationFailed(errors.New("validator leaked secret-token"))
	probe.RequestCompleted(service.RequestCompletion{
		Outcome:    service.AuditOutcomeDenied,
		ReasonCode: ReasonCredentialInvalid,
		GRPCCode:   16,
		HTTPStatus: 401,
	})
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, "parsec_request", records[0]["log_type"])
	require.Equal(t, "parsec_authorize", records[1]["log_type"])
	require.Equal(t, "warn", records[0]["level"])
	require.NotContains(t, output.String(), "secret-token")
}

func TestTokenExchangeAuditEmitsSingleTerminalRequest(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx := request.WithID(context.Background(), "exchange-1")
	_, probe := obs.TokenExchangeStarted(ctx, "grant", "requested", "aud", "scope")
	probe.ActorCredentialExtracted(&trust.BasicAuthCredential{Username: "user", Password: "secret-password"}, []string{"authorization"})
	probe.ActorValidationSucceeded(&trust.Result{Subject: "actor-1", TrustDomain: "actor.example"})
	probe.SubjectTokenValidationSucceeded(&trust.Result{Subject: "subject-1", TrustDomain: "subject.example"})
	probe.RequestCompleted(service.RequestCompletion{
		Outcome:    service.AuditOutcomeSuccess,
		GRPCCode:   0,
		HTTPStatus: 200,
		TokenTypes: []service.TokenType{"requested"},
	})
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	require.Equal(t, "parsec_request", records[0]["log_type"])
	require.NotContains(t, output.String(), "secret-password")
}

func TestAuditEventPrefixCanBeCustomizedOrRemoved(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{name: "3scale compatibility", prefix: "parsec_", want: "parsec_request"},
		{name: "no prefix", prefix: "", want: "request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"}, WithEventPrefix(tt.prefix))
			_, probe := obs.TokenExchangeStarted(request.WithID(context.Background(), "prefix-test"), "", "", "", "")
			probe.RequestCompleted(service.RequestCompletion{Outcome: service.AuditOutcomeSuccess, HTTPStatus: 200})
			probe.End()
			obs.ProcessReady(server.ProcessInfo{})
			_, rotation := obs.RotationCheckStarted(context.Background())
			rotation.RotationCompleted("active")
			rotation.End()

			records := decodeRecords(t, output.Bytes())
			require.Equal(t, []string{tt.want, tt.prefix + "process_status", tt.prefix + "key_rotation"}, eventNames(records))
			for _, record := range records {
				require.Equal(t, record["log_type"], record["event"])
			}
		})
	}
}

func TestValidEventPrefix(t *testing.T) {
	for _, prefix := range []string{"", "parsec_", "tenant-1.", "ABC_123"} {
		require.True(t, ValidEventPrefix(prefix), prefix)
	}
	for _, prefix := range []string{"bad prefix", "bad/", "line\nbreak", "påarsec_"} {
		require.False(t, ValidEventPrefix(prefix), prefix)
	}
}

func TestAuditEmitsKeyLifecycleEvents(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})

	_, rotation := obs.RotationCheckStarted(context.Background())
	rotation.RotationCompleted("slot-a")
	rotation.End()

	_, kms := obs.KMSRotateStarted(context.Background(), "secret-trust-domain", "secret-namespace", "secret-key-name")
	kms.KeyCreated()
	kms.AliasChanged(true)
	kms.DeletionScheduled()
	kms.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 4)
	for _, record := range records {
		require.Equal(t, "parsec_key_rotation", record["log_type"])
		require.Equal(t, record["log_type"], record["event"])
	}
	require.NotContains(t, output.String(), "secret-key-name")
	require.NotContains(t, output.String(), "secret-namespace")
}

func TestAuditEmitsProcessReadyAndShutdown(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
	obs.ProcessReady(server.ProcessInfo{Version: "v1", Commit: "abc123", TrustDomain: "prod.example"})
	_, stop := obs.StopStarted(context.Background())
	stop.ShutdownCompleted(0)
	stop.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, "parsec_process_status", records[0]["log_type"])
	require.Equal(t, "process_ready", records[0]["action"])
	require.Equal(t, "parsec_process_status", records[1]["log_type"])
	require.Equal(t, "process_stop", records[1]["action"])
}

func TestAuditEmitsEveryThreeScaleFailureName(t *testing.T) {
	tests := []struct {
		reason string
		name   string
	}{
		{ReasonComplianceDenied, "parsec_auth_compliance_failure"},
		{ReasonComplianceFailure, "parsec_compliance_failure"},
		{ReasonSupplementalFailure, "parsec_supplemental_user_data_failure"},
		{ReasonDependencyFailure, "parsec_dependency_failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
			_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-failure"))
			probe.RequestCompleted(service.RequestCompletion{Outcome: service.AuditOutcomeFailure, ReasonCode: tt.reason, GRPCCode: 13, HTTPStatus: 500})
			probe.End()

			names := map[string]bool{}
			for _, record := range decodeRecords(t, output.Bytes()) {
				names[record["log_type"].(string)] = true
			}
			require.True(t, names[tt.name])
		})
	}
}

func TestAuditEmitsCertificateAndInternalAuthenticationNames(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-auth"))
	probe.SubjectCredentialExtracted(&trust.MTLSCredential{Certificate: []byte("secret-certificate")}, nil)
	probe.ActorCredentialExtracted(&trust.HeaderCredential{Headers: map[string]string{"x-psk": "secret-psk"}}, nil)
	probe.RequestCompleted(service.RequestCompletion{Outcome: service.AuditOutcomeSuccess, HTTPStatus: 200})
	probe.End()

	names := map[string]bool{}
	for _, record := range decodeRecords(t, output.Bytes()) {
		names[record["log_type"].(string)] = true
	}
	require.True(t, names["parsec_validate_ssl_cert"])
	require.True(t, names["parsec_verify_psk"])
	require.NotContains(t, output.String(), "secret-certificate")
	require.NotContains(t, output.String(), "secret-psk")
}

func TestAuditCorrelatesNestedCacheAndDependencyProbes(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-nested"))
	_, cacheProbe := obs.InMemoryValidateStarted(ctx, "validator")
	cacheProbe.CacheHit()
	_, dataProbe := obs.LuaFetchStarted(ctx, "backoffice-proxy")
	dataProbe.ScriptExecutionFailed(errors.New("secret dependency response"))
	probe.RequestCompleted(service.RequestCompletion{Outcome: service.AuditOutcomeFailure, ReasonCode: ReasonInternalError, HTTPStatus: 500})
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, "error", records[0]["level"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "hit", resource["cache_status"])
	names := map[string]bool{}
	for _, record := range records {
		names[record["log_type"].(string)] = true
	}
	require.True(t, names["parsec_supplemental_user_data_failure"])
	require.NotContains(t, output.String(), "secret dependency response")
}

func TestAuditRejectsUnrecognizedReasonAndTokenValues(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.TokenExchangeStarted(request.WithID(context.Background(), "request-safe"), "", "secret-requested-type", "", "")
	probe.RequestCompleted(service.RequestCompletion{
		Outcome:    service.AuditOutcomeFailure,
		ReasonCode: "secret-arbitrary-error",
		TokenTypes: []service.TokenType{"secret-issued-token-type"},
	})
	probe.End()

	require.NotContains(t, output.String(), "secret-arbitrary-error")
	require.NotContains(t, output.String(), "secret-requested-type")
	require.NotContains(t, output.String(), "secret-issued-token-type")
	require.Contains(t, output.String(), ReasonInternalError)
}

func decodeRecords(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	var records []map[string]any
	for {
		var record map[string]any
		err := dec.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		records = append(records, record)
	}
	return records
}

func eventNames(records []map[string]any) []string {
	names := make([]string, 0, len(records))
	for _, record := range records {
		name, _ := record["log_type"].(string)
		names = append(names, name)
	}
	return names
}
