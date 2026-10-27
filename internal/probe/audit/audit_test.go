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

	auditctx "github.com/project-kessel/parsec/internal/audit"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestAuthzAuditUsesDefaultParsecPrefixAndSafeContract(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
	ctx := request.WithID(context.Background(), "request-123")
	ctx, probe := obs.AuthzCheckStarted(ctx)

	// Simulate Lua validator emitting a cross-account signal (previously detected by Go cookie parsing).
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source:    auditctx.SourceValidator,
		Operation: "cross_account_access",
		Outcome:   auditctx.OutcomeSuccess,
		Metadata: map[string]string{
			"target_org_id": "target-org",
		},
	})

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
	probe.PolicyDecisionIssue(1, "", "")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 3)
	require.Equal(t, "parsec_request", records[0]["event"])
	require.Equal(t, "1.0", records[0]["schema_version"])
	require.Equal(t, "request-123", records[0]["request_id"])
	require.Equal(t, "success", records[0]["outcome"])
	require.Equal(t, "info", records[0]["level"])
	require.Equal(t, "parsec_rbac_cross_access_audit", records[1]["event"])
	require.Equal(t, "parsec_authorize", records[2]["event"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "authorization_request", resource["type"],
		"ext_authz must emit resource type 'authorization_request'")

	// Verify cross_account metadata is carried through from the signal
	crossAccount, hasCrossAccount := records[1]["cross_account"].(map[string]any)
	require.True(t, hasCrossAccount)
	require.Equal(t, "target-org", crossAccount["target_org_id"])

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
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, "parsec_request", records[0]["event"])
	require.Equal(t, "parsec_authorize", records[1]["event"])
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
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	require.Equal(t, "parsec_request", records[0]["event"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "token_exchange_request", resource["type"],
		"token exchange must emit resource type 'token_exchange_request', not 'authorization_request'")
	require.NotContains(t, output.String(), "secret-password")
}

func TestAuditReporterPropagatesSignalsIntoRequestRecord(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "signal-1"))
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source: auditctx.SourceDataSource, Operation: "user_enrichment",
		Outcome: auditctx.OutcomeFailure, ReasonCode: ReasonSupplementalFailure,
	})
	probe.PolicyEvaluationFailed(errors.New("data source failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 3)
	requestRecord := records[0]
	signals, ok := requestRecord["signals"].([]any)
	require.True(t, ok)
	require.Len(t, signals, 1)
	require.Equal(t, "user_enrichment", signals[0].(map[string]any)["operation"])
	require.Equal(t, "parsec_supplemental_user_data_failure", records[2]["event"])
}

func TestCrossAccountDeniedSignalPreservesReasonCode(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "cross-account-1"))
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source:     auditctx.SourceValidator,
		Operation:  "cross_account_access",
		Outcome:    auditctx.OutcomeDenied,
		ReasonCode: ReasonCrossAccountDenied,
	})
	probe.PolicyDecisionDeny("policy denied")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	var crossAccountRecord map[string]any
	for _, record := range records {
		if record["event"] == "parsec_rbac_cross_access_audit" {
			crossAccountRecord = record
		}
	}
	require.NotNil(t, crossAccountRecord, "expected a rbac_cross_access_audit record")
	require.Equal(t, "denied", crossAccountRecord["outcome"])
	require.Equal(t, ReasonCrossAccountDenied, crossAccountRecord["reason_code"],
		"cross_account_denied must not be rewritten to internal_error by safeReasonCode")
}

func TestValidReasonCodeAcceptsKnownReasonsOnly(t *testing.T) {
	require.True(t, ValidReasonCode(ReasonCrossAccountDenied))
	require.True(t, ValidReasonCode(ReasonDependencyFailure))
	require.False(t, ValidReasonCode("not_a_real_reason"))
	require.False(t, ValidReasonCode(""))
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
			probe.End()
			obs.ProcessReady(server.ProcessInfo{})
			_, rotation := obs.RotationCheckStarted(context.Background())
			rotation.RotationCompleted("active")
			rotation.End()

			records := decodeRecords(t, output.Bytes())
			require.Equal(t, []string{tt.want, tt.prefix + "process_status", tt.prefix + "key_rotation"}, eventNames(records))
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
		require.Equal(t, "parsec_key_rotation", record["event"])
	}
	require.Equal(t, "key_alias_create", records[2]["action"])
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
	require.Equal(t, "parsec_process_status", records[0]["event"])
	require.Equal(t, "process_ready", records[0]["action"])
	require.Equal(t, "parsec_process_status", records[1]["event"])
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
			ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-failure"))
			auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
				Source:     auditctx.SourceDataSource,
				Operation:  "test",
				Outcome:    auditctx.OutcomeFailure,
				ReasonCode: tt.reason,
			})
			probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
			probe.End()

			names := map[string]bool{}
			for _, record := range decodeRecords(t, output.Bytes()) {
				names[record["event"].(string)] = true
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
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	names := map[string]bool{}
	for _, record := range decodeRecords(t, output.Bytes()) {
		names[record["event"].(string)] = true
	}
	require.True(t, names["parsec_validate_ssl_cert"])
	require.True(t, names["parsec_verify_psk"])
	require.NotContains(t, output.String(), "secret-certificate")
	require.NotContains(t, output.String(), "secret-psk")
}

func TestAuditCorrelatesNestedCacheAndDependencyProbes(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"},
		WithFailureClassifications(map[string]string{
			"backoffice-proxy": ReasonSupplementalFailure,
		}),
	)
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-nested"))
	_, cacheProbe := obs.InMemoryValidateStarted(ctx, "validator")
	cacheProbe.CacheHit()
	_, dataProbe := obs.LuaFetchStarted(ctx, "backoffice-proxy")
	dataProbe.ScriptExecutionFailed(errors.New("secret dependency response"))
	probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, "error", records[0]["level"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "hit", resource["cache_status"])

	layers, hasLayers := resource["cache_layers"].([]any)
	require.True(t, hasLayers, "cache_layers must be present when cache probes fire")
	require.Len(t, layers, 1)
	layer0 := layers[0].(map[string]any)
	require.Equal(t, "validator_memory", layer0["layer"])
	require.Equal(t, "hit", layer0["status"])

	names := map[string]bool{}
	for _, record := range records {
		names[record["event"].(string)] = true
	}
	require.True(t, names["parsec_supplemental_user_data_failure"])
	require.NotContains(t, output.String(), "secret dependency response")
}

func TestCacheLayersEmittedPerComponent(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "multi-layer"))

	_, memProbe := obs.InMemoryValidateStarted(ctx, "jwt-validator")
	memProbe.CacheMiss()

	_, distProbe := obs.DistributedValidateStarted(ctx, "jwt-validator")
	distProbe.ResultExpired()

	_, dsProbe := obs.CacheFetchStarted(ctx, "backoffice")
	dsProbe.CacheHit()

	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	resource := records[0]["resource"].(map[string]any)

	require.Equal(t, "hit", resource["cache_status"],
		"terminal cache_status should be the last writer (datasource hit)")

	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 3, "all three cache layers must be recorded")

	layer0 := layers[0].(map[string]any)
	require.Equal(t, "validator_memory", layer0["layer"])
	require.Equal(t, "miss", layer0["status"])

	layer1 := layers[1].(map[string]any)
	require.Equal(t, "validator_distributed", layer1["layer"])
	require.Equal(t, "expired", layer1["status"])

	layer2 := layers[2].(map[string]any)
	require.Equal(t, "datasource:backoffice", layer2["layer"])
	require.Equal(t, "hit", layer2["status"])
}

func TestDistributedGetFailedEmitsCacheLayer(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "distributed-get-failed"))

	_, distProbe := obs.DistributedValidateStarted(ctx, "jwt-validator")
	distProbe.GetFailed(errors.New("groupcache peer unreachable"))

	probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	resource := records[0]["resource"].(map[string]any)

	require.Equal(t, "failure", resource["cache_status"])

	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 1)
	layer0 := layers[0].(map[string]any)
	require.Equal(t, "validator_distributed", layer0["layer"])
	require.Equal(t, "failure", layer0["status"])

	require.Equal(t, ReasonDependencyFailure, records[0]["reason_code"],
		"GetFailed must classify as dependency_failure")
	require.NotContains(t, output.String(), "groupcache peer unreachable")
}

func TestFirstFailureReasonWins(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"},
		WithFailureClassifications(map[string]string{
			"enrichment": ReasonSupplementalFailure,
		}),
	)
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "first-wins"))

	_, jwtProbe := obs.JWTValidateStarted(ctx, "https://sso.example")
	jwtProbe.JWKSLookupFailed(errors.New("JWKS timeout"))

	_, dsProbe := obs.CacheFetchStarted(ctx, "enrichment")
	dsProbe.FetchFailed(errors.New("enrichment timeout"))

	probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, ReasonDependencyFailure, records[0]["reason_code"],
		"first failure reason (dependency_failure from JWKS) must win over supplemental_user_data_failure")
}

func TestInvalidCacheStatusDropped(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "invalid-status"))

	state := request.AuditStateFrom(ctx)
	state.RecordCacheLayer("test_layer", "bogus_value")
	state.RecordCacheLayer("test_layer", "hit")

	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "hit", resource["cache_status"],
		"only the valid status should survive")

	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 1, "invalid status must not produce a cache layer entry")
	require.Equal(t, "hit", layers[0].(map[string]any)["status"])
}

func TestNoCacheProbeEmitsNoCacheStatus(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "no-cache"))
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	resource := records[0]["resource"].(map[string]any)
	_, hasCacheStatus := resource["cache_status"]
	require.False(t, hasCacheStatus,
		"cache_status must be omitted (omitempty) when no cache probe fires")
	_, hasCacheLayers := resource["cache_layers"]
	require.False(t, hasCacheLayers,
		"cache_layers must be omitted (omitempty) when no cache probe fires")
}

func TestDeriveCompletion_ExchangeErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(probe *requestProbe)
		wantOutcome AuditOutcome
		wantReason  string
	}{
		{
			name:        "happy path — no callbacks → success",
			setup:       func(_ *requestProbe) {},
			wantOutcome: AuditOutcomeSuccess,
			wantReason:  "",
		},
		{
			name: "token issuance denied produces denied outcome",
			setup: func(p *requestProbe) {
				p.tokenIssuanceDenied = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  ReasonTokenIssuanceDenied,
		},
		{
			name: "token issuance denied overrides policy issue",
			setup: func(p *requestProbe) {
				p.policyIssue = true
				p.tokenIssuanceDenied = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  ReasonTokenIssuanceDenied,
		},
		{
			name: "token issuance denied takes priority over failure",
			setup: func(p *requestProbe) {
				p.tokenIssuanceDenied = true
				p.tokenIssuanceFailed = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  ReasonTokenIssuanceDenied,
		},
		{
			name: "token issuance failed overrides policy issue",
			setup: func(p *requestProbe) {
				p.policyIssue = true
				p.tokenIssuanceFailed = true
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  ReasonTokenIssuanceFailed,
		},
		{
			name: "token issuance failed without policy issue",
			setup: func(p *requestProbe) {
				p.tokenIssuanceFailed = true
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  ReasonTokenIssuanceFailed,
		},
		{
			name: "request failed with grant_type error",
			setup: func(p *requestProbe) {
				p.requestFailed = true
				p.requestFailedErr = errors.New("unsupported grant_type: foo")
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  ReasonGrantTypeUnsupported,
		},
		{
			name: "request failed with generic error",
			setup: func(p *requestProbe) {
				p.requestFailed = true
				p.requestFailedErr = errors.New("something unexpected")
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  ReasonInternalError,
		},
		{
			name: "actor extraction failed → denied credential_malformed",
			setup: func(p *requestProbe) {
				p.actorExtractionFailed = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  ReasonCredentialMalformed,
		},
		{
			name: "policy denied → ReasonPolicyDenied regardless of deny reason text",
			setup: func(p *requestProbe) {
				p.policyDenied = true
				p.policyDenyReason = "something with jwks in it"
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  ReasonPolicyDenied,
		},
		{
			name: "policy allowed → success",
			setup: func(p *requestProbe) {
				p.policyAllowed = true
			},
			wantOutcome: AuditOutcomeSuccess,
			wantReason:  "",
		},
		{
			name: "policy issue → success",
			setup: func(p *requestProbe) {
				p.policyIssue = true
			},
			wantOutcome: AuditOutcomeSuccess,
			wantReason:  "",
		},
		{
			name: "subject extraction failed → denied credential_malformed",
			setup: func(p *requestProbe) {
				p.subjectExtractionFailed = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  ReasonCredentialMalformed,
		},
		{
			name: "request context parse failed → failure internal_error",
			setup: func(p *requestProbe) {
				p.requestContextParseFailed = true
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  ReasonInternalError,
		},
		{
			name: "policy eval error → failure",
			setup: func(p *requestProbe) {
				p.policyEvalErr = errors.New("evaluation error")
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  ReasonInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &requestProbe{}
			tt.setup(p)
			outcome, reason := p.deriveCompletion()
			require.Equal(t, tt.wantOutcome, outcome, "outcome")
			require.Equal(t, tt.wantReason, reason, "reason")
		})
	}
}

func TestAuditRejectsUnrecognizedReasonAndTokenValues(t *testing.T) {
	var output bytes.Buffer
	obs := New(zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.TokenExchangeStarted(request.WithID(context.Background(), "request-safe"), "", "secret-requested-type", "", "")
	probe.ActorValidationFailed(errors.New("secret-arbitrary-error"))
	probe.End()

	require.NotContains(t, output.String(), "secret-arbitrary-error")
	require.NotContains(t, output.String(), "secret-requested-type")
	require.NotContains(t, output.String(), "secret-issued-token-type")
	require.Contains(t, output.String(), ReasonCredentialInvalid)
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
		name, _ := record["event"].(string)
		names = append(names, name)
	}
	return names
}

func BenchmarkRequestProbeEnd(b *testing.B) {
	obs := New(zerolog.New(io.Discard), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
	for i := 0; i < b.N; i++ {
		ctx := request.WithID(context.Background(), "bench-id")
		ctx, probe := obs.AuthzCheckStarted(ctx)
		auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source:    auditctx.SourceDataSource,
			Operation: "cross_account_access",
			Outcome:   auditctx.OutcomeSuccess,
			Metadata:  map[string]string{"target_org_id": "org-1"},
		})

		_, memProbe := obs.InMemoryValidateStarted(ctx, "validator")
		memProbe.CacheMiss()
		_, distProbe := obs.DistributedValidateStarted(ctx, "validator")
		distProbe.CacheHit()
		_, dsProbe := obs.CacheFetchStarted(ctx, "backoffice")
		dsProbe.CacheHit()

		probe.SubjectCredentialExtracted(&trust.MTLSCredential{}, nil)
		probe.ActorCredentialExtracted(&trust.HeaderCredential{Headers: map[string]string{"x-psk": "test"}}, nil)
		probe.PolicyDecisionIssue(1, "", "")
		probe.End()
	}
}
