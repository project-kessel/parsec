package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	auditctx "github.com/project-kessel/parsec/internal/audit"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func mustNew(t *testing.T, logger zerolog.Logger, meta Metadata, options ...Option) *Observer {
	t.Helper()
	obs, err := New(logger, meta, options...)
	require.NoError(t, err)
	return obs
}

func TestAuthzAuditUsesDefaultParsecPrefixAndSafeContract(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
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
	require.Len(t, records, 2)
	require.Equal(t, "parsec_request", records[0]["event"])
	require.Equal(t, "1.0", records[0]["schema_version"])
	require.Equal(t, "request-123", records[0]["request_id"])
	require.Equal(t, "success", records[0]["outcome"])
	require.Equal(t, "info", records[0]["level"])
	require.Equal(t, "parsec_authorize", records[1]["event"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "authorization_request", resource["type"],
		"ext_authz must emit resource type 'authorization_request'")

	// Cross-account access is recorded as a signal inside the request record,
	// not as a separate event.
	signals, hasSignals := records[0]["signals"].([]any)
	require.True(t, hasSignals, "request record must include signals")
	require.Len(t, signals, 1)
	sig := signals[0].(map[string]any)
	require.Equal(t, "cross_account_access", sig["operation"])

	serialized := output.String()
	require.NotContains(t, serialized, "secret-token")
	require.NotContains(t, serialized, "secret-query")
	require.NotContains(t, serialized, "secret-cookie")
	require.NotContains(t, serialized, "secret@example.com")
}

func TestAuthzAuditEmitsNamedFailureEventsWithoutRawError(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "signal-1"))
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source: auditctx.SourceDataSource, Operation: "user_enrichment",
		Outcome: auditctx.OutcomeFailure, ReasonCode: auditctx.ReasonSupplementalFailure,
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

func TestCrossAccountDeniedSignalAppearsInRequestRecordOnly(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "cross-account-1"))
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source:     auditctx.SourceValidator,
		Operation:  "cross_account_access",
		Outcome:    auditctx.OutcomeDenied,
		ReasonCode: auditctx.ReasonPolicyDenied, Classification: "rbac_denied",
	})
	probe.PolicyDecisionDeny("policy denied")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	for _, record := range records {
		require.NotEqual(t, "parsec_rbac_cross_access_audit", record["event"],
			"cross_account_access must not produce a separate rbac_cross_access_audit event")
	}
	signals := records[0]["signals"].([]any)
	sig := signals[0].(map[string]any)
	require.Equal(t, "cross_account_access", sig["operation"])
	require.Equal(t, "policy_denied", sig["reason_code"])
	require.Equal(t, "rbac_denied", sig["classification"])
}

func TestValidReasonCodeAcceptsKnownReasonsOnly(t *testing.T) {
	require.False(t, ValidReasonCode("cross_account_denied"),
		"deployment-specific reasons belong in a signal classification")
	require.True(t, ValidReasonCode(auditctx.ReasonDependencyFailure))
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
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"}, WithEventPrefix(tt.prefix))
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})

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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
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
		{auditctx.ReasonComplianceDenied, "parsec_auth_compliance_failure"},
		{auditctx.ReasonComplianceFailure, "parsec_compliance_failure"},
		{auditctx.ReasonSupplementalFailure, "parsec_supplemental_user_data_failure"},
		{auditctx.ReasonDependencyFailure, "parsec_dependency_failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-nested"))
	_, cacheProbe := obs.InMemoryValidateStarted(ctx, "validator")
	cacheProbe.CacheHit()
	probe.PolicyDecisionIssue(1, "", "")
	// The data source fails inside the mapper, so the failure surfaces through
	// the issuance path, as it does in a real request.
	issueCtx, issuance := obs.TokenIssuanceStarted(ctx, nil, nil, "", []service.TokenType{service.TokenTypeTransactionToken})
	_, dataProbe := obs.LuaFetchStarted(issueCtx, "backoffice-proxy")
	dataProbe.ScriptExecutionFailed(errors.New("secret dependency response"))
	issuance.TokenTypeIssuanceFailed(service.TokenTypeTransactionToken, errors.New("mapper failed"))
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

	require.Equal(t, "backoffice-proxy", resource["failed_component"],
		"failed_component must identify the datasource that failed")

	names := map[string]bool{}
	for _, record := range records {
		names[record["event"].(string)] = true
	}
	require.Equal(t, auditctx.ReasonDependencyFailure, records[0]["reason_code"],
		"a data source failure during issuance must not be reported as token_issuance_failed")
	require.True(t, names["parsec_dependency_failure"])
	require.NotContains(t, output.String(), "secret dependency response")
}

func TestCacheLayersEmittedPerComponent(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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

	require.Equal(t, auditctx.ReasonDependencyFailure, records[0]["reason_code"],
		"GetFailed must classify as dependency_failure")
	require.Equal(t, "validator_distributed", resource["failed_component"],
		"GetFailed must identify the distributed validator as the failed component")
	require.NotContains(t, output.String(), "groupcache peer unreachable")
}

func TestFirstFailureReasonWins(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "first-wins"))

	_, jwtProbe := obs.JWTValidateStarted(ctx, "https://sso.example")
	jwtProbe.JWKSLookupFailed(errors.New("JWKS timeout"))

	_, dsProbe := obs.CacheFetchStarted(ctx, "enrichment")
	dsProbe.FetchFailed(errors.New("enrichment timeout"))

	probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, auditctx.ReasonDependencyFailure, records[0]["reason_code"],
		"first failure reason (dependency_failure from JWKS) must win")

	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "jwks", resource["failed_component"],
		"first failed component (jwks) must win over datasource cache")
}

func TestInvalidCacheStatusDropped(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
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
			name:        "no callbacks must not be reported as success",
			setup:       func(_ *requestProbe) {},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  auditctx.ReasonInternalError,
		},
		{
			name: "token issued → success",
			setup: func(p *requestProbe) {
				p.TokenIssued()
			},
			wantOutcome: AuditOutcomeSuccess,
			wantReason:  "",
		},
		{
			name: "token issuance denied produces denied outcome",
			setup: func(p *requestProbe) {
				p.tokenIssuanceDenied = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonTokenIssuanceDenied,
		},
		{
			name: "token issuance denied overrides policy issue",
			setup: func(p *requestProbe) {
				p.policyIssue = true
				p.tokenIssuanceDenied = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonTokenIssuanceDenied,
		},
		{
			name: "later issuance failure overrides earlier denial",
			setup: func(p *requestProbe) {
				p.tokenIssuanceDenied = true
				p.tokenIssuanceFailed = true
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  auditctx.ReasonTokenIssuanceFailed,
		},
		{
			name: "token issuance failed overrides policy issue",
			setup: func(p *requestProbe) {
				p.policyIssue = true
				p.tokenIssuanceFailed = true
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  auditctx.ReasonTokenIssuanceFailed,
		},
		{
			name: "token issuance failed without policy issue",
			setup: func(p *requestProbe) {
				p.tokenIssuanceFailed = true
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  auditctx.ReasonTokenIssuanceFailed,
		},
		{
			name: "unsupported grant type is a client error → denied",
			setup: func(p *requestProbe) {
				p.InvalidRequest(fmt.Errorf("%w: foo", service.ErrUnsupportedGrantType))
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonGrantTypeUnsupported,
		},
		{
			name: "audience mismatch is a client error → denied invalid_request",
			setup: func(p *requestProbe) {
				p.InvalidRequest(errors.New("requested audience does not match trust domain"))
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonInvalidRequest,
		},
		{
			name: "server-side request failure → failure internal_error",
			setup: func(p *requestProbe) {
				p.RequestFailed(errors.New("something unexpected"))
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  auditctx.ReasonInternalError,
		},
		{
			name: "actor extraction failed → denied credential_malformed",
			setup: func(p *requestProbe) {
				p.actorExtractionFailed = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonCredentialMalformed,
		},
		{
			name: "policy denied produces auditctx.ReasonPolicyDenied",
			setup: func(p *requestProbe) {
				p.policyDenied = true
				p.policyDenyReason = "denied by policy"
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonPolicyDenied,
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
			wantReason:  auditctx.ReasonCredentialMalformed,
		},
		{
			name: "unparseable request_context is a client error → denied invalid_request",
			setup: func(p *requestProbe) {
				p.requestContextParseFailed = true
			},
			wantOutcome: AuditOutcomeDenied,
			wantReason:  auditctx.ReasonInvalidRequest,
		},
		{
			name: "policy eval error → failure",
			setup: func(p *requestProbe) {
				p.policyEvalErr = errors.New("evaluation error")
			},
			wantOutcome: AuditOutcomeFailure,
			wantReason:  auditctx.ReasonInternalError,
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.TokenExchangeStarted(request.WithID(context.Background(), "request-safe"), "", "secret-requested-type", "", "")
	probe.ActorValidationFailed(errors.New("secret-arbitrary-error"))
	probe.End()

	require.NotContains(t, output.String(), "secret-arbitrary-error")
	require.NotContains(t, output.String(), "secret-requested-type")
	require.NotContains(t, output.String(), "secret-issued-token-type")
	require.Contains(t, output.String(), auditctx.ReasonCredentialInvalid)
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
	obs, err := New(zerolog.New(io.Discard), Metadata{ServiceName: "parsec", ServiceVersion: "v1"})
	if err != nil {
		b.Fatal(err)
	}
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

func TestDeriveCompletionDependencyOutage(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(ctx context.Context, p service.AuthzCheckProbe)
		wantResult string // "outcome/reason_code"
	}{
		{
			name: "credential_invalid_plus_JWKSLookupFailed_gives_failure_dependency_failure",
			setup: func(ctx context.Context, p service.AuthzCheckProbe) {
				state := request.AuditStateFrom(ctx)
				state.SetFailureReason(auditctx.ReasonDependencyFailure)
				state.SetDependencyOutage()
				p.SubjectValidationFailed(errors.New("token invalid"))
			},
			wantResult: "failure/dependency_failure",
		},
		{
			name: "credential_invalid_plus_distributed_GetFailed_gives_failure_dependency_failure",
			setup: func(ctx context.Context, p service.AuthzCheckProbe) {
				state := request.AuditStateFrom(ctx)
				state.SetFailureReason(auditctx.ReasonDependencyFailure)
				state.SetDependencyOutage()
				p.SubjectValidationFailed(errors.New("token invalid"))
			},
			wantResult: "failure/dependency_failure",
		},
		{
			name: "credential_invalid_plus_SourceFailed_only_stays_denied_credential_invalid",
			setup: func(_ context.Context, p service.AuthzCheckProbe) {
				p.SubjectValidationFailed(errors.New("bad signature"))
			},
			wantResult: "denied/credential_invalid",
		},
		{
			name: "credential_expired_plus_JWKS_failure_stays_denied_credential_expired",
			setup: func(ctx context.Context, p service.AuthzCheckProbe) {
				state := request.AuditStateFrom(ctx)
				state.SetFailureReason(auditctx.ReasonDependencyFailure)
				state.SetDependencyOutage()
				p.SubjectValidationFailed(trust.ErrExpiredToken)
			},
			wantResult: "denied/credential_expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
			ctx := request.WithID(context.Background(), "test")
			ctx, probe := obs.AuthzCheckStarted(ctx)
			tt.setup(ctx, probe)
			probe.End()

			records := decodeRecords(t, output.Bytes())
			require.NotEmpty(t, records)
			got := records[0]["outcome"].(string) + "/" + stringOrEmpty(records[0]["reason_code"])
			require.Equal(t, tt.wantResult, got)
		})
	}

	t.Run("typed_grant_type_error_via_token_exchange_gives_grant_type_unsupported", func(t *testing.T) {
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
		ctx := request.WithID(context.Background(), "test")
		_, probe := obs.TokenExchangeStarted(ctx, "bad-grant", "", "", "")
		probe.InvalidRequest(fmt.Errorf("%w: bad-grant", service.ErrUnsupportedGrantType))
		probe.End()

		records := decodeRecords(t, output.Bytes())
		require.NotEmpty(t, records)
		got := records[0]["outcome"].(string) + "/" + stringOrEmpty(records[0]["reason_code"])
		require.Equal(t, "denied/grant_type_unsupported", got)
	})
}

func stringOrEmpty(v any) string {
	if v == nil {
		return ""
	}
	return v.(string)
}

func TestEndOverlapRule(t *testing.T) {
	t.Run("final_reason_compliance_denied_plus_signal_same_reason_gives_signal_event_only", func(t *testing.T) {
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
		ctx := request.WithID(context.Background(), "overlap-1")
		ctx, probe := obs.AuthzCheckStarted(ctx)
		auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source:     auditctx.SourceDataSource,
			Operation:  "compliance_check",
			Outcome:    auditctx.OutcomeDenied,
			ReasonCode: auditctx.ReasonComplianceDenied,
		})
		probe.PolicyDecisionDeny("compliance_denied")
		probe.End()

		records := decodeRecords(t, output.Bytes())
		names := eventNames(records)
		complianceCount := 0
		for _, name := range names {
			if name == "parsec_auth_compliance_failure" {
				complianceCount++
			}
		}
		require.Equal(t, 1, complianceCount,
			"overlap rule: signal covers the reason, so only 1 auth_compliance_failure event")
	})

	t.Run("two_signals_same_reason_different_outcomes_gives_2_signal_events", func(t *testing.T) {
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
		ctx := request.WithID(context.Background(), "overlap-2")
		ctx, probe := obs.AuthzCheckStarted(ctx)
		auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source:     auditctx.SourceDataSource,
			Operation:  "compliance_check_a",
			Outcome:    auditctx.OutcomeDenied,
			ReasonCode: auditctx.ReasonComplianceDenied,
		})
		auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source:     auditctx.SourceDataSource,
			Operation:  "compliance_check_b",
			Outcome:    auditctx.OutcomeFailure,
			ReasonCode: auditctx.ReasonComplianceDenied,
		})
		probe.PolicyDecisionDeny("compliance_denied")
		probe.End()

		records := decodeRecords(t, output.Bytes())
		complianceCount := 0
		for _, r := range records {
			if r["event"] == "parsec_auth_compliance_failure" {
				complianceCount++
			}
		}
		require.Equal(t, 2, complianceCount,
			"two signals with the same reason but different outcomes give two events")
	})
}

func TestSignalsDroppedCounting(t *testing.T) {
	t.Run("33_signals_gives_signals_dropped_1", func(t *testing.T) {
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"},
			WithAllowedMetadataKeys(map[string]bool{"key": true}))
		ctx := request.WithID(context.Background(), "drop-1")
		ctx, probe := obs.AuthzCheckStarted(ctx)
		for i := 0; i < 33; i++ {
			auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
				Source:    auditctx.SourceDataSource,
				Operation: "enrichment",
				Outcome:   auditctx.OutcomeSuccess,
			})
		}
		probe.PolicyDecisionIssue(1, "", "")
		probe.End()

		records := decodeRecords(t, output.Bytes())
		resource := records[0]["resource"].(map[string]any)
		dropped, ok := resource["signals_dropped"]
		require.True(t, ok, "signals_dropped must be present when signals were dropped")
		require.Equal(t, float64(1), dropped)
	})

	t.Run("disallowed_metadata_key_is_stripped_and_counted", func(t *testing.T) {
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"},
			WithAllowedMetadataKeys(map[string]bool{"allowed": true}))
		ctx := request.WithID(context.Background(), "drop-2")
		ctx, probe := obs.AuthzCheckStarted(ctx)
		ok := auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source:    auditctx.SourceDataSource,
			Operation: "enrichment",
			Outcome:   auditctx.OutcomeSuccess,
			Metadata:  map[string]string{"disallowed_key": "value"},
		})
		require.True(t, ok, "a disallowed key is stripped; the signal is kept")
		probe.PolicyDecisionIssue(1, "", "")
		probe.End()

		records := decodeRecords(t, output.Bytes())
		resource := records[0]["resource"].(map[string]any)
		_, hasDropped := resource["signals_dropped"]
		require.False(t, hasDropped, "a stripped key must not increment signals_dropped")
		require.EqualValues(t, 1, resource["metadata_keys_stripped"])
		signals := records[0]["signals"].([]any)
		require.Len(t, signals, 1)
		require.NotContains(t, signals[0].(map[string]any), "metadata")
	})
}

// A failed source fetch behind a data source cache is a cache miss followed
// by a dependency failure, not a failure of the cache layer itself.
func TestDataSourceFetchFailureIsACacheMiss(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "fetch-failed"))

	_, dsProbe := obs.CacheFetchStarted(ctx, "enrichment")
	dsProbe.FetchFailed(errors.New("enrichment timeout"))
	probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, auditctx.ReasonDependencyFailure, records[0]["reason_code"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "datasource:enrichment", resource["failed_component"])
	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 1)
	require.Equal(t, "miss", layers[0].(map[string]any)["status"])
}
