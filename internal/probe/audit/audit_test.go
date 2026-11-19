package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
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
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx := request.WithID(context.Background(), "request-123")
	ctx, probe := obs.AuthzCheckStarted(ctx)

	// Simulate a Lua validator emitting a signal.
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source:    auditctx.SourceValidator,
		Operation: "lookup",
		Outcome:   auditctx.OutcomeSuccess,
		Metadata: map[string]string{
			"key_a": "target-org",
		},
	})

	probe.RequestAttributesParsed(&request.RequestAttributes{
		Method:    "GET",
		Path:      "/api/widgets?access_token=secret-query",
		IPAddress: "192.0.2.10",
		Headers: map[string]string{
			"authorization": "Bearer secret-token",
			"cookie":        "session_hint=target-org; session=secret-cookie",
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
	require.Len(t, records, 1, "one record per request")
	require.Equal(t, "parsec_request", records[0]["event"])
	require.Equal(t, "authorize", records[0]["action"])
	require.Equal(t, SchemaVersion, records[0]["schema_version"])
	require.Equal(t, "request-123", records[0]["request_id"])
	require.Equal(t, "success", records[0]["outcome"])
	require.Equal(t, "info", records[0]["level"])
	require.Equal(t, "192.0.2.10", records[0]["request"].(map[string]any)["source_ip"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "authorization_request", resource["type"],
		"ext_authz must emit resource type 'authorization_request'")

	signals, hasSignals := records[0]["signals"].([]any)
	require.True(t, hasSignals, "request record must include signals")
	require.Len(t, signals, 1)
	sig := signals[0].(map[string]any)
	require.Equal(t, "lookup", sig["operation"])

	serialized := output.String()
	require.NotContains(t, serialized, "secret-token")
	require.NotContains(t, serialized, "secret-query")
	require.NotContains(t, serialized, "secret-cookie")
	require.NotContains(t, serialized, "secret@example.com")
}

func TestAuthzAuditFailureRecordOmitsRawError(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-456"))
	probe.RequestAttributesParsed(&request.RequestAttributes{Method: "GET", Path: "/api/widgets"})
	probe.SubjectValidationFailed(errors.New("validator leaked secret-token"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	require.Equal(t, "parsec_request", records[0]["event"])
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
		Outcome: auditctx.OutcomeFailure, Classification: "http_error",
	})
	probe.PolicyEvaluationFailed(errors.New("data source failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1, "a signal never produces its own event")
	signals, ok := records[0]["signals"].([]any)
	require.True(t, ok)
	require.Len(t, signals, 1)
	signal := signals[0].(map[string]any)
	require.Equal(t, "user_enrichment", signal["operation"])
	require.Equal(t, "failure", signal["outcome"])
	require.Equal(t, "http_error", signal["classification"])
	require.NotContains(t, signal, "reason_code")
}

func TestSignalAppearsInRequestRecordOnly(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "signal-only-1"))
	auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
		Source:     auditctx.SourceValidator,
		Operation:  "lookup",
		Outcome:    auditctx.OutcomeDenied,
		ReasonCode: auditctx.ReasonPolicyDenied, Classification: "tenant_policy",
	})
	probe.PolicyDecisionDeny("policy denied")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	signals := records[0]["signals"].([]any)
	sig := signals[0].(map[string]any)
	require.Equal(t, "lookup", sig["operation"])
	require.Equal(t, "policy_denied", sig["reason_code"])
	require.Equal(t, "tenant_policy", sig["classification"])
}

func TestValidReasonCodeAcceptsKnownReasonsOnly(t *testing.T) {
	require.False(t, ValidReasonCode("deployment_denied"),
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
		{name: "default prefix", prefix: "parsec_", want: "parsec_request"},
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

	_, kms := obs.KMSRotateStarted(context.Background(), "secret-trust-domain", "secret-namespace", "rotated-key-name")
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
	for _, record := range records[1:] {
		require.Equal(t, "rotated-key-name", record["resource"].(map[string]any)["key_name"],
			"KMS events must say which key they are about")
	}
	require.NotContains(t, output.String(), "secret-trust-domain")
	require.NotContains(t, output.String(), "secret-namespace")
}

func TestAuditEmitsProcessReadyAndShutdown(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	obs.ProcessReady(server.ProcessInfo{TrustDomain: "prod.example"})
	_, stop := obs.StopStarted(context.Background())
	stop.ShutdownCompleted()
	stop.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, "parsec_process_status", records[0]["event"])
	require.Equal(t, "process_ready", records[0]["action"])
	require.NotContains(t, records[0]["service"].(map[string]any), "version")
	require.NotContains(t, records[0]["configuration"].(map[string]any), "commit")
	require.Equal(t, "parsec_process_status", records[1]["event"])
	require.Equal(t, "process_stop", records[1]["action"])
}

func TestAuditRecordsEachPrincipalsCredentialTypeAndValidation(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-auth"))
	probe.SubjectCredentialExtracted(&trust.MTLSCredential{Certificate: []byte("secret-certificate")}, nil)
	probe.ActorCredentialExtracted(&trust.HeaderCredential{Headers: map[string]string{"x-shared-key": "secret-shared-key"}}, nil)
	probe.SubjectValidationSucceeded(&trust.Result{})
	probe.ActorValidationSucceeded(&trust.Result{})
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	subject := records[0]["subject"].(map[string]any)
	actor := records[0]["actor"].(map[string]any)
	require.Equal(t, "mtls", subject["credential_type"])
	require.Equal(t, map[string]any{"outcome": "success"}, subject["validation"])
	require.Equal(t, "header", actor["credential_type"])
	require.Equal(t, map[string]any{"outcome": "success"}, actor["validation"])
	require.NotContains(t, output.String(), "secret-certificate")
	require.NotContains(t, output.String(), "secret-shared-key")
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
	_, dataProbe := obs.LuaFetchStarted(issueCtx, "upstream-proxy")
	dataProbe.ScriptExecutionFailed(errors.New("secret dependency response"))
	issuance.TokenTypeIssuanceFailed(service.TokenTypeTransactionToken, errors.New("mapper failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, "error", records[0]["level"])
	resource := records[0]["resource"].(map[string]any)
	layers, hasLayers := resource["cache_layers"].([]any)
	require.True(t, hasLayers, "cache_layers must be present when cache probes fire")
	require.Len(t, layers, 1)
	layer0 := layers[0].(map[string]any)
	require.Equal(t, "validator_memory", layer0["layer"])
	require.Equal(t, "hit", layer0["status"])

	require.Equal(t, "upstream-proxy", resource["failed_component"],
		"failed_component must identify the datasource that failed")

	require.Len(t, records, 1)
	require.Equal(t, auditctx.ReasonTokenIssuanceFailed, records[0]["reason_code"],
		"an earlier dependency failure may have been tolerated, so it must not replace the issuance failure")
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

	_, dsProbe := obs.CacheFetchStarted(ctx, "upstream")
	dsProbe.CacheHit()

	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	resource := records[0]["resource"].(map[string]any)

	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 3, "all three cache layers must be recorded")

	layer0 := layers[0].(map[string]any)
	require.Equal(t, "validator_memory", layer0["layer"])
	require.Equal(t, "miss", layer0["status"])

	layer1 := layers[1].(map[string]any)
	require.Equal(t, "validator_distributed", layer1["layer"])
	require.Equal(t, "expired", layer1["status"])

	layer2 := layers[2].(map[string]any)
	require.Equal(t, "datasource:upstream", layer2["layer"])
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

	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 1)
	layer0 := layers[0].(map[string]any)
	require.Equal(t, "validator_distributed", layer0["layer"])
	require.Equal(t, "failure", layer0["status"])

	require.Equal(t, auditctx.ReasonInternalError, records[0]["reason_code"],
		"a cache failure must not relabel an unrelated evaluation error")
	require.Equal(t, "validator_distributed", resource["failed_component"],
		"GetFailed must identify the distributed validator as the failed component")
	require.NotContains(t, output.String(), "groupcache peer unreachable")
}

func TestFirstFailedComponentRemainsDiagnostic(t *testing.T) {
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
	require.Equal(t, auditctx.ReasonInternalError, records[0]["reason_code"],
		"earlier component failures do not determine the terminal reason")

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
	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 1, "invalid status must not produce a cache layer entry")
	require.Equal(t, "hit", layers[0].(map[string]any)["status"])
}

func TestNoCacheProbeEmitsNoCacheLayers(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "no-cache"))
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	resource := records[0]["resource"].(map[string]any)
	require.NotContains(t, resource, "cache_status", "the scalar cache_status field was removed")
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
	obs, err := New(zerolog.New(io.Discard), Metadata{ServiceName: "parsec"}, WithAllowedMetadataKeys(nil))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		ctx := request.WithID(context.Background(), "bench-id")
		ctx, probe := obs.AuthzCheckStarted(ctx)
		auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source:    auditctx.SourceDataSource,
			Operation: "lookup",
			Outcome:   auditctx.OutcomeSuccess,
			Metadata:  map[string]string{"key_a": "org-1"},
		})

		_, memProbe := obs.InMemoryValidateStarted(ctx, "validator")
		memProbe.CacheMiss()
		_, distProbe := obs.DistributedValidateStarted(ctx, "validator")
		distProbe.CacheHit()
		_, dsProbe := obs.CacheFetchStarted(ctx, "upstream")
		dsProbe.CacheHit()

		probe.SubjectCredentialExtracted(&trust.MTLSCredential{}, nil)
		probe.ActorCredentialExtracted(&trust.HeaderCredential{Headers: map[string]string{"x-shared-key": "test"}}, nil)
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
				state.SetDependencyOutage()
				p.SubjectValidationFailed(errors.New("token invalid"))
			},
			wantResult: "failure/dependency_failure",
		},
		{
			name: "credential_invalid_plus_distributed_GetFailed_gives_failure_dependency_failure",
			setup: func(ctx context.Context, p service.AuthzCheckProbe) {
				state := request.AuditStateFrom(ctx)
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
			requestProbe, ok := probe.(*requestProbe)
			require.True(t, ok)
			outcome, reason := requestProbe.deriveCompletion()
			require.Equal(t, tt.wantResult, string(outcome)+"/"+reason,
				"deriveCompletion must determine the terminal outcome before serialization")
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

func TestDependencySignalsDoNotOverrideRequestReason(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "dependency-1"))
	for _, op := range []string{"lookup_a", "lookup_b"} {
		auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source: auditctx.SourceDataSource, Operation: op,
			Outcome: auditctx.OutcomeFailure, ReasonCode: auditctx.ReasonDependencyFailure,
		})
	}
	probe.PolicyEvaluationFailed(errors.New("lookup failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1, "no separate dependency_failure event")
	require.Equal(t, "parsec_request", records[0]["event"])
	require.Equal(t, "failure", records[0]["outcome"])
	require.Equal(t, auditctx.ReasonInternalError, records[0]["reason_code"])
	require.Len(t, records[0]["signals"].([]any), 2)
}

func TestRecoveredActorOutageDoesNotOverrideTerminalError(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		t.Run(fmt.Sprintf("exchange=%t", exchange), func(t *testing.T) {
			var output bytes.Buffer
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
			ctx, probe := obs.startRequest(context.Background(), "authorize", requestInfo{})
			probe.ActorCredentialExtracted(&trust.BearerCredential{}, nil)
			_, validation := obs.JWTValidateStarted(ctx, "actor-validator")
			validation.JWKSLookupFailed(errors.New("private dependency details"))
			validation.End()
			probe.ActorValidationSucceeded(&trust.Result{Subject: "actor"})
			if exchange {
				probe.RequestFailed(errors.New("unrelated filter error"))
			} else {
				probe.PolicyEvaluationFailed(errors.New("unrelated policy error"))
			}
			probe.End()

			records := decodeRecords(t, output.Bytes())
			require.Len(t, records, 1)
			record := records[0]
			require.Equal(t, "failure", record["outcome"])
			require.Equal(t, auditctx.ReasonInternalError, record["reason_code"])
			require.Equal(t, map[string]any{"outcome": "success"}, record["actor"].(map[string]any)["validation"])
			require.Equal(t, "jwks", record["resource"].(map[string]any)["failed_component"])
			require.NotContains(t, output.String(), "private dependency details")
		})
	}
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

// A failed source fetch behind a data source cache is a cache miss. The
// terminal reason is internal_error; the failed datasource is diagnostic context.
func TestDataSourceFetchFailureIsACacheMiss(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "fetch-failed"))

	// The caching data source reports the miss, then the failed fetch.
	_, dsProbe := obs.CacheFetchStarted(ctx, "enrichment")
	dsProbe.CacheMiss()
	dsProbe.FetchFailed(errors.New("enrichment timeout"))
	probe.PolicyEvaluationFailed(errors.New("evaluation failed"))
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Equal(t, auditctx.ReasonInternalError, records[0]["reason_code"])
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, "datasource:enrichment", resource["failed_component"])
	layers := resource["cache_layers"].([]any)
	require.Len(t, layers, 1, "a failed fetch must not add a second layer for the same lookup")
	require.Equal(t, "miss", layers[0].(map[string]any)["status"])
}

// A Lua validator that cannot reach a verdict is a failed dependency. One
// that rejects the credential is an ordinary denial.
func TestLuaValidatorFaultIsADependencyFailure(t *testing.T) {
	run := func(t *testing.T, report func(trust.LuaValidateProbe)) map[string]any {
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
		ctx, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "lua-validator"))
		_, luaProbe := obs.LuaValidateStarted(ctx, "registry-auth")
		report(luaProbe)
		probe.SubjectValidationFailed(errors.New("validation failed"))
		probe.End()
		return decodeRecords(t, output.Bytes())[0]
	}

	t.Run("script execution failed", func(t *testing.T) {
		record := run(t, func(p trust.LuaValidateProbe) { p.ScriptExecutionFailed(errors.New("backend timeout")) })
		require.Equal(t, "failure", record["outcome"])
		require.Equal(t, auditctx.ReasonDependencyFailure, record["reason_code"])
		require.Equal(t, "validator:registry-auth", record["resource"].(map[string]any)["failed_component"])
	})

	t.Run("script rejected the credential", func(t *testing.T) {
		record := run(t, func(p trust.LuaValidateProbe) { p.ValidationRejected() })
		require.Equal(t, "denied", record["outcome"])
		require.Equal(t, auditctx.ReasonCredentialInvalid, record["reason_code"])
		require.NotContains(t, record["resource"].(map[string]any), "failed_component")
	})
}

// The handlers report an absent actor as a validated anonymous result. No
// credential was checked, so the record must not claim a validation.
func TestAuditOmitsValidationWithoutACredential(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.AuthzCheckStarted(context.Background())
	probe.ActorValidationSucceeded(trust.AnonymousResult())
	probe.SubjectCredentialExtracted(&trust.BearerCredential{Token: "secret-subject"}, nil)
	probe.SubjectValidationSucceeded(&trust.Result{Subject: "user-1"})
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	require.NotContains(t, records[0]["actor"], "validation")
	require.Equal(t, map[string]any{"outcome": "success"}, records[0]["subject"].(map[string]any)["validation"])
}

func TestAuditValidationPreservesEachPrincipalsResult(t *testing.T) {
	success := map[string]any{"outcome": "success"}
	for _, tt := range []struct {
		mode           string
		subject, actor any
	}{
		{"policy denied", success, success},
		{"actor invalid", nil, map[string]any{"outcome": "denied", "reason_code": auditctx.ReasonCredentialInvalid}},
		{"subject expired", map[string]any{"outcome": "denied", "reason_code": auditctx.ReasonCredentialExpired}, success},
		{"not validated", nil, nil},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			var output bytes.Buffer
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
			_, probe := obs.AuthzCheckStarted(context.Background())
			probe.SubjectCredentialExtracted(&trust.BearerCredential{Token: "secret-subject"}, nil)
			probe.ActorCredentialExtracted(&trust.BearerCredential{Token: "secret-actor"}, nil)
			switch tt.mode {
			case "policy denied":
				probe.SubjectValidationSucceeded(&trust.Result{})
				probe.ActorValidationSucceeded(&trust.Result{})
				probe.PolicyDecisionDeny("denied")
			case "actor invalid":
				probe.ActorValidationFailed(errors.New("invalid"))
			case "subject expired":
				probe.ActorValidationSucceeded(&trust.Result{})
				probe.SubjectValidationFailed(trust.ErrExpiredToken)
			}
			probe.End()
			records := decodeRecords(t, output.Bytes())
			require.Len(t, records, 1)
			require.Equal(t, tt.subject, records[0]["subject"].(map[string]any)["validation"])
			require.Equal(t, tt.actor, records[0]["actor"].(map[string]any)["validation"])
			require.NotContains(t, output.String(), "secret-")
		})
	}
}

func TestAuditExchangeFailedSubjectRetainsCredentialType(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
	_, probe := obs.TokenExchangeStarted(context.Background(), "", "", "", "")
	probe.SubjectCredentialExtracted(&trust.JWTCredential{BearerCredential: trust.BearerCredential{Token: "secret-token"}}, nil)
	probe.SubjectTokenValidationFailed(trust.ErrExpiredToken)
	probe.End()
	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	subject := records[0]["subject"].(map[string]any)
	require.Equal(t, "jwt", subject["credential_type"])
	require.Equal(t, map[string]any{"outcome": "denied", "reason_code": auditctx.ReasonCredentialExpired}, subject["validation"])
	require.NotContains(t, output.String(), "secret-token")
}

func TestAuditPrincipalAttributesFromConfiguredClaims(t *testing.T) {
	result := &trust.Result{
		Subject: "user-1",
		Claims: map[string]any{
			"tenant_alias": "  ",
			"tenant":       map[string]any{"id": "tenant-nested"},
			"account":      "acct-1",
			"bad":          "line\nbreak",
			"number":       42,
			"secret":       "do-not-copy",
		},
	}
	emit := func(t *testing.T, options ...Option) map[string]any {
		t.Helper()
		var output bytes.Buffer
		obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"}, options...)
		_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "attrs"))
		probe.SubjectValidationSucceeded(result)
		probe.PolicyDecisionAllowWithoutIssue("allowed")
		probe.End()
		require.NotContains(t, output.String(), "do-not-copy")
		return decodeRecords(t, output.Bytes())[0]["subject"].(map[string]any)
	}

	t.Run("none by default", func(t *testing.T) {
		require.NotContains(t, emit(t), "attributes")
	})

	t.Run("first non-empty claim wins and dots reach nested claims", func(t *testing.T) {
		subject := emit(t, WithPrincipalClaims(map[string][]string{
			"tenant":  {"tenant_alias", "missing", "tenant.id"},
			"account": {"account"},
			"bad":     {"bad"},
			"number":  {"number"},
		}))
		require.Equal(t, map[string]any{"tenant": "tenant-nested", "account": "acct-1"}, subject["attributes"],
			"blank, control-character and non-string claims are skipped")
	})

	t.Run("a top-level claim whose name contains a dot is matched first", func(t *testing.T) {
		result.Claims["tenant.id"] = "tenant-flat"
		defer delete(result.Claims, "tenant.id")
		subject := emit(t, WithPrincipalClaims(map[string][]string{"tenant": {"tenant.id"}}))
		require.Equal(t, map[string]any{"tenant": "tenant-flat"}, subject["attributes"])
	})
}

func TestSignalsWithDifferentMetadataAreKeptApart(t *testing.T) {
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"},
		WithAllowedMetadataKeys(map[string]bool{"target_org_id": true}))
	ctx, probe := obs.AuthzCheckStarted(context.Background())
	for _, target := range []string{"org-a", "org-b"} {
		require.True(t, auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
			Source: auditctx.SourceDataSource, Operation: "lookup", Outcome: auditctx.OutcomeSuccess,
			Classification: "lookup_result", Metadata: map[string]string{"target_org_id": target},
		}))
	}
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()
	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	signals := records[0]["signals"].([]any)
	require.Len(t, signals, 2)
	for i, target := range []string{"org-a", "org-b"} {
		require.Equal(t, target, signals[i].(map[string]any)["metadata"].(map[string]any)["target_org_id"])
	}
}

// Actor validation can recover through another validator in FilteredStore.
// Its outage must not affect the subject, but a new subject outage still must.
func TestCredentialOutagesAreScopedToPrincipal(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		for _, source := range []string{"jwks", "distributed", "lua"} {
			for _, actorOutage := range []bool{false, true} {
				for _, subjectOutage := range []bool{false, true} {
					t.Run(fmt.Sprintf("exchange=%t/%s/actor=%t/subject=%t", exchange, source, actorOutage, subjectOutage), func(t *testing.T) {
						var output bytes.Buffer
						obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"})
						ctx, probe := obs.startRequest(context.Background(), "authorize", requestInfo{})
						failDependency := func() {
							switch source {
							case "jwks":
								_, p := obs.JWTValidateStarted(ctx, "validator")
								p.JWKSLookupFailed(errors.New("unavailable"))
								p.End()
							case "distributed":
								_, p := obs.DistributedValidateStarted(ctx, "validator")
								p.GetFailed(errors.New("unavailable"))
								p.End()
							case "lua":
								_, p := obs.LuaValidateStarted(ctx, "validator")
								p.ScriptExecutionFailed(errors.New("unavailable"))
								p.End()
							}
						}
						probe.ActorCredentialExtracted(&trust.BearerCredential{}, nil)
						if actorOutage {
							failDependency()
						}
						probe.ActorValidationSucceeded(&trust.Result{Subject: "actor"})
						probe.SubjectCredentialExtracted(&trust.BearerCredential{}, nil)
						if subjectOutage {
							failDependency()
						}
						if exchange {
							probe.SubjectTokenValidationFailed(errors.New("invalid subject"))
						} else {
							probe.SubjectValidationFailed(errors.New("invalid subject"))
						}
						probe.End()
						wantOutcome, wantReason := "denied", "credential_invalid"
						if subjectOutage {
							wantOutcome, wantReason = "failure", "dependency_failure"
						}
						records := decodeRecords(t, output.Bytes())
						require.Len(t, records, 1)
						require.Equal(t, wantOutcome, records[0]["outcome"])
						require.Equal(t, wantReason, records[0]["reason_code"])
						require.Equal(t, map[string]any{"outcome": wantOutcome, "reason_code": wantReason},
							records[0]["subject"].(map[string]any)["validation"])
						require.Equal(t, map[string]any{"outcome": "success"},
							records[0]["actor"].(map[string]any)["validation"])
					})
				}
			}
		}
	}
}

func TestAuditNamesOnlyConfiguredTokenTypes(t *testing.T) {
	custom := service.TokenType("urn:example:params:oauth:token-type:custom")
	var output bytes.Buffer
	obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"},
		WithTokenTypes([]service.TokenType{custom}))
	ctx, probe := obs.TokenExchangeStarted(context.Background(), "", "", "", "")
	_, issuance := obs.TokenIssuanceStarted(ctx, nil, nil, "",
		[]service.TokenType{custom, "secret-client-supplied-type"})
	issuance.TokenTypeIssuanceSucceeded(custom, &service.Token{})
	probe.TokenIssued()
	probe.End()

	records := decodeRecords(t, output.Bytes())
	require.Len(t, records, 1)
	resource := records[0]["resource"].(map[string]any)
	require.Equal(t, []any{string(custom), UnrecognizedTokenType}, resource["requested_token_types"],
		"a configured type is named without a core change; an unknown one is visible but not copied")
	require.Equal(t, []any{string(custom)}, resource["token_types"])
	require.NotContains(t, output.String(), "secret-client-supplied-type")
}

func TestAuditConstructorMetadataDefaults(t *testing.T) {
	for _, tt := range []struct {
		name     string
		options  []Option
		want     map[string]any
		stripped int
	}{
		{name: "default strips all", stripped: 2},
		{name: "explicit empty strips all", options: []Option{WithAllowedMetadataKeys(map[string]bool{})}, stripped: 2},
		{name: "allowlist retains approved key", options: []Option{WithAllowedMetadataKeys(map[string]bool{"approved": true})}, want: map[string]any{"approved": "value"}, stripped: 1},
		{name: "explicit nil allows all", options: []Option{WithAllowedMetadataKeys(nil)}, want: map[string]any{"approved": "value", "unapproved": "private-value"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"}, tt.options...)
			ctx, probe := obs.AuthzCheckStarted(context.Background())
			require.True(t, auditctx.ReporterFrom(ctx).Record(auditctx.Signal{
				Source: auditctx.SourceDataSource, Operation: "lookup", Outcome: auditctx.OutcomeSuccess,
				Metadata: map[string]string{"approved": "value", "unapproved": "private-value"},
			}))
			probe.PolicyDecisionAllowWithoutIssue("allowed")
			probe.End()
			records := decodeRecords(t, output.Bytes())
			require.Len(t, records, 1)
			signals := records[0]["signals"].([]any)
			require.Len(t, signals, 1)
			if tt.want == nil {
				require.NotContains(t, signals[0], "metadata")
			} else {
				require.Equal(t, tt.want, signals[0].(map[string]any)["metadata"])
			}
			resource := records[0]["resource"].(map[string]any)
			if tt.stripped == 0 {
				require.NotContains(t, resource, "metadata_keys_stripped")
			} else {
				require.EqualValues(t, tt.stripped, resource["metadata_keys_stripped"])
				require.NotContains(t, output.String(), "private-value")
			}
			require.NotContains(t, resource, "signals_rejected")
		})
	}
}

func TestAuditBoundsConfiguredTokenTypeNames(t *testing.T) {
	for _, tt := range []struct {
		name      string
		tokenType string
		want      string
	}{
		{"length limit", strings.Repeat("a", 256), strings.Repeat("a", 256)},
		{"too long", strings.Repeat("a", 257), UnrecognizedTokenType},
		{"empty", "", UnrecognizedTokenType},
		{"padded", " urn:example:custom ", UnrecognizedTokenType},
		{"control", "urn:example:\ncustom", UnrecognizedTokenType},
		{"invalid UTF-8", "urn:example:\xff", UnrecognizedTokenType},
		{"UTF-8 text", "urn:example:例", "urn:example:例"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			tokenType := service.TokenType(tt.tokenType)
			obs := mustNew(t, zerolog.New(&output), Metadata{ServiceName: "parsec"}, WithTokenTypes([]service.TokenType{tokenType}))
			ctx, probe := obs.TokenExchangeStarted(context.Background(), "", "", "", "")
			_, issuance := obs.TokenIssuanceStarted(ctx, nil, nil, "", []service.TokenType{tokenType})
			issuance.TokenTypeIssuanceSucceeded(tokenType, &service.Token{})
			issuance.End()
			probe.TokenIssued()
			probe.End()
			records := decodeRecords(t, output.Bytes())
			require.Len(t, records, 1)
			resource := records[0]["resource"].(map[string]any)
			require.Equal(t, []any{tt.want}, resource["requested_token_types"])
			require.Equal(t, []any{tt.want}, resource["token_types"])
		})
	}
}
