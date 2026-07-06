package otel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/service"
)

type ctxKey struct{}

func testProvider(t *testing.T) *Provider {
	t.Helper()
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

func scrape(t *testing.T, p *Provider) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	p.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestNewObserver_SatisfiesObserverInterface(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)
	require.NotNil(t, obs)
}

func TestTokenIssuanceMetrics(t *testing.T) {
	tests := []struct {
		name       string
		action     func(probe service.TokenIssuanceProbe)
		wantResult string
		wantStatus string
	}{
		{
			name:       "success",
			action:     func(service.TokenIssuanceProbe) {},
			wantResult: `result="success"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "issuance failed",
			action:     func(p service.TokenIssuanceProbe) { p.TokenTypeIssuanceFailed("jwt", errors.New("sign error")) },
			wantResult: `result="issuance_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "issuer not found",
			action:     func(p service.TokenIssuanceProbe) { p.IssuerNotFound("jwt", errors.New("missing")) },
			wantResult: `result="issuer_not_found"`,
			wantStatus: `status="error"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.TokenIssuanceStarted(context.Background(), nil, nil, "test", []service.TokenType{"jwt"})
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_token_issuance_duration_seconds")
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestTokenExchangeMetrics(t *testing.T) {
	tests := []struct {
		name       string
		action     func(probe service.TokenExchangeProbe)
		wantResult string
		wantStatus string
	}{
		{
			name:       "success",
			action:     func(service.TokenExchangeProbe) {},
			wantResult: `result="success"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "actor validation failed",
			action:     func(p service.TokenExchangeProbe) { p.ActorValidationFailed(errors.New("bad actor")) },
			wantResult: `result="actor_validation_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "request context parse failed",
			action:     func(p service.TokenExchangeProbe) { p.RequestContextParseFailed(errors.New("bad json")) },
			wantResult: `result="request_context_parse_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "subject token validation failed",
			action:     func(p service.TokenExchangeProbe) { p.SubjectTokenValidationFailed(errors.New("expired")) },
			wantResult: `result="subject_token_validation_failed"`,
			wantStatus: `status="error"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.TokenExchangeStarted(context.Background(),
				"urn:ietf:params:oauth:grant-type:token-exchange", "jwt", "aud", "scope")
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_token_exchange_duration_seconds")
			assert.Contains(t, body, `grant_type="urn:ietf:params:oauth:grant-type:token-exchange"`)
			assert.Contains(t, body, `requested_token_type="jwt"`)
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestAuthzCheckMetrics(t *testing.T) {
	tests := []struct {
		name       string
		action     func(probe service.AuthzCheckProbe)
		wantResult string
		wantStatus string
	}{
		{
			name:       "policy decision issue",
			action:     func(p service.AuthzCheckProbe) { p.PolicyDecisionIssue(2, "openid", "allowed by rule") },
			wantResult: `result="policy_issue"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "policy decision allow without issue",
			action:     func(p service.AuthzCheckProbe) { p.PolicyDecisionAllowWithoutIssue("passthrough") },
			wantResult: `result="policy_allow_without_issue"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "policy decision deny",
			action:     func(p service.AuthzCheckProbe) { p.PolicyDecisionDeny("unauthorized") },
			wantResult: `result="policy_denied"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "policy evaluation failed",
			action:     func(p service.AuthzCheckProbe) { p.PolicyEvaluationFailed(errors.New("rego panic")) },
			wantResult: `result="policy_evaluation_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "actor validation failed",
			action:     func(p service.AuthzCheckProbe) { p.ActorValidationFailed(errors.New("bad actor")) },
			wantResult: `result="actor_validation_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "subject credential extraction failed",
			action:     func(p service.AuthzCheckProbe) { p.SubjectCredentialExtractionFailed(errors.New("no cred")) },
			wantResult: `result="subject_credential_extraction_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "subject validation failed",
			action:     func(p service.AuthzCheckProbe) { p.SubjectValidationFailed(errors.New("invalid")) },
			wantResult: `result="subject_validation_failed"`,
			wantStatus: `status="error"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.AuthzCheckStarted(context.Background())
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_authz_check_duration_seconds")
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestCacheFetchMetrics(t *testing.T) {
	tests := []struct {
		name           string
		dataSourceName string
		action         func(probe datasource.CacheFetchProbe)
		wantResult     string
		wantStatus     string
	}{
		{
			name:           "hit",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.CacheHit() },
			wantResult:     `result="hit"`,
			wantStatus:     `status="success"`,
		},
		{
			name:           "miss",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.CacheMiss() },
			wantResult:     `result="miss"`,
			wantStatus:     `status="success"`,
		},
		{
			name:           "expired",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.CacheExpired() },
			wantResult:     `result="expired"`,
			wantStatus:     `status="success"`,
		},
		{
			name:           "error",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.FetchFailed(errors.New("timeout")) },
			wantResult:     `result="error"`,
			wantStatus:     `status="error"`,
		},
		{
			name:           "unknown when no outcome is signaled",
			dataSourceName: "inventory",
			action:         func(datasource.CacheFetchProbe) {},
			wantResult:     `result="unknown"`,
			wantStatus:     `status="success"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.CacheFetchStarted(context.Background(), tt.dataSourceName)
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_datasource_cache_fetch_duration_seconds")
			assert.Contains(t, body, fmt.Sprintf(`datasource="%s"`, tt.dataSourceName))
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestLuaFetchMetrics(t *testing.T) {
	tests := []struct {
		name       string
		action     func(probe datasource.LuaFetchProbe)
		wantResult string
		wantStatus string
	}{
		{
			name:       "completed",
			action:     func(p datasource.LuaFetchProbe) { p.FetchCompleted() },
			wantResult: `result="completed"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "completed nil",
			action:     func(p datasource.LuaFetchProbe) { p.FetchCompletedNil() },
			wantResult: `result="completed_nil"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "script load failed",
			action:     func(p datasource.LuaFetchProbe) { p.ScriptLoadFailed(errors.New("not found")) },
			wantResult: `result="script_load_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "execution failed",
			action:     func(p datasource.LuaFetchProbe) { p.ScriptExecutionFailed(errors.New("lua panic")) },
			wantResult: `result="execution_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "invalid return type",
			action:     func(p datasource.LuaFetchProbe) { p.InvalidReturnType("number") },
			wantResult: `result="invalid_return_type"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "conversion failed",
			action:     func(p datasource.LuaFetchProbe) { p.ResultConversionFailed(errors.New("bad type")) },
			wantResult: `result="conversion_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "unknown when no outcome is signaled",
			action:     func(datasource.LuaFetchProbe) {},
			wantResult: `result="unknown"`,
			wantStatus: `status="success"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.LuaFetchStarted(context.Background(), "enrichment")
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_datasource_lua_fetch_duration_seconds")
			assert.Contains(t, body, `datasource="enrichment"`)
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestTrustValidationMetrics(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.ValidationStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_validation_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestKeyRotationMetrics(t *testing.T) {
	tests := []struct {
		name       string
		action     func(probe keys.RotationCheckProbe)
		wantResult string
		wantStatus string
	}{
		{
			name:       "completed",
			action:     func(p keys.RotationCheckProbe) { p.RotationCompleted("active") },
			wantResult: `result="completed"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "skipped version race",
			action:     func(p keys.RotationCheckProbe) { p.RotationSkippedVersionRace("active") },
			wantResult: `result="skipped_version_race"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "failed",
			action:     func(p keys.RotationCheckProbe) { p.RotationCheckFailed(errors.New("timeout")) },
			wantResult: `result="failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "not needed",
			action:     func(keys.RotationCheckProbe) {},
			wantResult: `result="not_needed"`,
			wantStatus: `status="success"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.RotationCheckStarted(context.Background())
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_keys_rotation_duration_seconds")
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestKeyCacheUpdateMetrics(t *testing.T) {
	tests := []struct {
		name       string
		action     func(probe keys.KeyCacheUpdateProbe)
		wantResult string
		wantStatus string
	}{
		{
			name:       "success",
			action:     func(keys.KeyCacheUpdateProbe) {},
			wantResult: `result="success"`,
			wantStatus: `status="success"`,
		},
		{
			name:       "general failure",
			action:     func(p keys.KeyCacheUpdateProbe) { p.KeyCacheUpdateFailed(errors.New("stale")) },
			wantResult: `result="general_failure"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "provider not found",
			action:     func(p keys.KeyCacheUpdateProbe) { p.KeyProviderNotFound("kms", "active") },
			wantResult: `result="provider_not_found"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "key handle failed",
			action:     func(p keys.KeyCacheUpdateProbe) { p.KeyHandleFailed("active", errors.New("err")) },
			wantResult: `result="key_handle_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "public key failed",
			action:     func(p keys.KeyCacheUpdateProbe) { p.PublicKeyFailed("active", errors.New("err")) },
			wantResult: `result="public_key_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "thumbprint failed",
			action:     func(p keys.KeyCacheUpdateProbe) { p.ThumbprintFailed("active", errors.New("err")) },
			wantResult: `result="thumbprint_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name:       "metadata failed",
			action:     func(p keys.KeyCacheUpdateProbe) { p.MetadataFailed("active", errors.New("err")) },
			wantResult: `result="metadata_failed"`,
			wantStatus: `status="error"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.KeyCacheUpdateStarted(context.Background())
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_keys_cache_update_duration_seconds")
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestJWTValidateMetrics(t *testing.T) {
	tests := []struct {
		name   string
		action func(probe interface {
			End()
			JWKSLookupFailed(error)
			TokenExpired()
			TokenInvalid(error)
			ClaimsExtractionFailed(error)
		})
		wantResult string
		wantStatus string
	}{
		{
			name: "success",
			action: func(p interface {
				End()
				JWKSLookupFailed(error)
				TokenExpired()
				TokenInvalid(error)
				ClaimsExtractionFailed(error)
			}) {
			},
			wantResult: `result="success"`,
			wantStatus: `status="success"`,
		},
		{
			name: "jwks lookup failed",
			action: func(p interface {
				End()
				JWKSLookupFailed(error)
				TokenExpired()
				TokenInvalid(error)
				ClaimsExtractionFailed(error)
			}) {
				p.JWKSLookupFailed(errors.New("timeout"))
			},
			wantResult: `result="jwks_lookup_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name: "token expired",
			action: func(p interface {
				End()
				JWKSLookupFailed(error)
				TokenExpired()
				TokenInvalid(error)
				ClaimsExtractionFailed(error)
			}) {
				p.TokenExpired()
			},
			wantResult: `result="token_expired"`,
			wantStatus: `status="error"`,
		},
		{
			name: "token invalid",
			action: func(p interface {
				End()
				JWKSLookupFailed(error)
				TokenExpired()
				TokenInvalid(error)
				ClaimsExtractionFailed(error)
			}) {
				p.TokenInvalid(errors.New("bad sig"))
			},
			wantResult: `result="token_invalid"`,
			wantStatus: `status="error"`,
		},
		{
			name: "claims extraction failed",
			action: func(p interface {
				End()
				JWKSLookupFailed(error)
				TokenExpired()
				TokenInvalid(error)
				ClaimsExtractionFailed(error)
			}) {
				p.ClaimsExtractionFailed(errors.New("missing iss"))
			},
			wantResult: `result="claims_extraction_failed"`,
			wantStatus: `status="error"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.JWTValidateStarted(context.Background(), "test-issuer")
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_trust_validate_duration_seconds")
			assert.Contains(t, body, `validator_type="jwt"`)
			assert.Contains(t, body, `validator="test-issuer"`)
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestLuaValidateMetrics(t *testing.T) {
	tests := []struct {
		name   string
		action func(probe interface {
			End()
			ScriptLoadFailed(error)
			ScriptExecutionFailed(error)
			InvalidReturnType(string)
			TokenInvalid(error)
			ValidationRejected()
			ResultConversionFailed(error)
		})
		wantResult string
		wantStatus string
	}{
		{
			name: "success",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
			},
			wantResult: `result="success"`,
			wantStatus: `status="success"`,
		},
		{
			name: "script load failed",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
				p.ScriptLoadFailed(errors.New("not found"))
			},
			wantResult: `result="script_load_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name: "execution failed",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
				p.ScriptExecutionFailed(errors.New("lua panic"))
			},
			wantResult: `result="execution_failed"`,
			wantStatus: `status="error"`,
		},
		{
			name: "invalid return type",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
				p.InvalidReturnType("number")
			},
			wantResult: `result="invalid_return_type"`,
			wantStatus: `status="error"`,
		},
		{
			name: "token invalid",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
				p.TokenInvalid(errors.New("bad token"))
			},
			wantResult: `result="token_invalid"`,
			wantStatus: `status="error"`,
		},
		{
			name: "rejected",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
				p.ValidationRejected()
			},
			wantResult: `result="rejected"`,
			wantStatus: `status="error"`,
		},
		{
			name: "conversion failed",
			action: func(p interface {
				End()
				ScriptLoadFailed(error)
				ScriptExecutionFailed(error)
				InvalidReturnType(string)
				TokenInvalid(error)
				ValidationRejected()
				ResultConversionFailed(error)
			}) {
				p.ResultConversionFailed(errors.New("bad type"))
			},
			wantResult: `result="conversion_failed"`,
			wantStatus: `status="error"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.LuaValidateStarted(context.Background(), "my-lua-validator")
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_trust_validate_duration_seconds")
			assert.Contains(t, body, `validator_type="lua"`)
			assert.Contains(t, body, `validator="my-lua-validator"`)
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestForActorFilterMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.ForActorStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_actor_filter_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestForActorFilterMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.ForActorStarted(context.Background())
	probe.FilterEvaluationFailed("validator-1", errors.New("eval error"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_actor_filter_duration_seconds")
	assert.Contains(t, body, `status="error"`)
}

func TestKMSRotateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.KMSRotateStarted(context.Background(), "td", "ns", "my-key")
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_kms_rotate_duration_seconds")
	assert.Contains(t, body, `key_name="my-key"`)
	assert.Contains(t, body, `status="success"`)
}

func TestKMSRotateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.KMSRotateStarted(context.Background(), "td", "ns", "my-key")
	probe.CreateKeyFailed(errors.New("kms error"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, `key_name="my-key"`)
	assert.Contains(t, body, `status="error"`)
}

func TestDiskRotateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.DiskRotateStarted(context.Background(), "td", "ns", "disk-key")
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_disk_rotate_duration_seconds")
	assert.Contains(t, body, `key_name="disk-key"`)
	assert.Contains(t, body, `status="success"`)
}

func TestDiskRotateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.DiskRotateStarted(context.Background(), "td", "ns", "disk-key")
	probe.KeyWriteFailed(errors.New("disk full"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, `key_name="disk-key"`)
	assert.Contains(t, body, `status="error"`)
}

func TestMemoryRotateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.MemoryRotateStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_memory_rotate_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestMemoryRotateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.MemoryRotateStarted(context.Background())
	probe.KeyGenerationFailed(errors.New("entropy"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_memory_rotate_duration_seconds")
	assert.Contains(t, body, `status="error"`)
}

func TestInitPopulationMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.InitPopulationStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_init_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestInitPopulationMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.InitPopulationStarted(context.Background())
	probe.InitialCachePopulationFailed(errors.New("fetch failed"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_init_duration_seconds")
	assert.Contains(t, body, `status="error"`)
}

func TestCacheRefreshMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.CacheRefreshStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_refresh_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestCacheRefreshMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.CacheRefreshStarted(context.Background())
	probe.CacheRefreshFailed(errors.New("timeout"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_refresh_duration_seconds")
	assert.Contains(t, body, `status="error"`)
}

func TestServeFailedMetrics_GRPC(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	obs.GRPCServeFailed(errors.New("bind error"))

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_serve_failed_total")
	assert.Contains(t, body, `transport="grpc"`)
}

func TestServeFailedMetrics_HTTP(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	obs.HTTPServeFailed(errors.New("bind error"))

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_serve_failed_total")
	assert.Contains(t, body, `transport="http"`)
}

func TestProbeContext_CarriesRequestContext(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), ctxKey{}, "request-123")

	_, ip := obs.TokenIssuanceStarted(ctx, nil, nil, "", nil)
	assert.Equal(t, "request-123", ip.(*tokenIssuanceProbe).ctx.Value(ctxKey{}))

	_, ep := obs.TokenExchangeStarted(ctx, "", "", "", "")
	assert.Equal(t, "request-123", ep.(*tokenExchangeProbe).ctx.Value(ctxKey{}))

	_, ap := obs.AuthzCheckStarted(ctx)
	assert.Equal(t, "request-123", ap.(*authzCheckProbe).ctx.Value(ctxKey{}))

	_, cp := obs.CacheFetchStarted(ctx, "ds")
	assert.Equal(t, "request-123", cp.(*cacheFetchProbe).ctx.Value(ctxKey{}))

	_, lp := obs.LuaFetchStarted(ctx, "ds")
	assert.Equal(t, "request-123", lp.(*luaFetchProbe).ctx.Value(ctxKey{}))

	_, vp := obs.ValidationStarted(ctx)
	assert.Equal(t, "request-123", vp.(*validationProbe).ctx.Value(ctxKey{}))

	_, rp := obs.RotationCheckStarted(ctx)
	assert.Equal(t, "request-123", rp.(*rotationCheckProbe).ctx.Value(ctxKey{}))

	_, kcp := obs.KeyCacheUpdateStarted(ctx)
	assert.Equal(t, "request-123", kcp.(*keyCacheUpdateProbe).ctx.Value(ctxKey{}))

	_, jp := obs.JWTValidateStarted(ctx, "iss")
	assert.Equal(t, "request-123", jp.(*jwtValidateProbe).ctx.Value(ctxKey{}))

	_, lvp := obs.LuaValidateStarted(ctx, "lua-v")
	assert.Equal(t, "request-123", lvp.(*luaValidateProbe).ctx.Value(ctxKey{}))

	_, fp := obs.ForActorStarted(ctx)
	assert.Equal(t, "request-123", fp.(*forActorProbe).ctx.Value(ctxKey{}))

	_, kmsp := obs.KMSRotateStarted(ctx, "td", "ns", "k")
	assert.Equal(t, "request-123", kmsp.(*kmsRotateProbe).ctx.Value(ctxKey{}))

	_, dkp := obs.DiskRotateStarted(ctx, "td", "ns", "k")
	assert.Equal(t, "request-123", dkp.(*diskRotateProbe).ctx.Value(ctxKey{}))

	_, mrp := obs.MemoryRotateStarted(ctx)
	assert.Equal(t, "request-123", mrp.(*memoryRotateProbe).ctx.Value(ctxKey{}))

	_, ipp := obs.InitPopulationStarted(ctx)
	assert.Equal(t, "request-123", ipp.(*initPopulationProbe).ctx.Value(ctxKey{}))

	_, crp := obs.CacheRefreshStarted(ctx)
	assert.Equal(t, "request-123", crp.(*cacheRefreshProbe).ctx.Value(ctxKey{}))
}
