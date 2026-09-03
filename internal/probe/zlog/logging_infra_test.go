package zlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/trust"
)

func testLogger(buf *bytes.Buffer) zerolog.Logger {
	return zerolog.New(buf).Level(zerolog.DebugLevel)
}

func testClock() clock.Clock {
	return clock.NewFixtureClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
}

// assertLog verifies the log output contains the expected level, message,
// and every additional field string (e.g. `"key":"value"`).
func assertLog(t *testing.T, out, level, msg string, fields ...string) {
	t.Helper()
	assert.Contains(t, out, fmt.Sprintf(`"level":"%s"`, level))
	assert.Contains(t, out, msg)
	for _, f := range fields {
		assert.Contains(t, out, f)
	}
}

// --- DataSourceCache ---

func TestLoggingDataSourceCacheObserver_DebugEvents(t *testing.T) {
	tests := []struct {
		name string
		call func(datasource.CacheFetchProbe)
		msg  string
	}{
		{"CacheHit", func(p datasource.CacheFetchProbe) { p.CacheHit() }, "cache hit"},
		{"CacheMiss", func(p datasource.CacheFetchProbe) { p.CacheMiss() }, "cache miss"},
		{"CacheExpired", func(p datasource.CacheFetchProbe) { p.CacheExpired() }, "cache entry expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			obs := NewLoggingDataSourceCacheObserver(testLogger(&buf), WithClock(testClock()))
			_, p := obs.CacheFetchStarted(context.Background(), "ds")
			tt.call(p)
			assertLog(t, buf.String(), "debug", tt.msg, `"datasource":"ds"`)
		})
	}
}

func TestLoggingDataSourceCacheObserver_FetchFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingDataSourceCacheObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.CacheFetchStarted(context.Background(), "my_ds")

	p.FetchFailed(errors.New("timeout"))

	assertLog(t, buf.String(), "warn", "data source fetch failed",
		`"datasource":"my_ds"`, `"error":"timeout"`)
}

// --- LuaDataSource ---

func TestLoggingLuaDataSourceObserver_ErrorEvents(t *testing.T) {
	tests := []struct {
		name  string
		call  func(datasource.LuaFetchProbe)
		level string
		msg   string
	}{
		{"ScriptLoadFailed", func(p datasource.LuaFetchProbe) { p.ScriptLoadFailed(errors.New("syntax error")) }, "error", "lua script load failed"},
		{"ScriptExecutionFailed", func(p datasource.LuaFetchProbe) { p.ScriptExecutionFailed(errors.New("nil ref")) }, "error", "lua script execution failed"},
		{"InvalidReturnType", func(p datasource.LuaFetchProbe) { p.InvalidReturnType("number") }, "error", "lua fetch returned invalid type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			obs := NewLoggingLuaDataSourceObserver(testLogger(&buf), WithClock(testClock()))
			_, p := obs.LuaFetchStarted(context.Background(), "my_lua_ds")
			tt.call(p)
			assertLog(t, buf.String(), tt.level, tt.msg, `"datasource":"my_lua_ds"`)
		})
	}
}

func TestLoggingLuaDataSourceObserver_FetchCompletedNil(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingLuaDataSourceObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.LuaFetchStarted(context.Background(), "my_lua_ds")
	p.FetchCompletedNil()
	assertLog(t, buf.String(), "debug", "lua fetch completed with nil result", `"datasource":"my_lua_ds"`)
}

func TestLoggingLuaDataSourceObserver_Outcome(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingLuaDataSourceObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.LuaFetchStarted(context.Background(), "my_lua_ds")
	p.Outcome("denied")
	assertLog(t, buf.String(), "info", "lua fetch outcome", `"datasource":"my_lua_ds"`, `"status":"denied"`)
}

// --- KeyRotation ---

func TestLoggingKeyRotationObserver_RotationCheckFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingKeyRotationObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.RotationCheckStarted(context.Background())

	p.RotationCheckFailed(errors.New("slot locked"))

	assertLog(t, buf.String(), "error", "key rotation check failed",
		`"error":"slot locked"`)
}

func TestLoggingKeyRotationObserver_InfoEvents(t *testing.T) {
	tests := []struct {
		name string
		call func(keys.RotationCheckProbe)
		msg  string
		slot string
	}{
		{"RotationCompleted", func(p keys.RotationCheckProbe) { p.RotationCompleted("primary") },
			"key rotation completed", "primary"},
		{"RotationSkippedVersionRace", func(p keys.RotationCheckProbe) { p.RotationSkippedVersionRace("secondary") },
			"another process completed rotation, skipping", "secondary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			obs := NewLoggingKeyRotationObserver(testLogger(&buf), WithClock(testClock()))
			_, p := obs.RotationCheckStarted(context.Background())
			tt.call(p)
			assertLog(t, buf.String(), "info", tt.msg,
				fmt.Sprintf(`"slot":"%s"`, tt.slot))
		})
	}
}

func TestLoggingKeyRotationObserver_KeyCacheUpdateFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingKeyRotationObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.KeyCacheUpdateStarted(context.Background())

	p.KeyCacheUpdateFailed(errors.New("no slots"))

	assertLog(t, buf.String(), "error", "active key cache update failed",
		`"error":"no slots"`)
}

func TestLoggingKeyRotationObserver_KeyProviderNotFound(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingKeyRotationObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.KeyCacheUpdateStarted(context.Background())

	p.KeyProviderNotFound("aws_kms", "primary")

	assertLog(t, buf.String(), "warn", "key provider not found, skipping",
		`"provider":"aws_kms"`, `"slot":"primary"`)
}

func TestLoggingKeyRotationObserver_WarningMethods(t *testing.T) {
	tests := []struct {
		name string
		call func(keys.KeyCacheUpdateProbe)
		msg  string
	}{
		{"KeyHandleFailed", func(p keys.KeyCacheUpdateProbe) { p.KeyHandleFailed("s1", errors.New("e")) }, "failed to get key handle"},
		{"PublicKeyFailed", func(p keys.KeyCacheUpdateProbe) { p.PublicKeyFailed("s1", errors.New("e")) }, "failed to get public key"},
		{"ThumbprintFailed", func(p keys.KeyCacheUpdateProbe) { p.ThumbprintFailed("s1", errors.New("e")) }, "failed to compute thumbprint"},
		{"MetadataFailed", func(p keys.KeyCacheUpdateProbe) { p.MetadataFailed("s1", errors.New("e")) }, "failed to get key metadata"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			obs := NewLoggingKeyRotationObserver(testLogger(&buf), WithClock(testClock()))
			_, p := obs.KeyCacheUpdateStarted(context.Background())
			tt.call(p)
			assertLog(t, buf.String(), "warn", tt.msg, `"slot":"s1"`)
		})
	}
}

// --- KMS Provider ---

func TestLoggingAWSKMSProviderObserver_CreateKeyFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingAWSKMSProviderObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.KMSRotateStarted(context.Background(), "td", "ns", "key")

	p.CreateKeyFailed(errors.New("access denied"))

	assertLog(t, buf.String(), "error", "KMS CreateKey failed",
		`"error":"access denied"`)
}

func TestLoggingAWSKMSProviderObserver_OldKeyDeletionFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingAWSKMSProviderObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.KMSRotateStarted(context.Background(), "td", "ns", "key")

	p.OldKeyDeletionFailed("key-123", errors.New("access denied"))

	assertLog(t, buf.String(), "warn", "failed to schedule old KMS key for deletion",
		`"key_id":"key-123"`, `"error":"access denied"`)
}

// --- Disk Provider ---

func TestLoggingDiskProviderObserver_KeyWriteFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingDiskProviderObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.DiskRotateStarted(context.Background(), "td", "ns", "test-key")

	p.KeyWriteFailed(errors.New("permission denied"))

	assertLog(t, buf.String(), "error", "disk key write failed",
		`"error":"permission denied"`)
}

// --- InMemory Provider ---

func TestLoggingInMemoryProviderObserver_KeyGenerationFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingInMemoryProviderObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.MemoryRotateStarted(context.Background())

	p.KeyGenerationFailed(errors.New("entropy exhausted"))

	assertLog(t, buf.String(), "error", "in-memory key generation failed",
		`"error":"entropy exhausted"`)
}

// --- TrustValidation ---

func TestLoggingTrustValidationObserver_ValidatorFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.ValidationStarted(context.Background())

	p.ValidatorFailed("oidc_v1", trust.CredentialTypeJWT, errors.New("expired"))

	assertLog(t, buf.String(), "debug", "validator rejected credential",
		`"validator":"oidc_v1"`, `"credential_type":"jwt"`)
}

func TestLoggingTrustValidationObserver_AllValidatorsFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.ValidationStarted(context.Background())

	p.AllValidatorsFailed(trust.CredentialTypeBearer, 3, errors.New("no match"))

	assertLog(t, buf.String(), "warn", "all validators failed for credential type",
		`"credential_type":"bearer"`, `"attempted":3`)
}

func TestLoggingTrustValidationObserver_ValidatorFiltered(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.ForActorStarted(context.Background())

	p.ValidatorFiltered("v1", "actor-xyz")

	assertLog(t, buf.String(), "debug", "validator filtered out for actor",
		`"validator":"v1"`, `"actor":"actor-xyz"`)
}

func TestLoggingTrustValidationObserver_FilterEvaluationFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.ForActorStarted(context.Background())

	p.FilterEvaluationFailed("v2", errors.New("cel error"))

	assertLog(t, buf.String(), "error", "filter evaluation failed",
		`"validator":"v2"`, `"error":"cel error"`)
}

// --- JWTValidator ---

func TestLoggingTrustObserver_JWKSLookupFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.JWTValidateStarted(context.Background(), "https://idp.example.com")

	p.JWKSLookupFailed(errors.New("connection refused"))

	assertLog(t, buf.String(), "error", "JWKS lookup failed",
		`"issuer":"https://idp.example.com"`, `"error":"connection refused"`)
}

func TestLoggingTrustObserver_TokenExpired(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.JWTValidateStarted(context.Background(), "https://idp.example.com")

	p.TokenExpired()

	assertLog(t, buf.String(), "debug", "token expired",
		`"issuer":"https://idp.example.com"`)
}

func TestLoggingTrustObserver_TokenInvalid(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingTrustObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.JWTValidateStarted(context.Background(), "https://idp.example.com")

	p.TokenInvalid(errors.New("bad signature"))

	assertLog(t, buf.String(), "debug", "token invalid",
		`"issuer":"https://idp.example.com"`, `"error":"bad signature"`)
}

// --- JWKS InitPopulation ---

func TestLoggingJWKSObserver_InitPopulationFailed(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingJWKSObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.InitPopulationStarted(context.Background())
	p.InitialCachePopulationFailed(errors.New("timeout"))
	assertLog(t, buf.String(), "error", "initial JWKS cache population failed",
		`"error":"timeout"`)
}

// --- JWKS CacheRefresh ---

func TestLoggingJWKSObserver(t *testing.T) {
	tests := []struct {
		name   string
		call   func(server.CacheRefreshProbe)
		msg    string
		fields []string
	}{
		{"CacheRefreshFailed",
			func(p server.CacheRefreshProbe) { p.CacheRefreshFailed(errors.New("network")) },
			"cache refresh failed",
			[]string{`"error":"network"`}},
		{"KeyConversionFailed",
			func(p server.CacheRefreshProbe) { p.KeyConversionFailed("kid-1", errors.New("unsupported alg")) },
			"skipping key: conversion failed",
			[]string{`"key_id":"kid-1"`, `"error":"unsupported alg"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			obs := NewLoggingJWKSObserver(testLogger(&buf), WithClock(testClock()))
			_, p := obs.CacheRefreshStarted(context.Background())
			tt.call(p)
			assertLog(t, buf.String(), "warn", tt.msg, tt.fields...)
		})
	}
}

// --- ServerLifecycle ---

func TestLoggingServerLifecycleObserver_ServeFailed(t *testing.T) {
	t.Run("GRPCServeFailed", func(t *testing.T) {
		var buf bytes.Buffer
		obs := NewLoggingServerLifecycleObserver(testLogger(&buf), WithClock(testClock()))
		obs.GRPCServeFailed(errors.New("bind error"))
		assertLog(t, buf.String(), "error", "gRPC server error")
	})
	t.Run("HTTPServeFailed", func(t *testing.T) {
		var buf bytes.Buffer
		obs := NewLoggingServerLifecycleObserver(testLogger(&buf), WithClock(testClock()))
		obs.HTTPServeFailed(errors.New("port in use"))
		assertLog(t, buf.String(), "error", "HTTP server error")
	})
}

func TestLoggingServerLifecycleObserver_StopStarted(t *testing.T) {
	var buf bytes.Buffer
	obs := NewLoggingServerLifecycleObserver(testLogger(&buf), WithClock(testClock()))
	_, p := obs.StopStarted(context.Background())
	p.End()
	assertLog(t, buf.String(), "debug", "server stopped")
}
