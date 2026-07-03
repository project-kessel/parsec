package otel

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/service"
)

func benchProvider(b *testing.B) *Provider {
	b.Helper()
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(b, err)
	b.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

// BenchmarkProbeRecord_StatusOnly benchmarks a probe with only a status
// attribute (1 KeyValue in the set).
func BenchmarkProbeRecord_StatusOnly(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.MemoryRotateStarted(ctx)
		probe.End()
	}
}

// BenchmarkProbeRecord_WithResult benchmarks a probe with result + status
// attributes (2 KeyValues in the set).
func BenchmarkProbeRecord_WithResult(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.TokenIssuanceStarted(ctx, nil, nil, "test", []service.TokenType{"jwt"})
		probe.End()
	}
}

// BenchmarkProbeRecord_WithResult_Error benchmarks the error path of a
// result + status probe.
func BenchmarkProbeRecord_WithResult_Error(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.TokenIssuanceStarted(ctx, nil, nil, "test", []service.TokenType{"jwt"})
		probe.TokenTypeIssuanceFailed("jwt", errBench)
		probe.End()
	}
}

// BenchmarkProbeRecord_KnownAtStartAttrs benchmarks a probe with attributes
// known at creation (validator_type + validator + result + status = 4 KeyValues).
func BenchmarkProbeRecord_KnownAtStartAttrs(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.JWTValidateStarted(ctx, "https://issuer.example.com")
		probe.End()
	}
}

// BenchmarkProbeRecord_KnownAtStartAttrs_Error benchmarks the error path
// of a probe with creation-time attributes.
func BenchmarkProbeRecord_KnownAtStartAttrs_Error(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.JWTValidateStarted(ctx, "https://issuer.example.com")
		probe.TokenInvalid(errBench)
		probe.End()
	}
}

// BenchmarkProbeRecord_FieldSelectedAttrs benchmarks a probe where the result
// attribute is set by a lifecycle method (datasource + result + status).
func BenchmarkProbeRecord_FieldSelectedAttrs(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.CacheFetchStarted(ctx, "inventory")
		probe.CacheHit()
		probe.End()
	}
}

// BenchmarkProbeRecord_ServeFailedStatic benchmarks a fire-and-forget counter
// with a fully pre-built attribute set (no probe lifecycle).
func BenchmarkProbeRecord_ServeFailedStatic(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		obs.GRPCServeFailed(errBench)
	}
}

var errBench = context.DeadlineExceeded
