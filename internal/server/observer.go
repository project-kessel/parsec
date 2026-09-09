package server

import "context"

// JWKSObserver is called at key points during JWKS cache operations.
// Implementations should embed NoOpJWKSObserver for forward compatibility
// with new methods added to this interface.
type JWKSObserver interface {
	// InitPopulationStarted is called when the initial JWKS cache population begins in Start.
	InitPopulationStarted(ctx context.Context) (context.Context, InitPopulationProbe)
	// CacheRefreshStarted is called when a JWKS cache build or refresh begins.
	CacheRefreshStarted(ctx context.Context) (context.Context, CacheRefreshProbe)
}

// InitPopulationProbe tracks the initial JWKS cache population in Start.
// Implementations should embed NoOpInitPopulationProbe for forward compatibility.
type InitPopulationProbe interface {
	InitialCachePopulationFailed(err error)
	End()
}

// CacheRefreshProbe tracks a single JWKS cache refresh invocation.
// Implementations should embed NoOpCacheRefreshProbe for forward compatibility.
type CacheRefreshProbe interface {
	CacheRefreshFailed(err error)
	KeyConversionFailed(keyID string, err error)
	End()
}

// LifecycleObserver is called at key points during server lifecycle.
// Implementations should embed NoOpLifecycleObserver for forward compatibility
// with new methods added to this interface.
type LifecycleObserver interface {
	// ProcessReady records that the service completed initialization and is ready.
	ProcessReady(info ProcessInfo)
	// GRPCServeFailed is a fire-and-forget event from an async goroutine.
	GRPCServeFailed(err error)
	// HTTPServeFailed is a fire-and-forget event from an async goroutine.
	HTTPServeFailed(err error)
	// StopStarted is called when graceful shutdown begins.
	StopStarted(ctx context.Context) (context.Context, StopProbe)
}

// StopProbe tracks server graceful shutdown.
// Implementations should embed NoOpStopProbe for forward compatibility.
type StopProbe interface {
	ShutdownCompleted(interruptedRequests int64)
	ShutdownFailed(interruptedRequests int64)
	End()
}

// ProcessInfo contains only allowlisted, non-secret startup configuration.
type ProcessInfo struct {
	Version     string
	Commit      string
	TrustDomain string
	GRPCAddress string
	HTTPAddress string
}

// ServerObserver is the per-package aggregate for all server observer interfaces.
type ServerObserver interface {
	JWKSObserver
	LifecycleObserver
}

// --- NoOp implementations ---

// NoOpInitPopulationProbe is a no-op implementation of InitPopulationProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpInitPopulationProbe struct{}

func (NoOpInitPopulationProbe) InitialCachePopulationFailed(error) {}
func (NoOpInitPopulationProbe) End()                               {}

// NoOpCacheRefreshProbe is a no-op implementation of CacheRefreshProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpCacheRefreshProbe struct{}

func (NoOpCacheRefreshProbe) CacheRefreshFailed(error)          {}
func (NoOpCacheRefreshProbe) KeyConversionFailed(string, error) {}
func (NoOpCacheRefreshProbe) End()                              {}

// NoOpStopProbe is a no-op implementation of StopProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpStopProbe struct{}

func (NoOpStopProbe) ShutdownCompleted(int64) {}
func (NoOpStopProbe) ShutdownFailed(int64)    {}
func (NoOpStopProbe) End()                    {}

// NoOpJWKSObserver is a no-op implementation of JWKSObserver.
// Embed this in concrete observer types for forward compatibility.
type NoOpJWKSObserver struct{}

func (NoOpJWKSObserver) InitPopulationStarted(ctx context.Context) (context.Context, InitPopulationProbe) {
	return ctx, NoOpInitPopulationProbe{}
}

func (NoOpJWKSObserver) CacheRefreshStarted(ctx context.Context) (context.Context, CacheRefreshProbe) {
	return ctx, NoOpCacheRefreshProbe{}
}

// NoOpLifecycleObserver is a no-op implementation of LifecycleObserver.
// Embed this in concrete observer types for forward compatibility.
type NoOpLifecycleObserver struct{}

func (NoOpLifecycleObserver) ProcessReady(ProcessInfo) {}
func (NoOpLifecycleObserver) GRPCServeFailed(error)    {}
func (NoOpLifecycleObserver) HTTPServeFailed(error)    {}
func (NoOpLifecycleObserver) StopStarted(ctx context.Context) (context.Context, StopProbe) {
	return ctx, NoOpStopProbe{}
}

// NoOpServerObserver satisfies both JWKSObserver and LifecycleObserver
// with empty probes. Useful in tests that don't care about observer events.
type NoOpServerObserver struct {
	NoOpJWKSObserver
	NoOpLifecycleObserver
}

var _ ServerObserver = NoOpServerObserver{}
