package datasource

import "context"

// CacheObserver is called at key points during data source cache operations.
// Implementations should embed NoOpCacheObserver for forward compatibility
// with new methods added to this interface.
type CacheObserver interface {
	// CacheFetchStarted is called when a cache fetch begins.
	// Returns a potentially modified context and a probe to track the operation.
	CacheFetchStarted(ctx context.Context, dataSourceName string) (context.Context, CacheFetchProbe)
}

// CacheFetchProbe tracks a single cache fetch invocation.
// Implementations should embed NoOpCacheFetchProbe for forward compatibility.
type CacheFetchProbe interface {
	CacheHit()
	CacheMiss()
	CacheExpired()
	FetchFailed(err error)
	End()
}

// LuaObserver is called at key points during Lua data source operations.
// Implementations should embed NoOpLuaObserver for forward compatibility
// with new methods added to this interface.
type LuaObserver interface {
	// LuaFetchStarted is called when a Lua fetch begins.
	// Returns a potentially modified context and a probe to track the operation.
	LuaFetchStarted(ctx context.Context, dataSourceName string) (context.Context, LuaFetchProbe)
}

// LuaFetchProbe tracks a single Lua fetch invocation.
// Implementations should embed NoOpLuaFetchProbe for forward compatibility.
type LuaFetchProbe interface {
	ScriptLoadFailed(err error)
	ScriptExecutionFailed(err error)
	InvalidReturnType(got string)
	FetchCompleted()
	FetchCompletedNil()
	ResultConversionFailed(err error)
	// Outcome records a script-defined result string from returned JSON
	// (e.g. "allowed", "denied"). Call after a successful table return.
	Outcome(status string)
	End()
}

// DataSourceObserver is the per-package aggregate for all datasource observer interfaces.
type DataSourceObserver interface {
	CacheObserver
	LuaObserver
}

// --- NoOp implementations ---

// NoOpCacheFetchProbe is a no-op implementation of CacheFetchProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpCacheFetchProbe struct{}

func (NoOpCacheFetchProbe) CacheHit()         {}
func (NoOpCacheFetchProbe) CacheMiss()        {}
func (NoOpCacheFetchProbe) CacheExpired()     {}
func (NoOpCacheFetchProbe) FetchFailed(error) {}
func (NoOpCacheFetchProbe) End()              {}

// NoOpLuaFetchProbe is a no-op implementation of LuaFetchProbe.
// Embed this in concrete probe types for forward compatibility.
type NoOpLuaFetchProbe struct{}

func (NoOpLuaFetchProbe) ScriptLoadFailed(error)       {}
func (NoOpLuaFetchProbe) ScriptExecutionFailed(error)  {}
func (NoOpLuaFetchProbe) InvalidReturnType(string)     {}
func (NoOpLuaFetchProbe) FetchCompleted()              {}
func (NoOpLuaFetchProbe) FetchCompletedNil()           {}
func (NoOpLuaFetchProbe) ResultConversionFailed(error) {}
func (NoOpLuaFetchProbe) Outcome(string)               {}
func (NoOpLuaFetchProbe) End()                         {}

// NoOpCacheObserver is a no-op implementation of CacheObserver.
// Embed this in concrete observer types for forward compatibility.
type NoOpCacheObserver struct{}

func (NoOpCacheObserver) CacheFetchStarted(ctx context.Context, _ string) (context.Context, CacheFetchProbe) {
	return ctx, NoOpCacheFetchProbe{}
}

// NoOpLuaObserver is a no-op implementation of LuaObserver.
// Embed this in concrete observer types for forward compatibility.
type NoOpLuaObserver struct{}

func (NoOpLuaObserver) LuaFetchStarted(ctx context.Context, _ string) (context.Context, LuaFetchProbe) {
	return ctx, NoOpLuaFetchProbe{}
}

// NoOpDataSourceObserver satisfies both datasource observer interfaces with empty probes.
type NoOpDataSourceObserver struct {
	NoOpCacheObserver
	NoOpLuaObserver
}

var _ DataSourceObserver = NoOpDataSourceObserver{}
