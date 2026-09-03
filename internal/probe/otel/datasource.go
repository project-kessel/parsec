package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
)

var (
	cacheResultHit     = attribute.String("result", "hit")
	cacheResultMiss    = attribute.String("result", "miss")
	cacheResultExpired = attribute.String("result", "expired")
	cacheResultError   = attribute.String("result", "error")
	cacheResultUnknown = attribute.String("result", "unknown")

	luaResultCompleted        = attribute.String("result", "completed")
	luaResultCompletedNil     = attribute.String("result", "completed_nil")
	luaResultScriptLoadFailed = attribute.String("result", "script_load_failed")
	luaResultExecutionFailed  = attribute.String("result", "execution_failed")
	luaResultInvalidReturn    = attribute.String("result", "invalid_return_type")
	luaResultConversionFailed = attribute.String("result", "conversion_failed")
	luaResultUnknown          = attribute.String("result", "unknown")
)

type dataSourceObserver struct {
	datasource.NoOpDataSourceObserver

	cacheFetchDuration metric.Float64Histogram
	luaFetchDuration   metric.Float64Histogram
	clock              clock.Clock
}

func newDataSourceObserver(m metric.Meter, clk clock.Clock) (*dataSourceObserver, error) {
	cfd, err := m.Float64Histogram("parsec.datasource.cache.fetch.duration",
		metric.WithDescription("Data source cache fetch duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	lfd, err := m.Float64Histogram("parsec.datasource.lua.fetch.duration",
		metric.WithDescription("Lua data source fetch duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &dataSourceObserver{
		cacheFetchDuration: cfd,
		luaFetchDuration:   lfd,
		clock:              clk,
	}, nil
}

func (o *dataSourceObserver) CacheFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &cacheFetchProbe{
		obs: o, ctx: ctx, startTime: o.clock.Now(),
		status:     successStatusAttr,
		datasource: attribute.String("datasource", dataSourceName),
	}
}

func (o *dataSourceObserver) LuaFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.LuaFetchProbe) {
	return ctx, &luaFetchProbe{
		obs: o, ctx: ctx, startTime: o.clock.Now(),
		status:     successStatusAttr,
		datasource: attribute.String("datasource", dataSourceName),
	}
}

// --- cache fetch probe ---

type cacheFetchProbe struct {
	datasource.NoOpCacheFetchProbe
	obs        *dataSourceObserver
	ctx        context.Context
	startTime  time.Time
	status     attribute.KeyValue
	datasource attribute.KeyValue
	result     attribute.KeyValue
}

func (p *cacheFetchProbe) CacheHit()     { p.result = cacheResultHit }
func (p *cacheFetchProbe) CacheMiss()    { p.result = cacheResultMiss }
func (p *cacheFetchProbe) CacheExpired() { p.result = cacheResultExpired }
func (p *cacheFetchProbe) FetchFailed(_ error) {
	p.status = errorStatusAttr
	p.result = cacheResultError
}

func (p *cacheFetchProbe) End() {
	if p.result == (attribute.KeyValue{}) {
		p.result = cacheResultUnknown
	}
	attrs := metric.WithAttributeSet(attribute.NewSet(p.datasource, p.result, p.status))
	p.obs.cacheFetchDuration.Record(p.ctx, p.obs.clock.Since(p.startTime).Seconds(), attrs)
}

// --- lua fetch probe ---

type luaFetchProbe struct {
	datasource.NoOpLuaFetchProbe
	obs        *dataSourceObserver
	ctx        context.Context
	startTime  time.Time
	status     attribute.KeyValue
	datasource attribute.KeyValue
	result     attribute.KeyValue
}

func (p *luaFetchProbe) FetchCompleted()    { p.result = luaResultCompleted }
func (p *luaFetchProbe) FetchCompletedNil() { p.result = luaResultCompletedNil }
func (p *luaFetchProbe) Outcome(status string) {
	if status != "" {
		p.result = attribute.String("result", status)
	}
}
func (p *luaFetchProbe) ScriptLoadFailed(_ error) {
	p.status = errorStatusAttr
	p.result = luaResultScriptLoadFailed
}
func (p *luaFetchProbe) ScriptExecutionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = luaResultExecutionFailed
}
func (p *luaFetchProbe) InvalidReturnType(_ string) {
	p.status = errorStatusAttr
	p.result = luaResultInvalidReturn
}
func (p *luaFetchProbe) ResultConversionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = luaResultConversionFailed
}

func (p *luaFetchProbe) End() {
	if p.result == (attribute.KeyValue{}) {
		p.result = luaResultUnknown
	}
	attrs := metric.WithAttributeSet(attribute.NewSet(p.datasource, p.result, p.status))
	p.obs.luaFetchDuration.Record(p.ctx, p.obs.clock.Since(p.startTime).Seconds(), attrs)
}

var (
	_ datasource.DataSourceObserver = (*dataSourceObserver)(nil)
	_ datasource.CacheFetchProbe    = (*cacheFetchProbe)(nil)
	_ datasource.LuaFetchProbe      = (*luaFetchProbe)(nil)
)
