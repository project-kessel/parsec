package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
)

var _ datasource.LuaObserver = (*LoggingLuaDataSourceObserver)(nil)

type LoggingLuaDataSourceObserver struct {
	datasource.NoOpLuaObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingLuaDataSourceObserver(logger zerolog.Logger, opts ...Option) *LoggingLuaDataSourceObserver {
	cfg := resolveOptions(opts)
	return &LoggingLuaDataSourceObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingLuaDataSourceObserver) LuaFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.LuaFetchProbe) {
	return ctx, &loggingLuaFetchProbe{
		logger:    o.logger.With().Str("datasource", dataSourceName).Logger(),
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingLuaFetchProbe struct {
	datasource.NoOpLuaFetchProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingLuaFetchProbe) ScriptLoadFailed(err error) {
	p.logger.Error().Err(err).Msg("lua script load failed")
}

func (p *loggingLuaFetchProbe) ScriptExecutionFailed(err error) {
	p.logger.Error().Err(err).Msg("lua script execution failed")
}

func (p *loggingLuaFetchProbe) InvalidReturnType(got string) {
	p.logger.Error().Str("got", got).Msg("lua fetch returned invalid type (expected table or nil)")
}

func (p *loggingLuaFetchProbe) FetchCompleted() {
	p.logger.Debug().Msg("lua fetch completed")
}

func (p *loggingLuaFetchProbe) FetchCompletedNil() {
	p.logger.Debug().Msg("lua fetch completed with nil result")
}

func (p *loggingLuaFetchProbe) ResultConversionFailed(err error) {
	p.logger.Error().Err(err).Msg("lua result table conversion failed")
}

func (p *loggingLuaFetchProbe) Outcome(status string) {
	p.logger.Info().Str("status", status).Msg("lua fetch outcome")
}

func (p *loggingLuaFetchProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("lua fetch ended")
}
