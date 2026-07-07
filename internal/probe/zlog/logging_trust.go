package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/trust"
)

var (
	_ trust.StoreObserver = (*LoggingTrustObserver)(nil)
	_ trust.TrustObserver = (*LoggingTrustObserver)(nil)
)

// LoggingTrustObserver logs trust validation, FilteredStore.ForActor, and
// individual validator steps via zerolog. It satisfies trust.TrustObserver by
// embedding trust.NoOpStoreObserver (store + filtered-store defaults) and
// trust.NoOpValidatorObserver (validator defaults), then overriding the six
// *Started factories that emit logs: ValidationStarted, ForActorStarted,
// JWTValidateStarted, LuaValidateStarted, InMemoryValidateStarted, and
// DistributedValidateStarted.
type LoggingTrustObserver struct {
	trust.NoOpStoreObserver
	trust.NoOpValidatorObserver
	logger zerolog.Logger
}

func NewLoggingTrustObserver(logger zerolog.Logger) *LoggingTrustObserver {
	return &LoggingTrustObserver{logger: logger}
}

func (o *LoggingTrustObserver) ValidationStarted(ctx context.Context) (context.Context, trust.ValidationProbe) {
	return ctx, &loggingValidationProbe{
		logger:    o.logger,
		startTime: time.Now(),
	}
}

func (o *LoggingTrustObserver) ForActorStarted(ctx context.Context) (context.Context, trust.ForActorProbe) {
	return ctx, &loggingForActorProbe{
		logger:    o.logger,
		startTime: time.Now(),
	}
}

func (o *LoggingTrustObserver) JWTValidateStarted(ctx context.Context, issuer string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &loggingJWTValidateProbe{
		logger:    o.logger.With().Str("issuer", issuer).Logger(),
		startTime: time.Now(),
	}
}

func (o *LoggingTrustObserver) LuaValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.LuaValidateProbe) {
	return ctx, &loggingLuaValidateProbe{
		logger:    o.logger.With().Str("validator", validatorName).Logger(),
		startTime: time.Now(),
	}
}

func (o *LoggingTrustObserver) InMemoryValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.InMemoryValidateProbe) {
	return ctx, &loggingInMemoryValidateProbe{
		logger:    o.logger.With().Str("validator", validatorName).Logger(),
		startTime: time.Now(),
	}
}

func (o *LoggingTrustObserver) DistributedValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.DistributedValidateProbe) {
	return ctx, &loggingDistributedValidateProbe{
		logger:    o.logger.With().Str("validator", validatorName).Logger(),
		startTime: time.Now(),
	}
}

// --- Store.Validate probe ---

type loggingValidationProbe struct {
	trust.NoOpValidationProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingValidationProbe) ValidatorFailed(validatorName string, credType trust.CredentialType, err error) {
	p.logger.Debug().
		Err(err).
		Str("validator", validatorName).
		Str("credential_type", string(credType)).
		Msg("validator rejected credential")
}

func (p *loggingValidationProbe) AllValidatorsFailed(credType trust.CredentialType, attempted int, lastErr error) {
	p.logger.Warn().
		Err(lastErr).
		Str("credential_type", string(credType)).
		Int("attempted", attempted).
		Msg("all validators failed for credential type")
}

func (p *loggingValidationProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("trust validation completed")
}

// --- FilteredStore.ForActor probe ---

type loggingForActorProbe struct {
	trust.NoOpForActorProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingForActorProbe) ValidatorFiltered(validatorName string, actorSubject string) {
	p.logger.Debug().
		Str("validator", validatorName).
		Str("actor", actorSubject).
		Msg("validator filtered out for actor")
}

func (p *loggingForActorProbe) FilterEvaluationFailed(validatorName string, err error) {
	p.logger.Error().
		Err(err).
		Str("validator", validatorName).
		Msg("filter evaluation failed")
}

func (p *loggingForActorProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("actor filter evaluation completed")
}

// --- JWTValidator.Validate probe ---

type loggingJWTValidateProbe struct {
	trust.NoOpJWTValidateProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingJWTValidateProbe) JWKSLookupFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("JWKS lookup failed")
}

func (p *loggingJWTValidateProbe) TokenExpired() {
	p.logger.Debug().
		Msg("token expired")
}

func (p *loggingJWTValidateProbe) TokenInvalid(err error) {
	p.logger.Debug().
		Err(err).
		Msg("token invalid")
}

func (p *loggingJWTValidateProbe) ClaimsExtractionFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("claims extraction failed")
}

func (p *loggingJWTValidateProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("JWT validation completed")
}

// --- LuaValidator.Validate probe ---

type loggingLuaValidateProbe struct {
	trust.NoOpLuaValidateProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingLuaValidateProbe) ScriptLoadFailed(err error) {
	p.logger.Error().Err(err).Msg("lua validator script load failed")
}

func (p *loggingLuaValidateProbe) ScriptExecutionFailed(err error) {
	p.logger.Error().Err(err).Msg("lua validator script execution failed")
}

func (p *loggingLuaValidateProbe) InvalidReturnType(got string) {
	p.logger.Error().Str("got", got).Msg("lua validator returned invalid type")
}

func (p *loggingLuaValidateProbe) TokenInvalid(err error) {
	p.logger.Debug().Err(err).Msg("lua validator rejected credential before script execution")
}

func (p *loggingLuaValidateProbe) ValidationRejected() {
	p.logger.Debug().Msg("lua validator rejected credential")
}

func (p *loggingLuaValidateProbe) ResultConversionFailed(err error) {
	p.logger.Error().Err(err).Msg("lua validator result conversion failed")
}

func (p *loggingLuaValidateProbe) ValidationCompleted() {
	p.logger.Debug().Msg("lua validation completed")
}

func (p *loggingLuaValidateProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("lua validation ended")
}

// --- InMemoryCachingValidator.Validate probe ---

type loggingInMemoryValidateProbe struct {
	trust.NoOpInMemoryValidateProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingInMemoryValidateProbe) CacheKeyFailed(err error) {
	p.logger.Warn().Err(err).Msg("cache key derivation failed, bypassing cache")
}

func (p *loggingInMemoryValidateProbe) CacheHit() {
	p.logger.Debug().Msg("in-memory cache hit")
}

func (p *loggingInMemoryValidateProbe) CacheExpired() {
	p.logger.Debug().Msg("in-memory cache entry expired")
}

func (p *loggingInMemoryValidateProbe) CacheMiss() {
	p.logger.Debug().Msg("in-memory cache miss")
}

func (p *loggingInMemoryValidateProbe) SourceFailed(err error) {
	p.logger.Warn().Err(err).Msg("source validation failed on cache miss")
}

func (p *loggingInMemoryValidateProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("in-memory caching validate completed")
}

// --- DistributedCachingValidator.Validate probe ---

type loggingDistributedValidateProbe struct {
	trust.NoOpDistributedValidateProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingDistributedValidateProbe) CacheKeyFailed(err error) {
	p.logger.Warn().Err(err).Msg("cache key derivation failed, bypassing cache")
}

func (p *loggingDistributedValidateProbe) GetFailed(err error) {
	p.logger.Warn().Err(err).Msg("distributed cache get failed")
}

func (p *loggingDistributedValidateProbe) ResultExpired() {
	p.logger.Debug().Msg("distributed cache result expired")
}

func (p *loggingDistributedValidateProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("distributed caching validate completed")
}
