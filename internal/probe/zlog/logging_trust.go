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
// JWTValidator.Validate via zerolog. It satisfies trust.TrustObserver by
// embedding trust.NoOpStoreObserver (store + filtered-store defaults) and
// trust.NoOpValidatorObserver (JWT defaults), then overriding only the three
// *Started factories that emit logs.
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

func (p *loggingJWTValidateProbe) AudienceMissingAccepted() {
	p.logger.Info().
		Msg("token accepted without audience claim")
}

func (p *loggingJWTValidateProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("JWT validation completed")
}
