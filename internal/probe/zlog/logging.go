package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

var _ service.ServiceObserver = (*loggingObserver)(nil)

// loggingObserver creates request-scoped logging probes.
// Each event type has a pre-built sub-logger with its event name and
// per-event log level baked in at construction time.
type loggingObserver struct {
	service.NoOpServiceObserver
	tokenIssuanceLogger zerolog.Logger
	tokenExchangeLogger zerolog.Logger
	authzCheckLogger    zerolog.Logger
}

// LoggingObserverConfig configures the logging observer.
// Each field is a pre-configured zerolog.Logger for one event type,
// with the "event" field and per-event level already applied.
type LoggingObserverConfig struct {
	TokenIssuanceLogger zerolog.Logger
	TokenExchangeLogger zerolog.Logger
	AuthzCheckLogger    zerolog.Logger
}

// NewLoggingObserver creates an application observer that logs all observability events
// using structured logging with zerolog. All events inherit the base logger's level.
func NewLoggingObserver(logger zerolog.Logger) service.ServiceObserver {
	return NewLoggingObserverWithConfig(LoggingObserverConfig{
		TokenIssuanceLogger: logger.With().Str("event", "token_issuance").Logger(),
		TokenExchangeLogger: logger.With().Str("event", "token_exchange").Logger(),
		AuthzCheckLogger:    logger.With().Str("event", "authz_check").Logger(),
	})
}

// NewLoggingObserverWithConfig creates a logging observer with pre-configured per-event loggers.
func NewLoggingObserverWithConfig(cfg LoggingObserverConfig) service.ServiceObserver {
	return &loggingObserver{
		tokenIssuanceLogger: cfg.TokenIssuanceLogger,
		tokenExchangeLogger: cfg.TokenExchangeLogger,
		authzCheckLogger:    cfg.AuthzCheckLogger,
	}
}

func tokenIssuanceRequestLogger(
	base zerolog.Logger,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []service.TokenType,
) zerolog.Logger {
	loggerCtx := base.With().
		Str("scope", scope).
		Interface("token_types", tokenTypes)

	if subject != nil {
		loggerCtx = loggerCtx.
			Str("subject_id", subject.Subject).
			Str("subject_trust_domain", subject.TrustDomain)
	}

	if actor != nil {
		loggerCtx = loggerCtx.
			Str("actor_id", actor.Subject).
			Str("actor_trust_domain", actor.TrustDomain)
	}

	return loggerCtx.Logger()
}

func tokenExchangeRequestLogger(
	base zerolog.Logger,
	grantType string,
	requestedTokenType string,
	audience string,
	scope string,
) zerolog.Logger {
	return base.With().
		Str("grant_type", grantType).
		Str("requested_token_type", requestedTokenType).
		Str("audience", audience).
		Str("scope", scope).
		Logger()
}

func (o *loggingObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []service.TokenType,
) (context.Context, service.TokenIssuanceProbe) {
	requestLogger := tokenIssuanceRequestLogger(o.tokenIssuanceLogger, subject, actor, scope, tokenTypes)
	requestLogger.Debug().Msg("Starting token issuance")

	return ctx, &loggingTokenIssuanceProbe{
		logger:    requestLogger,
		startTime: time.Now(),
	}
}

// loggingTokenIssuanceProbe is a request-scoped probe that logs events for a single token issuance
type loggingTokenIssuanceProbe struct {
	service.NoOpTokenIssuanceProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingTokenIssuanceProbe) TokenTypeIssuanceStarted(tokenType service.TokenType) {
	p.logger.Debug().
		Str("token_type", string(tokenType)).
		Msg("Issuing token")
}

func (p *loggingTokenIssuanceProbe) TokenTypeIssuanceSucceeded(tokenType service.TokenType, token *service.Token) {
	event := p.logger.Debug().
		Str("token_type", string(tokenType))

	if token != nil {
		event = event.
			Time("issued_at", token.IssuedAt).
			Time("expires_at", token.ExpiresAt)
	}

	event.Msg("Token issued successfully")
}

func (p *loggingTokenIssuanceProbe) TokenTypeIssuanceFailed(tokenType service.TokenType, err error) {
	p.logger.Error().
		Str("token_type", string(tokenType)).
		Err(err).
		Msg("Token issuance failed")
}

func (p *loggingTokenIssuanceProbe) IssuerNotFound(tokenType service.TokenType, err error) {
	p.logger.Error().
		Str("token_type", string(tokenType)).
		Err(err).
		Msg("No issuer found for token type")
}

func (p *loggingTokenIssuanceProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("Token issuance completed")
}

// TokenExchangeStarted implements service.TokenExchangeObserver
func (o *loggingObserver) TokenExchangeStarted(
	ctx context.Context,
	grantType string,
	requestedTokenType string,
	audience string,
	scope string,
) (context.Context, service.TokenExchangeProbe) {
	requestLogger := tokenExchangeRequestLogger(o.tokenExchangeLogger, grantType, requestedTokenType, audience, scope)
	requestLogger.Debug().Msg("Starting token exchange")

	return ctx, &loggingTokenExchangeProbe{
		logger:    requestLogger,
		startTime: time.Now(),
	}
}

// loggingTokenExchangeProbe is a request-scoped probe that logs token exchange events
type loggingTokenExchangeProbe struct {
	service.NoOpTokenExchangeProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingTokenExchangeProbe) ActorCredentialExtracted(cred trust.Credential, headersUsed []string) {
	p.logger.Debug().
		Str("credential_type", string(cred.Type())).
		Strs("headers_used", headersUsed).
		Msg("Actor credential extracted")
}

func (p *loggingTokenExchangeProbe) ActorCredentialExtractionFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Actor credential extraction failed")
}

func (p *loggingTokenExchangeProbe) ActorValidationSucceeded(actor *trust.Result) {
	event := p.logger.Debug()
	if actor != nil {
		event = event.
			Str("actor_id", actor.Subject).
			Str("actor_trust_domain", actor.TrustDomain)
	}
	event.Msg("Actor validation succeeded")
}

func (p *loggingTokenExchangeProbe) ActorValidationFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Actor validation failed")
}

func (p *loggingTokenExchangeProbe) RequestContextParsed(attrs *request.RequestAttributes) {
	p.logger.Debug().Msg("Request context parsed")
}

func (p *loggingTokenExchangeProbe) RequestContextParseFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Request context parse failed")
}

func (p *loggingTokenExchangeProbe) SubjectTokenValidationSucceeded(subject *trust.Result) {
	event := p.logger.Debug()
	if subject != nil {
		event = event.
			Str("subject_id", subject.Subject).
			Str("subject_trust_domain", subject.TrustDomain)
	}
	event.Msg("Subject token validation succeeded")
}

func (p *loggingTokenExchangeProbe) SubjectTokenValidationFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Subject token validation failed")
}

func (p *loggingTokenExchangeProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("Token exchange completed")
}

// AuthzCheckStarted implements service.AuthzCheckObserver
func (o *loggingObserver) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, service.AuthzCheckProbe) {
	// AuthzCheckStarted receives no request-scoped parameters (unlike
	// token issuance/exchange), so we use the base event logger directly.
	requestLogger := o.authzCheckLogger
	requestLogger.Debug().Msg("Starting authorization check")

	return ctx, &loggingAuthzCheckProbe{
		logger:    requestLogger,
		startTime: time.Now(),
	}
}

// loggingAuthzCheckProbe is a request-scoped probe that logs authorization check events
type loggingAuthzCheckProbe struct {
	service.NoOpAuthzCheckProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingAuthzCheckProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	event := p.logger.Debug()
	if attrs != nil {
		event = event.
			Str("method", attrs.Method).
			Str("path", attrs.Path)
	}
	event.Msg("Request attributes parsed")
}

func (p *loggingAuthzCheckProbe) ActorCredentialExtracted(cred trust.Credential, headersUsed []string) {
	p.logger.Debug().
		Str("credential_type", string(cred.Type())).
		Strs("headers_used", headersUsed).
		Msg("Actor credential extracted")
}

func (p *loggingAuthzCheckProbe) ActorCredentialExtractionFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Actor credential extraction failed")
}

func (p *loggingAuthzCheckProbe) ActorValidationSucceeded(actor *trust.Result) {
	event := p.logger.Debug()
	if actor != nil {
		event = event.
			Str("actor_id", actor.Subject).
			Str("actor_trust_domain", actor.TrustDomain)
	}
	event.Msg("Actor validation succeeded")
}

func (p *loggingAuthzCheckProbe) ActorValidationFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Actor validation failed")
}

func (p *loggingAuthzCheckProbe) SubjectCredentialExtracted(cred trust.Credential, headersUsed []string) {
	p.logger.Debug().
		Str("credential_type", string(cred.Type())).
		Msg("Subject credential extracted")
}

func (p *loggingAuthzCheckProbe) SubjectCredentialExtractionFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Subject credential extraction failed")
}

func (p *loggingAuthzCheckProbe) SubjectValidationSucceeded(subject *trust.Result) {
	event := p.logger.Debug()
	if subject != nil {
		event = event.
			Str("subject_id", subject.Subject).
			Str("subject_trust_domain", subject.TrustDomain)
	}
	event.Msg("Subject validation succeeded")
}

func (p *loggingAuthzCheckProbe) SubjectValidationFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Subject validation failed")
}

func (p *loggingAuthzCheckProbe) SubjectAnonymous() {
	p.logger.Debug().
		Msg("No subject credential found, treating as anonymous")
}

func (p *loggingAuthzCheckProbe) PolicyDecisionIssue(tokenTypeCount int, scope string, reason string) {
	p.logger.Debug().
		Int("token_type_count", tokenTypeCount).
		Str("scope", scope).
		Str("reason", reason).
		Msg("Authz check policy: issue")
}

func (p *loggingAuthzCheckProbe) PolicyDecisionAllowWithoutIssue(reason string) {
	p.logger.Debug().
		Str("reason", reason).
		Msg("Authz check policy: allow without issue")
}

func (p *loggingAuthzCheckProbe) PolicyDecisionDeny(reason string) {
	p.logger.Warn().
		Str("reason", reason).
		Msg("Authz check policy: deny")
}

func (p *loggingAuthzCheckProbe) PolicyEvaluationFailed(err error) {
	p.logger.Error().
		Err(err).
		Msg("Authz check policy evaluation failed")
}

func (p *loggingAuthzCheckProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("Authorization check completed")
}
