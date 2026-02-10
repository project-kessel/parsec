package probe

import (
	"context"
	"log/slog"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// loggingObserver creates request-scoped logging probes
type loggingObserver struct {
	service.NoOpApplicationObserver
	logger *slog.Logger
}

// LoggingObserverConfig configures the logging observer
type LoggingObserverConfig struct {
	// Logger is the base logger to use. If nil, uses slog.Default()
	Logger *slog.Logger
}

// NewLoggingObserver creates an application observer that logs all observability events
// using structured logging with slog.
func NewLoggingObserver(logger *slog.Logger) service.ApplicationObserver {
	if logger == nil {
		logger = slog.Default()
	}
	return NewLoggingObserverWithConfig(LoggingObserverConfig{
		Logger: logger,
	})
}

// NewLoggingObserverWithConfig creates a logging observer with custom configuration
func NewLoggingObserverWithConfig(cfg LoggingObserverConfig) service.ApplicationObserver {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &loggingObserver{
		logger: logger,
	}
}

func (o *loggingObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []service.TokenType,
) (context.Context, service.TokenIssuanceProbe) {
	// Create scoped logger for this probe type
	probeLogger := o.logger.With("event", "token_issuance")

	attrs := []slog.Attr{
		slog.String("scope", scope),
		slog.Any("token_types", tokenTypes),
	}

	if subject != nil {
		attrs = append(attrs,
			slog.String("subject_id", subject.Subject),
			slog.String("subject_trust_domain", subject.TrustDomain),
		)
	}

	if actor != nil {
		attrs = append(attrs,
			slog.String("actor_id", actor.Subject),
			slog.String("actor_trust_domain", actor.TrustDomain),
		)
	}

	probeLogger.LogAttrs(ctx, slog.LevelDebug, "Starting token issuance", attrs...)

	// Return a request-scoped probe that captures the context
	return ctx, &loggingTokenIssuanceProbe{
		ctx:    ctx,
		logger: probeLogger,
	}
}

// loggingTokenIssuanceProbe is a request-scoped probe that logs events for a single token issuance
type loggingTokenIssuanceProbe struct {
	service.NoOpTokenIssuanceProbe
	ctx    context.Context
	logger *slog.Logger
}

func (p *loggingTokenIssuanceProbe) TokenTypeIssuanceStarted(tokenType service.TokenType) {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug,
		"Issuing token",
		slog.String("token_type", string(tokenType)),
	)
}

func (p *loggingTokenIssuanceProbe) TokenTypeIssuanceSucceeded(tokenType service.TokenType, token *service.Token) {
	attrs := []slog.Attr{
		slog.String("token_type", string(tokenType)),
	}

	if token != nil {
		attrs = append(attrs,
			slog.Time("issued_at", token.IssuedAt),
			slog.Time("expires_at", token.ExpiresAt),
		)
	}

	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Token issued successfully", attrs...)
}

func (p *loggingTokenIssuanceProbe) TokenTypeIssuanceFailed(tokenType service.TokenType, err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Token issuance failed",
		slog.String("token_type", string(tokenType)),
		slog.String("error", err.Error()),
	)
}

func (p *loggingTokenIssuanceProbe) IssuerNotFound(tokenType service.TokenType, err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"No issuer found for token type",
		slog.String("token_type", string(tokenType)),
		slog.String("error", err.Error()),
	)
}

func (p *loggingTokenIssuanceProbe) End() {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Token issuance completed")
}

// TokenExchangeStarted implements service.TokenExchangeObserver
func (o *loggingObserver) TokenExchangeStarted(
	ctx context.Context,
	grantType string,
	requestedTokenType string,
	audience string,
	scope string,
) (context.Context, service.TokenExchangeProbe) {
	// Create scoped logger for this probe type
	probeLogger := o.logger.With("event", "token_exchange")

	probeLogger.LogAttrs(ctx, slog.LevelDebug,
		"Starting token exchange",
		slog.String("grant_type", grantType),
		slog.String("requested_token_type", requestedTokenType),
		slog.String("audience", audience),
		slog.String("scope", scope),
	)

	return ctx, &loggingTokenExchangeProbe{
		ctx:    ctx,
		logger: probeLogger,
	}
}

// loggingTokenExchangeProbe is a request-scoped probe that logs token exchange events
type loggingTokenExchangeProbe struct {
	service.NoOpTokenExchangeProbe
	ctx    context.Context
	logger *slog.Logger
}

func (p *loggingTokenExchangeProbe) ActorValidationSucceeded(actor *trust.Result) {
	attrs := []slog.Attr{}
	if actor != nil {
		attrs = append(attrs,
			slog.String("actor_id", actor.Subject),
			slog.String("actor_trust_domain", actor.TrustDomain),
		)
	}
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Actor validation succeeded", attrs...)
}

func (p *loggingTokenExchangeProbe) ActorValidationFailed(err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Actor validation failed",
		slog.String("error", err.Error()),
	)
}

func (p *loggingTokenExchangeProbe) RequestContextParsed(attrs *request.RequestAttributes) {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Request context parsed")
}

func (p *loggingTokenExchangeProbe) RequestContextParseFailed(err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Request context parse failed",
		slog.String("error", err.Error()),
	)
}

func (p *loggingTokenExchangeProbe) SubjectTokenValidationSucceeded(subject *trust.Result) {
	attrs := []slog.Attr{}
	if subject != nil {
		attrs = append(attrs,
			slog.String("subject_id", subject.Subject),
			slog.String("subject_trust_domain", subject.TrustDomain),
		)
	}
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Subject token validation succeeded", attrs...)
}

func (p *loggingTokenExchangeProbe) SubjectTokenValidationFailed(err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Subject token validation failed",
		slog.String("error", err.Error()),
	)
}

func (p *loggingTokenExchangeProbe) End() {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Token exchange completed")
}

// AuthzCheckStarted implements service.AuthzCheckObserver
func (o *loggingObserver) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, service.AuthzCheckProbe) {
	// Create scoped logger for this probe type
	probeLogger := o.logger.With("event", "authz_check")

	probeLogger.LogAttrs(ctx, slog.LevelDebug, "Starting authorization check")

	return ctx, &loggingAuthzCheckProbe{
		ctx:    ctx,
		logger: probeLogger,
	}
}

// loggingAuthzCheckProbe is a request-scoped probe that logs authorization check events
type loggingAuthzCheckProbe struct {
	service.NoOpAuthzCheckProbe
	ctx    context.Context
	logger *slog.Logger
}

func (p *loggingAuthzCheckProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	logAttrs := []slog.Attr{}
	if attrs != nil {
		logAttrs = append(logAttrs,
			slog.String("method", attrs.Method),
			slog.String("path", attrs.Path),
		)
	}
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Request attributes parsed", logAttrs...)
}

func (p *loggingAuthzCheckProbe) ActorValidationSucceeded(actor *trust.Result) {
	attrs := []slog.Attr{}
	if actor != nil {
		attrs = append(attrs,
			slog.String("actor_id", actor.Subject),
			slog.String("actor_trust_domain", actor.TrustDomain),
		)
	}
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Actor validation succeeded", attrs...)
}

func (p *loggingAuthzCheckProbe) ActorValidationFailed(err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Actor validation failed",
		slog.String("error", err.Error()),
	)
}

func (p *loggingAuthzCheckProbe) SubjectCredentialExtracted(cred trust.Credential, headersUsed []string) {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug,
		"Subject credential extracted",
		slog.String("credential_type", string(cred.Type())),
	)
}

func (p *loggingAuthzCheckProbe) SubjectCredentialExtractionFailed(err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Subject credential extraction failed",
		slog.String("error", err.Error()),
	)
}

func (p *loggingAuthzCheckProbe) SubjectValidationSucceeded(subject *trust.Result) {
	attrs := []slog.Attr{}
	if subject != nil {
		attrs = append(attrs,
			slog.String("subject_id", subject.Subject),
			slog.String("subject_trust_domain", subject.TrustDomain),
		)
	}
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Subject validation succeeded", attrs...)
}

func (p *loggingAuthzCheckProbe) SubjectValidationFailed(err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Subject validation failed",
		slog.String("error", err.Error()),
	)
}

func (p *loggingAuthzCheckProbe) End() {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Authorization check completed")
}
