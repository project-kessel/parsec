package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/trust"
)

var (
	jwtResultJWKSLookupFailed       = attribute.String("result", "jwks_lookup_failed")
	jwtResultTokenExpired           = attribute.String("result", "token_expired")
	jwtResultTokenInvalid           = attribute.String("result", "token_invalid")
	jwtResultClaimsExtractionFailed = attribute.String("result", "claims_extraction_failed")
	jwtResultAudienceMissingAccepted = attribute.String("result", "audience_missing_accepted")
)

type trustObserver struct {
	trust.NoOpTrustObserver

	validationDuration  metric.Float64Histogram
	jwtValidateDuration metric.Float64Histogram
	actorFilterDuration metric.Float64Histogram
}

func newTrustObserver(m metric.Meter) (*trustObserver, error) {
	vd, err := m.Float64Histogram("parsec.trust.validation.duration",
		metric.WithDescription("Trust validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	jvd, err := m.Float64Histogram("parsec.trust.jwt.validate.duration",
		metric.WithDescription("JWT validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	afd, err := m.Float64Histogram("parsec.trust.actor.filter.duration",
		metric.WithDescription("Actor filter duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &trustObserver{
		validationDuration:  vd,
		jwtValidateDuration: jvd,
		actorFilterDuration: afd,
	}, nil
}

// --- validation probe ---

func (o *trustObserver) ValidationStarted(ctx context.Context) (context.Context, trust.ValidationProbe) {
	return ctx, &validationProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type validationProbe struct {
	trust.NoOpValidationProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *validationProbe) AllValidatorsFailed(_ trust.CredentialType, _ int, _ error) {
	p.status = errorStatusAttr
}
func (p *validationProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.validationDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- JWT validate probe ---

func (o *trustObserver) JWTValidateStarted(ctx context.Context, issuer string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &jwtValidateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
		result: resultSuccess,
		issuer: attribute.String("issuer", issuer),
	}
}

// jwtValidateProbe records metrics for a single JWT validation.
// The issuer attribute is the configured issuer URL of the validator,
// bounded by the number of trust_store.validators — not a per-request value.
type jwtValidateProbe struct {
	trust.NoOpJWTValidateProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
	issuer    attribute.KeyValue
}

func (p *jwtValidateProbe) JWKSLookupFailed(_ error) {
	p.status = errorStatusAttr
	p.result = jwtResultJWKSLookupFailed
}
func (p *jwtValidateProbe) TokenExpired() {
	p.status = errorStatusAttr
	p.result = jwtResultTokenExpired
}
func (p *jwtValidateProbe) TokenInvalid(_ error) {
	p.status = errorStatusAttr
	p.result = jwtResultTokenInvalid
}
func (p *jwtValidateProbe) ClaimsExtractionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = jwtResultClaimsExtractionFailed
}
func (p *jwtValidateProbe) AudienceMissingAccepted() {
	p.result = jwtResultAudienceMissingAccepted
}
func (p *jwtValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.issuer, p.result, p.status))
	p.obs.jwtValidateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- actor filter probe ---

func (o *trustObserver) ForActorStarted(ctx context.Context) (context.Context, trust.ForActorProbe) {
	return ctx, &forActorProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type forActorProbe struct {
	trust.NoOpForActorProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *forActorProbe) FilterEvaluationFailed(_ string, _ error) { p.status = errorStatusAttr }
func (p *forActorProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.actorFilterDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

var (
	_ trust.TrustObserver    = (*trustObserver)(nil)
	_ trust.ValidationProbe  = (*validationProbe)(nil)
	_ trust.JWTValidateProbe = (*jwtValidateProbe)(nil)
	_ trust.ForActorProbe    = (*forActorProbe)(nil)
)
