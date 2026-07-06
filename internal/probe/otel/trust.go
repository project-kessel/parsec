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

	luaValidateResultRejected         = attribute.String("result", "rejected")
	luaValidateResultScriptLoadFailed = attribute.String("result", "script_load_failed")
	luaValidateResultExecutionFailed  = attribute.String("result", "execution_failed")
	luaValidateResultInvalidReturn    = attribute.String("result", "invalid_return_type")
	luaValidateResultTokenInvalid     = attribute.String("result", "token_invalid")
	luaValidateResultConversionFailed = attribute.String("result", "conversion_failed")

	inMemoryResultCacheKeyFailed = attribute.String("result", "cache_key_failed")
	inMemoryResultHit            = attribute.String("result", "hit")
	inMemoryResultExpired        = attribute.String("result", "expired")
	inMemoryResultMiss           = attribute.String("result", "miss")
	inMemoryResultSourceFailed   = attribute.String("result", "source_failed")

	distributedResultCacheKeyFailed = attribute.String("result", "cache_key_failed")
	distributedResultGetFailed      = attribute.String("result", "get_failed")
	distributedResultExpired        = attribute.String("result", "result_expired")
)

var (
	validatorTypeJWT = attribute.String("validator_type", "jwt")
	validatorTypeLua = attribute.String("validator_type", "lua")
)

var (
	cacheTypeInMemory    = attribute.String("cache_type", "in_memory")
	cacheTypeDistributed = attribute.String("cache_type", "distributed")
)

type trustObserver struct {
	trust.NoOpTrustObserver

	validationDuration               metric.Float64Histogram
	validateDuration                 metric.Float64Histogram
	cachingValidatorValidateDuration metric.Float64Histogram
	actorFilterDuration              metric.Float64Histogram
}

func newTrustObserver(m metric.Meter) (*trustObserver, error) {
	vd, err := m.Float64Histogram("parsec.trust.validation.duration",
		metric.WithDescription("Trust validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	vald, err := m.Float64Histogram("parsec.trust.validate.duration",
		metric.WithDescription("Per-validator validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	cvvd, err := m.Float64Histogram("parsec.trust.caching.validate.duration",
		metric.WithDescription("Caching validator validate duration in seconds"),
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
		validationDuration:               vd,
		validateDuration:                 vald,
		cachingValidatorValidateDuration: cvvd,
		actorFilterDuration:              afd,
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
		status:        successStatusAttr,
		result:        resultSuccess,
		validatorType: validatorTypeJWT,
		validator:     attribute.String("validator", issuer),
	}
}

// jwtValidateProbe records metrics for a single JWT validation.
// The validator attribute is the configured issuer URL of the JWT validator,
// bounded by the number of trust_store.validators — not a per-request value.
type jwtValidateProbe struct {
	trust.NoOpJWTValidateProbe
	obs           *trustObserver
	ctx           context.Context
	startTime     time.Time
	status        attribute.KeyValue
	result        attribute.KeyValue
	validatorType attribute.KeyValue
	validator     attribute.KeyValue
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
func (p *jwtValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.validatorType, p.validator, p.result, p.status))
	p.obs.validateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- Lua validate probe ---

func (o *trustObserver) LuaValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.LuaValidateProbe) {
	return ctx, &luaValidateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status:        successStatusAttr,
		result:        resultSuccess,
		validatorType: validatorTypeLua,
		validator:     attribute.String("validator", validatorName),
	}
}

type luaValidateProbe struct {
	trust.NoOpLuaValidateProbe
	obs           *trustObserver
	ctx           context.Context
	startTime     time.Time
	status        attribute.KeyValue
	result        attribute.KeyValue
	validatorType attribute.KeyValue
	validator     attribute.KeyValue
}

func (p *luaValidateProbe) ScriptLoadFailed(_ error) {
	p.status = errorStatusAttr
	p.result = luaValidateResultScriptLoadFailed
}
func (p *luaValidateProbe) ScriptExecutionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = luaValidateResultExecutionFailed
}
func (p *luaValidateProbe) InvalidReturnType(_ string) {
	p.status = errorStatusAttr
	p.result = luaValidateResultInvalidReturn
}
func (p *luaValidateProbe) TokenInvalid(_ error) {
	p.status = errorStatusAttr
	p.result = luaValidateResultTokenInvalid
}
func (p *luaValidateProbe) ValidationRejected() {
	p.status = errorStatusAttr
	p.result = luaValidateResultRejected
}
func (p *luaValidateProbe) ResultConversionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = luaValidateResultConversionFailed
}
func (p *luaValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.validatorType, p.validator, p.result, p.status))
	p.obs.validateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- in-memory caching validator probe ---

func (o *trustObserver) InMemoryValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.InMemoryValidateProbe) {
	return ctx, &inMemoryValidateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status:    successStatusAttr,
		result:    resultSuccess,
		cacheType: cacheTypeInMemory,
		validator: attribute.String("validator", validatorName),
	}
}

type inMemoryValidateProbe struct {
	trust.NoOpInMemoryValidateProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
	cacheType attribute.KeyValue
	validator attribute.KeyValue
}

func (p *inMemoryValidateProbe) CacheKeyFailed(_ error) {
	p.status = errorStatusAttr
	p.result = inMemoryResultCacheKeyFailed
}
func (p *inMemoryValidateProbe) CacheHit()     { p.result = inMemoryResultHit }
func (p *inMemoryValidateProbe) CacheExpired() { p.result = inMemoryResultExpired }
func (p *inMemoryValidateProbe) CacheMiss()    { p.result = inMemoryResultMiss }
func (p *inMemoryValidateProbe) SourceFailed(_ error) {
	p.status = errorStatusAttr
	p.result = inMemoryResultSourceFailed
}
func (p *inMemoryValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.cacheType, p.validator, p.result, p.status))
	p.obs.cachingValidatorValidateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- distributed caching validator probe ---

func (o *trustObserver) DistributedValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.DistributedValidateProbe) {
	return ctx, &distributedValidateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status:    successStatusAttr,
		result:    resultSuccess,
		cacheType: cacheTypeDistributed,
		validator: attribute.String("validator", validatorName),
	}
}

type distributedValidateProbe struct {
	trust.NoOpDistributedValidateProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
	cacheType attribute.KeyValue
	validator attribute.KeyValue
}

func (p *distributedValidateProbe) CacheKeyFailed(_ error) {
	p.status = errorStatusAttr
	p.result = distributedResultCacheKeyFailed
}
func (p *distributedValidateProbe) GetFailed(_ error) {
	p.status = errorStatusAttr
	p.result = distributedResultGetFailed
}
func (p *distributedValidateProbe) ResultExpired() {
	p.status = errorStatusAttr
	p.result = distributedResultExpired
}
func (p *distributedValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.cacheType, p.validator, p.result, p.status))
	p.obs.cachingValidatorValidateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
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
	_ trust.TrustObserver            = (*trustObserver)(nil)
	_ trust.ValidationProbe          = (*validationProbe)(nil)
	_ trust.JWTValidateProbe         = (*jwtValidateProbe)(nil)
	_ trust.LuaValidateProbe         = (*luaValidateProbe)(nil)
	_ trust.InMemoryValidateProbe    = (*inMemoryValidateProbe)(nil)
	_ trust.DistributedValidateProbe = (*distributedValidateProbe)(nil)
	_ trust.ForActorProbe            = (*forActorProbe)(nil)
)
