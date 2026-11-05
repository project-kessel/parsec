// Package audit implements security audit records with configurable event names.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog"

	auditctx "github.com/project-kessel/parsec/internal/audit"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// AuditOutcome is the externally-visible result of a security-relevant request.
type AuditOutcome string

const (
	AuditOutcomeSuccess AuditOutcome = "success"
	AuditOutcomeDenied  AuditOutcome = "denied"
	AuditOutcomeFailure AuditOutcome = "failure"
)

const (
	SchemaVersion      = "1.0"
	DefaultEventPrefix = "parsec_"

	ReasonCredentialMissing    = "credential_missing"
	ReasonCredentialMalformed  = "credential_malformed"
	ReasonCredentialInvalid    = "credential_invalid"
	ReasonCredentialExpired    = "credential_expired"
	ReasonInvalidRequest       = "invalid_request"
	ReasonGrantTypeUnsupported = "grant_type_unsupported"
	ReasonSchemeNotAllowed     = "scheme_not_allowed"
	ReasonPolicyDenied         = "policy_denied"
	ReasonComplianceDenied     = "compliance_denied"
	ReasonComplianceFailure    = "compliance_failure"
	ReasonSupplementalFailure  = "supplemental_user_data_failure"
	ReasonDependencyFailure    = "dependency_failure"
	ReasonInternalError        = "internal_error"
	ReasonTokenIssuanceFailed  = "token_issuance_failed"
	ReasonTokenIssuanceDenied  = "token_issuance_denied"
	ReasonCrossAccountDenied   = "cross_account_denied"
)

// Metadata is safe service metadata included in every audit record.
type Metadata struct {
	ServiceName    string `json:"name"`
	ServiceVersion string `json:"version,omitempty"`
	Environment    string `json:"environment,omitempty"`
	TrustDomain    string `json:"trust_domain,omitempty"`
}

// Observer is intentionally separate from diagnostic logging. It emits a
// small allowlisted schema and never serializes credentials, claims, or errors.
type Observer struct {
	service.NoOpServiceObserver
	datasource.NoOpDataSourceObserver
	keys.NoOpKeysObserver
	trust.NoOpTrustObserver
	server.NoOpServerObserver
	httpclient.NoOpHTTPClientObserver

	logger                 zerolog.Logger
	meta                   Metadata
	metaJSON               json.RawMessage
	eventPrefix            string
	failureClassifications map[string]string
	allowedMetadataKeys    map[string]bool
}

// Option configures an audit observer.
type Option func(*Observer)

// WithEventPrefix sets the prefix applied to every audit event name.
func WithEventPrefix(prefix string) Option {
	return func(observer *Observer) {
		observer.eventPrefix = prefix
	}
}

// WithFailureClassifications sets the mapping from datasource name to audit
// failure reason code. When a datasource fails, the mapped classification is
// used instead of the generic "dependency_failure" default.
func WithFailureClassifications(classifications map[string]string) Option {
	return func(observer *Observer) {
		observer.failureClassifications = classifications
	}
}

// WithAllowedMetadataKeys sets the allowlist of metadata keys that
// audit.record() may emit. A non-nil empty map rejects all metadata
// keys (fail-closed default). A nil map means allow-all (text/length
// validation only). When non-empty, only listed keys are permitted.
func WithAllowedMetadataKeys(keys map[string]bool) Option {
	return func(observer *Observer) {
		observer.allowedMetadataKeys = keys
	}
}

func New(logger zerolog.Logger, meta Metadata, options ...Option) (*Observer, error) {
	observer := &Observer{logger: logger, meta: meta, eventPrefix: DefaultEventPrefix}
	for _, option := range options {
		option(observer)
	}
	var err error
	observer.metaJSON, err = json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal audit metadata: %w", err)
	}
	return observer, nil
}

// ValidEventPrefix reports whether prefix is safe to include in the event field.
// An empty prefix is valid and emits the canonical event suffix unchanged.
func ValidEventPrefix(prefix string) bool {
	for _, r := range prefix {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func (o *Observer) eventName(suffix string) string { return o.eventPrefix + suffix }

func (o *Observer) Shutdown(context.Context) error  { return nil }
func (o *Observer) ConfigureHTTPMux(*http.ServeMux) {}

type principal struct {
	ID             string `json:"id,omitempty"`
	TrustDomain    string `json:"trust_domain,omitempty"`
	OrgID          string `json:"org_id,omitempty"`
	AccountNumber  string `json:"account_number,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
}

type requestInfo struct {
	Protocol string `json:"protocol"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
}

type resourceInfo struct {
	Type                string               `json:"type"`
	TokenTypes          []string             `json:"token_types,omitempty"`
	RequestedTokenTypes []string             `json:"requested_token_types,omitempty"`
	CacheStatus         string               `json:"cache_status,omitempty"`
	CacheLayers         []request.CacheLayer `json:"cache_layers,omitempty"`
	FailedComponent     string               `json:"failed_component,omitempty"`
	SignalsDropped      int                  `json:"signals_dropped,omitempty"`
}

// emitEnvelope holds pre-serialized JSON for the shared fields that are
// identical across all events emitted during a single request. Built once
// in End(), then passed by pointer to every emitRaw() call, replacing
// per-call Interface() marshaling with zero-cost RawJSON() byte copies.
type emitEnvelope struct {
	service  json.RawMessage
	request  json.RawMessage
	subject  json.RawMessage
	actor    json.RawMessage
	resource json.RawMessage
	signals  json.RawMessage // nil when no signals
}

type requestProbe struct {
	service.NoOpAuthzCheckProbe
	service.NoOpTokenExchangeProbe
	observer  *Observer
	requestID string
	started   time.Time
	action    string
	request   requestInfo
	subject   principal
	actor     principal
	authorize bool
	state     *request.AuditState
	collector *auditctx.Collector

	// Callback state for reason derivation (set by probe methods)
	subjectAnonymous          bool
	subjectExtractionFailed   bool
	subjectValidationErr      error
	actorExtractionFailed     bool
	actorValidationErr        error
	policyDenied              bool
	policyDenyReason          string
	policyEvalErr             error
	policyAllowed             bool
	policyIssue               bool
	requestContextParseFailed bool
	tokenIssuanceFailed       bool
	tokenIssuanceDenied       bool
	issuanceDenialReason      string
	requestFailed             bool
	requestFailedErr          error
	tokenTypes                []service.TokenType
	requestedTokenTypes       []service.TokenType

	// Derived at emit time
	cacheStatus       string
	derivedOutcome    AuditOutcome
	derivedReasonCode string
}

// Each audit observer keeps its own request probe, including when multiple
// audit observers are composed. Nested issuance callbacks update only that
// observer's request; no audit state is needed in application handlers.
type requestProbeKey struct{ observer *Observer }

func (o *Observer) AuthzCheckStarted(ctx context.Context) (context.Context, service.AuthzCheckProbe) {
	return o.startRequest(ctx, "authorize", requestInfo{Protocol: "ext_authz"})
}

func (o *Observer) TokenExchangeStarted(ctx context.Context, _, _, _, _ string) (context.Context, service.TokenExchangeProbe) {
	return o.startRequest(ctx, "token_exchange", requestInfo{Protocol: "grpc", Method: http.MethodPost, Path: "/v1/token"})
}

func (o *Observer) startRequest(ctx context.Context, action string, info requestInfo) (context.Context, *requestProbe) {
	ctx, state := request.WithAuditState(ctx)
	collector := auditctx.NewCollector(o.allowedMetadataKeys)
	ctx = auditctx.WithReporter(ctx, collector)
	p := &requestProbe{
		observer:  o,
		requestID: safeValue(request.ID(ctx), 128),
		started:   time.Now(),
		action:    action,
		request:   info,
		authorize: action == "authorize",
		state:     state,
		collector: collector,
	}
	return context.WithValue(ctx, requestProbeKey{o}, p), p
}

type issuanceProbe struct {
	service.NoOpTokenIssuanceProbe
	request *requestProbe
}

func (o *Observer) TokenIssuanceStarted(ctx context.Context, _, _ *trust.Result, _ string, tokenTypes []service.TokenType) (context.Context, service.TokenIssuanceProbe) {
	p, _ := ctx.Value(requestProbeKey{o}).(*requestProbe)
	if p == nil {
		return ctx, service.NoOpTokenIssuanceProbe{}
	}
	p.requestedTokenTypes = append(p.requestedTokenTypes, tokenTypes...)
	return ctx, &issuanceProbe{request: p}
}

func (p *issuanceProbe) TokenTypeIssuanceSucceeded(tokenType service.TokenType, token *service.Token) {
	if token == nil {
		p.request.tokenIssuanceFailed = true
		return
	}
	p.request.tokenTypes = append(p.request.tokenTypes, tokenType)
}

func (p *issuanceProbe) TokenTypeIssuanceFailed(_ service.TokenType, err error) {
	p.request.TokenIssuanceFailed(err)
}

func (p *issuanceProbe) IssuerNotFound(_ service.TokenType, err error) {
	p.request.TokenIssuanceFailed(err)
}

func (p *issuanceProbe) TokenTypeIssuanceDenied(_ service.TokenType, denial *service.ExchangeError) {
	p.request.TokenIssuanceDenied(denial)
	if denial != nil && ValidReasonCode(denial.Classification) {
		// Preserve the individual policy decision even if another token type
		// later fails and changes the terminal request outcome.
		p.request.collector.Record(auditctx.Signal{
			Source: auditctx.SourcePolicy, Operation: "token_issuance",
			Outcome: auditctx.OutcomeDenied, ReasonCode: denial.Classification,
		})
	}
}

func (p *requestProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	if attrs == nil {
		return
	}
	p.request.Method = safeValue(attrs.Method, 32)
	p.request.Path = safePath(attrs.Path)
	p.request.SourceIP = safeValue(attrs.IPAddress, 64)
}

func (p *requestProbe) ActorCredentialExtracted(credential trust.Credential, _ []string) {
	if credential != nil {
		p.actor.CredentialType = string(credential.Type())
	}
}

func (p *requestProbe) SubjectCredentialExtracted(credential trust.Credential, _ []string) {
	if credential != nil {
		p.subject.CredentialType = string(credential.Type())
	}
}

func (p *requestProbe) ActorValidationSucceeded(result *trust.Result) {
	fillPrincipal(&p.actor, result)
}

func (p *requestProbe) ActorCredentialExtractionFailed(error) { p.actorExtractionFailed = true }
func (p *requestProbe) ActorValidationFailed(err error)       { p.actorValidationErr = err }

func (p *requestProbe) SubjectValidationSucceeded(result *trust.Result) {
	fillPrincipal(&p.subject, result)
}

func (p *requestProbe) SubjectCredentialExtractionFailed(error) {
	p.subjectExtractionFailed = true
}

func (p *requestProbe) SubjectValidationFailed(err error) {
	p.subjectValidationErr = err
}

func (p *requestProbe) SubjectAnonymous() {
	p.subjectAnonymous = true
}

func (p *requestProbe) SubjectTokenValidationFailed(err error) {
	p.subjectValidationErr = err
}

func (p *requestProbe) SubjectTokenValidationSucceeded(result *trust.Result) {
	fillPrincipal(&p.subject, result)
}

func (p *requestProbe) RequestContextParseFailed(error) {
	p.requestContextParseFailed = true
}

func (p *requestProbe) PolicyDecisionDeny(reason string) {
	p.policyDenied = true
	p.policyDenyReason = reason
}

func (p *requestProbe) PolicyDecisionAllowWithoutIssue(string) {
	p.policyAllowed = true
}

func (p *requestProbe) PolicyDecisionIssue(_ int, _ string, _ string) {
	p.policyIssue = true
}

func (p *requestProbe) PolicyEvaluationFailed(err error) {
	p.policyEvalErr = err
}

func (p *requestProbe) TokenIssuanceFailed(error) {
	p.tokenIssuanceFailed = true
}

// First-writer-wins: record the earliest denial's classification for root-cause attribution.
func (p *requestProbe) TokenIssuanceDenied(err error) {
	var denial *service.ExchangeError
	if !p.tokenIssuanceDenied && errors.As(err, &denial) && denial != nil && ValidReasonCode(denial.Classification) {
		p.issuanceDenialReason = denial.Classification
	}
	p.tokenIssuanceDenied = true
}

func (p *requestProbe) RequestFailed(err error) {
	p.requestFailed = true
	p.requestFailedErr = err
}

// deriveCompletion determines audit outcome and reason from the sequence of
// probe callbacks received during the request. This keeps audit vocabulary
// out of the handlers and centralizes reason derivation in the observer.
func (p *requestProbe) deriveCompletion() (outcome AuditOutcome, reasonCode string) {
	// A system failure overrides earlier successes or denials: IssueTokens
	// returns a top-level error even when an earlier type was denied.
	// This fires when the policy decided to issue but the actual issuance
	// (signing, system error) failed afterward.
	if p.tokenIssuanceFailed {
		return AuditOutcomeFailure, ReasonTokenIssuanceFailed
	}
	if p.tokenIssuanceDenied {
		if p.issuanceDenialReason != "" {
			return AuditOutcomeDenied, p.issuanceDenialReason
		}
		return AuditOutcomeDenied, ReasonTokenIssuanceDenied
	}

	// Success paths
	if p.policyAllowed || p.policyIssue {
		return AuditOutcomeSuccess, ""
	}

	// Explicit deny
	if p.policyDenied {
		if p.subjectAnonymous {
			return AuditOutcomeDenied, ReasonCredentialMissing
		}
		return AuditOutcomeDenied, ReasonPolicyDenied
	}

	// Credential extraction failures
	if p.subjectExtractionFailed {
		return AuditOutcomeDenied, ReasonCredentialMalformed
	}
	if p.actorExtractionFailed {
		return AuditOutcomeDenied, ReasonCredentialMalformed
	}

	// Validation failures
	if p.subjectValidationErr != nil {
		if errors.Is(p.subjectValidationErr, trust.ErrExpiredToken) {
			return AuditOutcomeDenied, ReasonCredentialExpired
		}
		return AuditOutcomeDenied, ReasonCredentialInvalid
	}
	if p.actorValidationErr != nil {
		if errors.Is(p.actorValidationErr, trust.ErrExpiredToken) {
			return AuditOutcomeDenied, ReasonCredentialExpired
		}
		return AuditOutcomeDenied, ReasonCredentialInvalid
	}

	// Request context parse failure (token exchange path)
	if p.requestContextParseFailed {
		return AuditOutcomeFailure, ReasonInternalError
	}

	// Policy evaluation error
	if p.policyEvalErr != nil {
		return AuditOutcomeFailure, ReasonInternalError
	}

	// Catch-all request failure (e.g. unsupported grant type, audience mismatch)
	if p.requestFailed {
		if p.requestFailedErr != nil {
			if errors.Is(p.requestFailedErr, service.ErrUnsupportedGrantType) {
				return AuditOutcomeFailure, ReasonGrantTypeUnsupported
			}
		}
		return AuditOutcomeFailure, ReasonInternalError
	}

	// No failure was signaled — the request completed successfully.
	// For authz this is unreachable (policy callbacks always fire);
	// for token exchange it means the token was issued without error.
	return AuditOutcomeSuccess, ""
}

func (p *requestProbe) End() {
	outcome, reasonCode := p.deriveCompletion()

	cacheStatus, cacheLayers, failureReason, failedComponent, dependencyOutage := p.state.Snapshot()
	if outcome == AuditOutcomeFailure && (reasonCode == "" || reasonCode == ReasonInternalError) && failureReason != "" {
		reasonCode = failureReason
	}
	// A real infrastructure outage (JWKS down, distributed cache failure)
	// overrides credential_invalid to failure/dependency_failure so that
	// bad signatures are not reported as outages.
	if dependencyOutage && outcome == AuditOutcomeDenied && reasonCode == ReasonCredentialInvalid {
		outcome = AuditOutcomeFailure
		reasonCode = ReasonDependencyFailure
	}
	p.cacheStatus = cacheStatus
	p.derivedOutcome = outcome
	p.derivedReasonCode = reasonCode
	signals := p.collector.Signals()

	env := emitEnvelope{
		service: p.observer.metaJSON,
	}
	env.request, _ = json.Marshal(p.request)
	env.subject, _ = json.Marshal(p.subject)
	env.actor, _ = json.Marshal(p.actor)
	env.resource, _ = json.Marshal(resourceInfo{
		Type: resourceTypeForAction(p.action), TokenTypes: safeTokenTypes(p.tokenTypes),
		RequestedTokenTypes: safeTokenTypes(p.requestedTokenTypes), CacheStatus: p.cacheStatus, CacheLayers: cacheLayers,
		FailedComponent: failedComponent, SignalsDropped: p.collector.Dropped(),
	})
	if len(signals) > 0 {
		env.signals, _ = json.Marshal(signals)
	}

	p.emitRaw("request", nil, &env)

	if p.authorize {
		p.emitRaw("authorize", nil, &env)
	}
	if p.subject.CredentialType == string(trust.CredentialTypeMTLS) || p.subject.CredentialType == string(trust.CredentialTypeForwardedClientCert) {
		p.emitRaw("validate_ssl_cert", nil, &env)
	}
	if p.actor.CredentialType == string(trust.CredentialTypeHeader) {
		p.emitRaw("verify_psk", nil, &env)
	}

	// Each signal whose reason maps to an event emits its own event with
	// its own outcome. Two signals with the same reason emit two events.
	signalCoveredSuffix := false
	finalSuffix := signalEventSuffix(reasonCode)
	for _, signal := range signals {
		if suffix := signalEventSuffix(signal.ReasonCode); suffix != "" {
			p.emitRaw(suffix, &signal, &env)
			if suffix == finalSuffix {
				signalCoveredSuffix = true
			}
		}
	}

	// Emit the reason-specific event for the request's final reason only
	// when no signal already carries the same reason.
	if finalSuffix != "" && !signalCoveredSuffix {
		p.emitRaw(finalSuffix, nil, &env)
	}
}

// emitRaw writes a single audit event record using pre-serialized envelope
// fields. Only outcome and reason_code vary per event; the shared fields are
// serialized once in End().
func (p *requestProbe) emitRaw(suffix string, signal *auditctx.Signal, env *emitEnvelope) {
	name := p.observer.eventName(suffix)
	var outcome AuditOutcome
	var reasonCode string
	if signal != nil {
		outcome = signalOutcomeToAuditOutcome(signal.Outcome)
		reasonCode = signal.ReasonCode
	} else {
		outcome = p.derivedOutcome
		reasonCode = p.derivedReasonCode
	}

	reason := safeReasonCode(reasonCode)

	event := p.observer.event(outcome).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", p.action).
		Str("outcome", string(outcome)).
		Str("request_id", p.requestID).
		Int64("duration_ms", time.Since(p.started).Milliseconds()).
		RawJSON("service", env.service).
		RawJSON("request", env.request).
		RawJSON("subject", env.subject).
		RawJSON("actor", env.actor).
		RawJSON("resource", env.resource)
	if len(env.signals) > 0 {
		event = event.RawJSON("signals", env.signals)
	}
	if reason != "" {
		event = event.Str("reason_code", reason)
	}
	event.Msg(name)
}

func signalOutcomeToAuditOutcome(outcome string) AuditOutcome {
	switch outcome {
	case auditctx.OutcomeSuccess:
		return AuditOutcomeSuccess
	case auditctx.OutcomeDenied:
		return AuditOutcomeDenied
	case auditctx.OutcomeFailure:
		return AuditOutcomeFailure
	default:
		return AuditOutcomeFailure
	}
}

// resourceTypeForAction maps the probe action to the audit resource type.
// ext_authz authorize requests emit "authorization_request"; token exchange
// requests emit "token_exchange_request".
func resourceTypeForAction(action string) string {
	switch action {
	case "token_exchange":
		return "token_exchange_request"
	default:
		return "authorization_request"
	}
}

func signalEventSuffix(reason string) string {
	switch reason {
	case ReasonComplianceDenied:
		return "auth_compliance_failure"
	case ReasonComplianceFailure:
		return "compliance_failure"
	case ReasonSupplementalFailure:
		return "supplemental_user_data_failure"
	case ReasonDependencyFailure:
		return "dependency_failure"
	default:
		return ""
	}
}

func safeReasonCode(reason string) string {
	if reason == "" {
		return ""
	}
	if !ValidReasonCode(reason) {
		return ReasonInternalError
	}
	return reason
}

// ValidReasonCode delegates to the shared implementation in internal/audit.
func ValidReasonCode(reason string) bool {
	return auditctx.ValidReasonCode(reason)
}

func safeTokenType(tokenType service.TokenType) string {
	switch tokenType {
	case service.TokenTypeTransactionToken, service.TokenTypeAccessToken,
		service.TokenTypeJWT, service.TokenTypeRHIdentity:
		return string(tokenType)
	default:
		return ""
	}
}

func safeTokenTypes(tokenTypes []service.TokenType) []string {
	var safe []string
	for _, tokenType := range tokenTypes {
		if value := safeTokenType(tokenType); value != "" {
			safe = append(safe, value)
		}
	}
	return safe
}

type auditInMemoryCacheProbe struct {
	trust.NoOpInMemoryValidateProbe
	state *request.AuditState
}

func (o *Observer) InMemoryValidateStarted(ctx context.Context, _ string) (context.Context, trust.InMemoryValidateProbe) {
	return ctx, &auditInMemoryCacheProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditInMemoryCacheProbe) CacheHit()  { p.state.RecordCacheLayer("validator_memory", "hit") }
func (p *auditInMemoryCacheProbe) CacheMiss() { p.state.RecordCacheLayer("validator_memory", "miss") }
func (p *auditInMemoryCacheProbe) CacheExpired() {
	p.state.RecordCacheLayer("validator_memory", "expired")
}
func (p *auditInMemoryCacheProbe) SourceFailed(error) {
	// SourceFailed fires for any inner validation error (bad signature,
	// expired token, etc.), not only infrastructure outages. Real outages
	// are flagged by JWKSLookupFailed / distributed GetFailed via
	// SetDependencyOutage; this callback no longer sets dependency_failure.
}

type auditDistributedCacheProbe struct {
	trust.NoOpDistributedValidateProbe
	state *request.AuditState
}

func (o *Observer) DistributedValidateStarted(ctx context.Context, _ string) (context.Context, trust.DistributedValidateProbe) {
	return ctx, &auditDistributedCacheProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditDistributedCacheProbe) CacheHit() {
	p.state.RecordCacheLayer("validator_distributed", "hit")
}
func (p *auditDistributedCacheProbe) CacheMiss() {
	p.state.RecordCacheLayer("validator_distributed", "miss")
}
func (p *auditDistributedCacheProbe) GetFailed(error) {
	p.state.RecordCacheLayer("validator_distributed", "failure")
	p.state.SetFailureReason(ReasonDependencyFailure)
	p.state.SetFailedComponent("validator_distributed")
	p.state.SetDependencyOutage()
}
func (p *auditDistributedCacheProbe) ResultExpired() {
	p.state.RecordCacheLayer("validator_distributed", "expired")
}

type auditDataSourceCacheProbe struct {
	datasource.NoOpCacheFetchProbe
	state         *request.AuditState
	layer         string
	failureReason string
}

func (o *Observer) CacheFetchStarted(ctx context.Context, name string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &auditDataSourceCacheProbe{
		state:         request.AuditStateFrom(ctx),
		layer:         "datasource:" + name,
		failureReason: o.classificationFor(name),
	}
}
func (p *auditDataSourceCacheProbe) CacheHit()     { p.state.RecordCacheLayer(p.layer, "hit") }
func (p *auditDataSourceCacheProbe) CacheMiss()    { p.state.RecordCacheLayer(p.layer, "miss") }
func (p *auditDataSourceCacheProbe) CacheExpired() { p.state.RecordCacheLayer(p.layer, "expired") }
func (p *auditDataSourceCacheProbe) FetchFailed(error) {
	p.state.RecordCacheLayer(p.layer, "failure")
	p.state.SetFailureReason(p.failureReason)
	p.state.SetFailedComponent(p.layer)
}

type auditLuaFetchProbe struct {
	datasource.NoOpLuaFetchProbe
	state         *request.AuditState
	name          string
	failureReason string
}

func (o *Observer) LuaFetchStarted(ctx context.Context, name string) (context.Context, datasource.LuaFetchProbe) {
	return ctx, &auditLuaFetchProbe{state: request.AuditStateFrom(ctx), name: name, failureReason: o.classificationFor(name)}
}
func (p *auditLuaFetchProbe) ScriptLoadFailed(error) {
	p.state.SetFailureReason(p.failureReason)
	p.state.SetFailedComponent(p.name)
}
func (p *auditLuaFetchProbe) ScriptExecutionFailed(error) {
	p.state.SetFailureReason(p.failureReason)
	p.state.SetFailedComponent(p.name)
}
func (p *auditLuaFetchProbe) InvalidReturnType(string) {
	p.state.SetFailureReason(p.failureReason)
	p.state.SetFailedComponent(p.name)
}
func (p *auditLuaFetchProbe) ResultConversionFailed(error) {
	p.state.SetFailureReason(p.failureReason)
	p.state.SetFailedComponent(p.name)
}

type auditJWTProbe struct {
	trust.NoOpJWTValidateProbe
	state *request.AuditState
}

func (o *Observer) JWTValidateStarted(ctx context.Context, _ string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &auditJWTProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditJWTProbe) JWKSLookupFailed(error) {
	p.state.SetFailureReason(ReasonDependencyFailure)
	p.state.SetFailedComponent("jwks")
	p.state.SetDependencyOutage()
}

// classificationFor returns the configured failure classification for a
// datasource, falling back to "dependency_failure" when not configured.
func (o *Observer) classificationFor(name string) string {
	if o.failureClassifications != nil {
		if classification, ok := o.failureClassifications[name]; ok && classification != "" {
			return classification
		}
	}
	return ReasonDependencyFailure
}

func (o *Observer) event(outcome AuditOutcome) *zerolog.Event {
	switch outcome {
	case AuditOutcomeDenied:
		return o.logger.Warn().Timestamp()
	case AuditOutcomeFailure:
		return o.logger.Error().Timestamp()
	default:
		return o.logger.Info().Timestamp()
	}
}

type lifecycleResource struct {
	Type                string `json:"type"`
	KeyPosition         string `json:"key_position,omitempty"`
	InterruptedRequests *int64 `json:"interrupted_requests,omitempty"`
}

type processConfig struct {
	TrustDomain string `json:"trust_domain,omitempty"`
	GRPCAddress string `json:"grpc_address,omitempty"`
	HTTPAddress string `json:"http_address,omitempty"`
	Commit      string `json:"commit,omitempty"`
}

func (o *Observer) emitLifecycle(suffix, action string, outcome AuditOutcome, reason string, started time.Time, resource lifecycleResource, config any) {
	name := o.eventName(suffix)
	event := o.event(outcome).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", action).
		Str("outcome", string(outcome)).
		Int64("duration_ms", time.Since(started).Milliseconds()).
		Interface("service", o.meta).
		Interface("resource", resource)
	if reason != "" {
		event = event.Str("reason_code", reason)
	}
	if config != nil {
		event = event.Interface("configuration", config)
	}
	event.Msg(name)
}

func (o *Observer) ProcessReady(info server.ProcessInfo) {
	meta := o.meta
	if meta.ServiceVersion == "" {
		meta.ServiceVersion = safeValue(info.Version, 128)
	}
	name := o.eventName("process_status")
	event := o.event(AuditOutcomeSuccess).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", "process_ready").
		Str("outcome", string(AuditOutcomeSuccess)).
		Int64("duration_ms", 0).
		Interface("service", meta).
		Interface("resource", lifecycleResource{Type: "process"}).
		Interface("configuration", processConfig{
			TrustDomain: safeValue(info.TrustDomain, 512),
			GRPCAddress: safeValue(info.GRPCAddress, 256),
			HTTPAddress: safeValue(info.HTTPAddress, 256),
			Commit:      safeValue(info.Commit, 128),
		})
	// configuration values are static process startup config, not per-request.
	event.Msg(name)
}

type auditStopProbe struct {
	server.NoOpStopProbe
	observer *Observer
	started  time.Time
	emitted  bool
}

func (o *Observer) StopStarted(ctx context.Context) (context.Context, server.StopProbe) {
	return ctx, &auditStopProbe{observer: o, started: time.Now()}
}

func (p *auditStopProbe) ShutdownCompleted(interrupted int64) {
	p.observer.emitLifecycle("process_status", "process_stop", AuditOutcomeSuccess, "", p.started, lifecycleResource{Type: "process", InterruptedRequests: int64Pointer(interrupted)}, nil)
	p.emitted = true
}

func (p *auditStopProbe) ShutdownFailed(interrupted int64) {
	p.observer.emitLifecycle("process_status", "process_stop", AuditOutcomeFailure, ReasonInternalError, p.started, lifecycleResource{Type: "process", InterruptedRequests: int64Pointer(interrupted)}, nil)
	p.emitted = true
}

func (p *auditStopProbe) End() {
	if !p.emitted {
		p.ShutdownFailed(0)
	}
}

func int64Pointer(value int64) *int64 { return &value }

type auditRotationProbe struct {
	keys.NoOpRotationCheckProbe
	observer *Observer
	started  time.Time
	emitted  bool
}

func (o *Observer) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	return ctx, &auditRotationProbe{observer: o, started: time.Now()}
}

func (p *auditRotationProbe) RotationCheckFailed(error) {
	p.observer.emitLifecycle("key_rotation", "key_rotate", AuditOutcomeFailure, ReasonDependencyFailure, p.started, lifecycleResource{Type: "signing_key"}, nil)
	p.emitted = true
}

func (p *auditRotationProbe) RotationCompleted(slot string) {
	p.observer.emitLifecycle("key_rotation", "key_rotate", AuditOutcomeSuccess, "", p.started, lifecycleResource{Type: "signing_key", KeyPosition: safeValue(slot, 64)}, nil)
	p.emitted = true
}

func (p *auditRotationProbe) End() {}

type auditKMSProbe struct {
	keys.NoOpKMSRotateProbe
	observer *Observer
	started  time.Time
}

func (o *Observer) KMSRotateStarted(ctx context.Context, _, _, _ string) (context.Context, keys.KMSRotateProbe) {
	return ctx, &auditKMSProbe{observer: o, started: time.Now()}
}

func (p *auditKMSProbe) emit(action string, outcome AuditOutcome) {
	reason := ""
	if outcome == AuditOutcomeFailure {
		reason = ReasonDependencyFailure
	}
	p.observer.emitLifecycle("key_rotation", action, outcome, reason, p.started, lifecycleResource{Type: "signing_key"}, nil)
}

func (p *auditKMSProbe) KeyCreated()           { p.emit("key_create", AuditOutcomeSuccess) }
func (p *auditKMSProbe) CreateKeyFailed(error) { p.emit("key_create", AuditOutcomeFailure) }
func (p *auditKMSProbe) AliasChanged(created bool) {
	action := "key_alias_update"
	if created {
		action = "key_alias_create"
	}
	p.emit(action, AuditOutcomeSuccess)
}
func (p *auditKMSProbe) AliasCheckFailed(error) {
	p.emit("key_alias_change", AuditOutcomeFailure)
}
func (p *auditKMSProbe) AliasUpdateFailed(error) {
	p.emit("key_alias_change", AuditOutcomeFailure)
}
func (p *auditKMSProbe) DeletionScheduled() {
	p.emit("key_deletion_schedule", AuditOutcomeSuccess)
}
func (p *auditKMSProbe) OldKeyDeletionFailed(string, error) {
	p.emit("key_deletion_schedule", AuditOutcomeFailure)
}
func (p *auditKMSProbe) End() {}

func fillPrincipal(dst *principal, result *trust.Result) {
	if result == nil {
		return
	}
	dst.ID = safeValue(result.Subject, 256)
	dst.TrustDomain = safeValue(result.TrustDomain, 512)
	dst.OrgID = orgID(result)
	dst.AccountNumber = scalarClaim(result, "account_number")
}

func orgID(result *trust.Result) string {
	if result == nil || result.Claims == nil {
		return ""
	}
	for _, key := range []string{"org_id", "rh-org-id"} {
		if value, ok := result.Claims[key].(string); ok {
			if safe := safeValue(value, 256); safe != "" {
				return safe
			}
		}
	}
	if organization, ok := result.Claims["organization"].(map[string]any); ok {
		if value, ok := organization["id"].(string); ok {
			return safeValue(value, 256)
		}
	}
	return ""
}

func scalarClaim(result *trust.Result, key string) string {
	if result == nil || result.Claims == nil {
		return ""
	}
	value, _ := result.Claims[key].(string)
	return safeValue(value, 256)
}

func safePath(path string) string {
	path, _, _ = strings.Cut(path, "?")
	return safeValue(path, 2048)
}

func safeValue(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ""
		}
	}
	if len(value) > max {
		end := max
		for end > 0 && !utf8.RuneStart(value[end]) {
			end--
		}
		value = value[:end]
	}
	return value
}

var _ interface {
	service.ServiceObserver
	datasource.DataSourceObserver
	keys.KeysObserver
	trust.TrustObserver
	server.ServerObserver
	httpclient.HTTPClientObserver
	Shutdown(context.Context) error
	ConfigureHTTPMux(*http.ServeMux)
} = (*Observer)(nil)
