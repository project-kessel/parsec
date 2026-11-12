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
	SchemaVersion      = "1.1"
	DefaultEventPrefix = "parsec_"
)

// Metadata is safe service metadata included in every audit record.
type Metadata struct {
	ServiceName string `json:"name"`
	TrustDomain string `json:"trust_domain,omitempty"`
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

	logger              zerolog.Logger
	meta                Metadata
	metaJSON            json.RawMessage
	eventPrefix         string
	allowedMetadataKeys map[string]bool
	principalClaims     map[string][]string
	tokenTypes          map[service.TokenType]bool
}

// Option configures an audit observer.
type Option func(*Observer)

// WithEventPrefix sets the prefix applied to every audit event name.
func WithEventPrefix(prefix string) Option {
	return func(observer *Observer) {
		observer.eventPrefix = prefix
	}
}

// WithAllowedMetadataKeys sets the allowlist of metadata keys that
// audit.record() may emit. Keys that are not listed are stripped and the
// signal is kept. A non-nil empty map strips all metadata keys (fail-closed
// default). A nil map means allow-all (text/length validation only).
func WithAllowedMetadataKeys(keys map[string]bool) Option {
	return func(observer *Observer) {
		observer.allowedMetadataKeys = keys
	}
}

// WithPrincipalClaims selects the validated claims copied into a principal's
// attributes. Each attribute name maps to an ordered list of claim paths; the
// first one holding a non-empty string wins. A path names a top-level claim
// or, with dots, a claim nested in objects ("organization.id"). By default
// no claims are copied.
func WithPrincipalClaims(claims map[string][]string) Option {
	return func(observer *Observer) {
		observer.principalClaims = claims
	}
}

// WithTokenTypes sets the token types the deployment can issue. Only these
// are named in resource.token_types and resource.requested_token_types; any
// other requested type is recorded as UnrecognizedTokenType, because on the
// token exchange path it is a client-supplied string.
func WithTokenTypes(tokenTypes []service.TokenType) Option {
	return func(observer *Observer) {
		observer.tokenTypes = make(map[service.TokenType]bool, len(tokenTypes))
		for _, tokenType := range tokenTypes {
			observer.tokenTypes[tokenType] = true
		}
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
	ID             string            `json:"id,omitempty"`
	TrustDomain    string            `json:"trust_domain,omitempty"`
	CredentialType string            `json:"credential_type,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	// Validation is the result of validating this principal's credential.
	// It is absent when the credential was never validated.
	Validation *principalValidation `json:"validation,omitempty"`
}

type principalValidation struct {
	Outcome    AuditOutcome `json:"outcome"`
	ReasonCode string       `json:"reason_code,omitempty"`
}

type requestInfo struct {
	Protocol string `json:"protocol"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
}

type resourceInfo struct {
	Type                 string               `json:"type"`
	TokenTypes           []string             `json:"token_types,omitempty"`
	RequestedTokenTypes  []string             `json:"requested_token_types,omitempty"`
	CacheLayers          []request.CacheLayer `json:"cache_layers,omitempty"`
	FailedComponent      string               `json:"failed_component,omitempty"`
	SignalsDropped       int                  `json:"signals_dropped,omitempty"`
	SignalsRejected      int                  `json:"signals_rejected,omitempty"`
	MetadataKeysStripped int                  `json:"metadata_keys_stripped,omitempty"`
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
	state     *request.AuditState
	collector *auditctx.Collector

	// Callback state for reason derivation (set by probe methods)
	subjectAnonymous          bool
	subjectExtractionFailed   bool
	subjectValidated          bool
	subjectValidationErr      error
	subjectOutagesAtStart     uint64
	subjectDependencyOutage   bool
	actorExtractionFailed     bool
	actorValidated            bool
	actorValidationErr        error
	actorOutagesAtStart       uint64
	actorDependencyOutage     bool
	policyDenied              bool
	policyEvalErr             error
	policyAllowed             bool
	policyIssue               bool
	requestContextParseFailed bool
	tokenIssuanceFailed       bool
	tokenIssuanceDenied       bool
	issuanceDenialReason      string
	tokenIssued               bool
	invalidRequestErr         error
	tokenTypes                []service.TokenType
	requestedTokenTypes       []service.TokenType
}

// Each audit observer keeps its own request probe, so nested issuance
// callbacks update only that observer's request and no audit state is needed
// in application handlers. The AuditState and signal Reporter are stored
// under shared context keys: composing more than one audit observer is not
// supported, because nested cache, dependency and script signals would all
// reach the last one started.
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
	if denial != nil && denial.Classification != "" {
		// Preserve the individual policy decision even if another token type
		// later fails and changes the terminal request outcome. A label that
		// is not a core reason code is the deployment's own classification.
		signal := auditctx.Signal{
			Source: auditctx.SourcePolicy, Operation: "token_issuance",
			Outcome: auditctx.OutcomeDenied, ReasonCode: denial.Classification,
		}
		if !ValidReasonCode(denial.Classification) {
			signal.ReasonCode = auditctx.ReasonTokenIssuanceDenied
			signal.Classification = denial.Classification
		}
		p.request.collector.Record(signal)
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
	p.actorOutagesAtStart = p.state.DependencyOutages()
	if credential != nil {
		p.actor.CredentialType = string(credential.Type())
	}
}

func (p *requestProbe) SubjectCredentialExtracted(credential trust.Credential, _ []string) {
	p.subjectOutagesAtStart = p.state.DependencyOutages()
	if credential != nil {
		p.subject.CredentialType = string(credential.Type())
	}
}

func (p *requestProbe) ActorValidationSucceeded(result *trust.Result) {
	p.actorValidated = true
	p.observer.fillPrincipal(&p.actor, result)
}

func (p *requestProbe) ActorCredentialExtractionFailed(error) { p.actorExtractionFailed = true }
func (p *requestProbe) ActorValidationFailed(err error) {
	p.actorValidationErr = err
	p.actorDependencyOutage = p.state.DependencyOutages() > p.actorOutagesAtStart
}

func (p *requestProbe) SubjectValidationSucceeded(result *trust.Result) {
	p.subjectValidated = true
	p.observer.fillPrincipal(&p.subject, result)
}

func (p *requestProbe) SubjectCredentialExtractionFailed(error) {
	p.subjectExtractionFailed = true
}

func (p *requestProbe) SubjectValidationFailed(err error) {
	p.subjectValidationErr = err
	p.subjectDependencyOutage = p.state.DependencyOutages() > p.subjectOutagesAtStart
}

func (p *requestProbe) SubjectAnonymous() {
	p.subjectAnonymous = true
}

func (p *requestProbe) SubjectTokenValidationFailed(err error) {
	p.SubjectValidationFailed(err)
}

func (p *requestProbe) SubjectTokenValidationSucceeded(result *trust.Result) {
	p.subjectValidated = true
	p.observer.fillPrincipal(&p.subject, result)
}

func (p *requestProbe) RequestContextParseFailed(error) {
	p.requestContextParseFailed = true
}

func (p *requestProbe) PolicyDecisionDeny(string) {
	p.policyDenied = true
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

func (p *requestProbe) TokenIssued() { p.tokenIssued = true }

func (p *requestProbe) InvalidRequest(err error) {
	if err == nil {
		err = errors.New("invalid request")
	}
	p.invalidRequestErr = err
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
		return AuditOutcomeFailure, auditctx.ReasonTokenIssuanceFailed
	}
	if p.tokenIssuanceDenied {
		if p.issuanceDenialReason != "" {
			return AuditOutcomeDenied, p.issuanceDenialReason
		}
		return AuditOutcomeDenied, auditctx.ReasonTokenIssuanceDenied
	}

	// Success paths
	if p.policyAllowed || p.policyIssue || p.tokenIssued {
		return AuditOutcomeSuccess, ""
	}

	// Explicit deny
	if p.policyDenied {
		if p.subjectAnonymous {
			return AuditOutcomeDenied, auditctx.ReasonCredentialMissing
		}
		return AuditOutcomeDenied, auditctx.ReasonPolicyDenied
	}

	// Credential extraction failures
	if p.subjectExtractionFailed {
		return AuditOutcomeDenied, auditctx.ReasonCredentialMalformed
	}
	if p.actorExtractionFailed {
		return AuditOutcomeDenied, auditctx.ReasonCredentialMalformed
	}

	// Validation failures
	if p.subjectValidationErr != nil {
		return AuditOutcomeDenied, credentialFailureReason(p.subjectValidationErr)
	}
	if p.actorValidationErr != nil {
		return AuditOutcomeDenied, credentialFailureReason(p.actorValidationErr)
	}

	// Client errors on the token exchange path: the caller sent something
	// the server refuses. These are denials, not server failures.
	if p.invalidRequestErr != nil {
		if errors.Is(p.invalidRequestErr, service.ErrUnsupportedGrantType) {
			return AuditOutcomeDenied, auditctx.ReasonGrantTypeUnsupported
		}
		return AuditOutcomeDenied, auditctx.ReasonInvalidRequest
	}
	if p.requestContextParseFailed {
		return AuditOutcomeDenied, auditctx.ReasonInvalidRequest
	}

	// Policy evaluation error
	if p.policyEvalErr != nil {
		return AuditOutcomeFailure, auditctx.ReasonInternalError
	}

	// Either a server-side failure with no more specific callback
	// (RequestFailed), or no callback stated an outcome. Never report the
	// latter as a success: a handler exit that forgot its callback must show
	// up as a failure.
	return AuditOutcomeFailure, auditctx.ReasonInternalError
}

// credentialFailureReason classifies a credential validation error.
func credentialFailureReason(err error) string {
	if errors.Is(err, trust.ErrExpiredToken) {
		return auditctx.ReasonCredentialExpired
	}
	return auditctx.ReasonCredentialInvalid
}

// credentialValidation is a principal's own credential validation result.
// It is nil when the principal presented no credential (an anonymous
// principal is reported as validated, but nothing was checked), and when the
// credential was never validated because the request ended first. An outage
// observed during validation is a failed dependency, not a bad credential.
func credentialValidation(credentialType string, validated bool, validationErr error, dependencyOutage bool) *principalValidation {
	switch {
	case credentialType == "":
		return nil
	case validationErr != nil:
		reason := credentialFailureReason(validationErr)
		if dependencyOutage && reason == auditctx.ReasonCredentialInvalid {
			return &principalValidation{Outcome: AuditOutcomeFailure, ReasonCode: auditctx.ReasonDependencyFailure}
		}
		return &principalValidation{Outcome: AuditOutcomeDenied, ReasonCode: reason}
	case validated:
		return &principalValidation{Outcome: AuditOutcomeSuccess}
	}
	return nil
}

func (p *requestProbe) End() {
	outcome, reasonCode := p.deriveCompletion()

	cacheLayers, failureReason, failedComponent, _ := p.state.Snapshot()
	// token_issuance_failed is not replaced: a dependency may have failed
	// earlier and been tolerated, so it cannot be assumed to be the cause.
	// failed_component still names it.
	if outcome == AuditOutcomeFailure && (reasonCode == "" || reasonCode == auditctx.ReasonInternalError) && failureReason != "" {
		reasonCode = failureReason
	}
	// A real infrastructure outage (JWKS down, distributed cache failure)
	// overrides credential_invalid to failure/dependency_failure so that
	// bad signatures are not reported as outages.
	if (p.subjectDependencyOutage || p.actorDependencyOutage) && outcome == AuditOutcomeDenied && reasonCode == auditctx.ReasonCredentialInvalid {
		outcome = AuditOutcomeFailure
		reasonCode = auditctx.ReasonDependencyFailure
	}

	p.subject.Validation = credentialValidation(p.subject.CredentialType, p.subjectValidated, p.subjectValidationErr, p.subjectDependencyOutage)
	p.actor.Validation = credentialValidation(p.actor.CredentialType, p.actorValidated, p.actorValidationErr, p.actorDependencyOutage)
	requestJSON, _ := json.Marshal(p.request)
	subjectJSON, _ := json.Marshal(p.subject)
	actorJSON, _ := json.Marshal(p.actor)
	resourceJSON, _ := json.Marshal(resourceInfo{
		Type: resourceTypeForAction(p.action), TokenTypes: p.observer.safeTokenTypes(p.tokenTypes),
		RequestedTokenTypes: p.observer.safeTokenTypes(p.requestedTokenTypes), CacheLayers: cacheLayers,
		FailedComponent: failedComponent, SignalsDropped: p.collector.Dropped(),
		SignalsRejected: p.collector.Rejected(), MetadataKeysStripped: p.collector.StrippedKeys(),
	})

	name := p.observer.eventName("request")
	event := p.observer.event(outcome).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", p.action).
		Str("outcome", string(outcome)).
		Str("request_id", p.requestID).
		Int64("duration_ms", time.Since(p.started).Milliseconds()).
		RawJSON("service", p.observer.metaJSON).
		RawJSON("request", requestJSON).
		RawJSON("subject", subjectJSON).
		RawJSON("actor", actorJSON).
		RawJSON("resource", resourceJSON)
	if signals := p.collector.Signals(); len(signals) > 0 {
		signalsJSON, _ := json.Marshal(signals)
		event = event.RawJSON("signals", signalsJSON)
	}
	if reason := safeReasonCode(reasonCode); reason != "" {
		event = event.Str("reason_code", reason)
	}
	event.Msg(name)
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

func safeReasonCode(reason string) string {
	if reason == "" {
		return ""
	}
	if !ValidReasonCode(reason) {
		return auditctx.ReasonInternalError
	}
	return reason
}

// ValidReasonCode delegates to the shared implementation in internal/audit.
func ValidReasonCode(reason string) bool {
	return auditctx.ValidReasonCode(reason)
}

// UnrecognizedTokenType stands in for a token type no configured issuer
// handles. The type itself is not recorded: it can be arbitrary client input.
const UnrecognizedTokenType = "unrecognized"

// safeTokenTypes names the configured token types and replaces any other
// with UnrecognizedTokenType, so an unknown type is visible without being
// copied into the record.
func (o *Observer) safeTokenTypes(tokenTypes []service.TokenType) []string {
	var safe []string
	for _, tokenType := range tokenTypes {
		if o.tokenTypes[tokenType] {
			safe = append(safe, string(tokenType))
		} else {
			safe = append(safe, UnrecognizedTokenType)
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
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent("validator_distributed")
	p.state.SetDependencyOutage()
}
func (p *auditDistributedCacheProbe) ResultExpired() {
	p.state.RecordCacheLayer("validator_distributed", "expired")
}

type auditDataSourceCacheProbe struct {
	datasource.NoOpCacheFetchProbe
	state *request.AuditState
	layer string
}

func (o *Observer) CacheFetchStarted(ctx context.Context, name string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &auditDataSourceCacheProbe{
		state: request.AuditStateFrom(ctx),
		layer: "datasource:" + name,
	}
}
func (p *auditDataSourceCacheProbe) CacheHit()     { p.state.RecordCacheLayer(p.layer, "hit") }
func (p *auditDataSourceCacheProbe) CacheMiss()    { p.state.RecordCacheLayer(p.layer, "miss") }
func (p *auditDataSourceCacheProbe) CacheExpired() { p.state.RecordCacheLayer(p.layer, "expired") }

// FetchFailed follows the CacheMiss or CacheExpired already recorded for this
// lookup, so it adds no cache layer: the cache itself worked. The failure is
// carried by the reason and failed_component.
func (p *auditDataSourceCacheProbe) FetchFailed(error) {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent(p.layer)
}

type auditLuaFetchProbe struct {
	datasource.NoOpLuaFetchProbe
	state *request.AuditState
	name  string
}

func (o *Observer) LuaFetchStarted(ctx context.Context, name string) (context.Context, datasource.LuaFetchProbe) {
	return ctx, &auditLuaFetchProbe{state: request.AuditStateFrom(ctx), name: name}
}
func (p *auditLuaFetchProbe) ScriptLoadFailed(error) {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent(p.name)
}
func (p *auditLuaFetchProbe) ScriptExecutionFailed(error) {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent(p.name)
}
func (p *auditLuaFetchProbe) InvalidReturnType(string) {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent(p.name)
}
func (p *auditLuaFetchProbe) ResultConversionFailed(error) {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent(p.name)
}

// auditLuaValidateProbe marks a Lua validator that could not reach a verdict
// (script failed to load or run, or returned something unusable) as a failed
// dependency. A script that rejects the credential returns nil and reaches
// ValidationRejected instead, which stays a credential denial.
type auditLuaValidateProbe struct {
	trust.NoOpLuaValidateProbe
	state *request.AuditState
	name  string
}

func (o *Observer) LuaValidateStarted(ctx context.Context, name string) (context.Context, trust.LuaValidateProbe) {
	return ctx, &auditLuaValidateProbe{state: request.AuditStateFrom(ctx), name: "validator:" + name}
}

func (p *auditLuaValidateProbe) fault() {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent(p.name)
	p.state.SetDependencyOutage()
}
func (p *auditLuaValidateProbe) ScriptLoadFailed(error)       { p.fault() }
func (p *auditLuaValidateProbe) ScriptExecutionFailed(error)  { p.fault() }
func (p *auditLuaValidateProbe) InvalidReturnType(string)     { p.fault() }
func (p *auditLuaValidateProbe) ResultConversionFailed(error) { p.fault() }

type auditJWTProbe struct {
	trust.NoOpJWTValidateProbe
	state *request.AuditState
}

func (o *Observer) JWTValidateStarted(ctx context.Context, _ string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &auditJWTProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditJWTProbe) JWKSLookupFailed(error) {
	p.state.SetFailureReason(auditctx.ReasonDependencyFailure)
	p.state.SetFailedComponent("jwks")
	p.state.SetDependencyOutage()
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
	Type        string `json:"type"`
	KeyPosition string `json:"key_position,omitempty"`
	KeyName     string `json:"key_name,omitempty"`
}

type processConfig struct {
	TrustDomain string `json:"trust_domain,omitempty"`
	GRPCAddress string `json:"grpc_address,omitempty"`
	HTTPAddress string `json:"http_address,omitempty"`
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
	name := o.eventName("process_status")
	event := o.event(AuditOutcomeSuccess).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", "process_ready").
		Str("outcome", string(AuditOutcomeSuccess)).
		Int64("duration_ms", 0).
		Interface("service", o.meta).
		Interface("resource", lifecycleResource{Type: "process"}).
		Interface("configuration", processConfig{
			TrustDomain: safeValue(info.TrustDomain, 512),
			GRPCAddress: safeValue(info.GRPCAddress, 256),
			HTTPAddress: safeValue(info.HTTPAddress, 256),
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

func (p *auditStopProbe) ShutdownCompleted() {
	p.observer.emitLifecycle("process_status", "process_stop", AuditOutcomeSuccess, "", p.started, lifecycleResource{Type: "process"}, nil)
	p.emitted = true
}

func (p *auditStopProbe) ShutdownFailed() {
	p.observer.emitLifecycle("process_status", "process_stop", AuditOutcomeFailure, auditctx.ReasonInternalError, p.started, lifecycleResource{Type: "process"}, nil)
	p.emitted = true
}

func (p *auditStopProbe) End() {
	if !p.emitted {
		p.ShutdownFailed()
	}
}

type auditRotationProbe struct {
	keys.NoOpRotationCheckProbe
	observer *Observer
	started  time.Time
}

func (o *Observer) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	return ctx, &auditRotationProbe{observer: o, started: time.Now()}
}

func (p *auditRotationProbe) RotationCheckFailed(error) {
	p.observer.emitLifecycle("key_rotation", "key_rotate", AuditOutcomeFailure, auditctx.ReasonDependencyFailure, p.started, lifecycleResource{Type: "signing_key"}, nil)
}

func (p *auditRotationProbe) RotationCompleted(slot string) {
	p.observer.emitLifecycle("key_rotation", "key_rotate", AuditOutcomeSuccess, "", p.started, lifecycleResource{Type: "signing_key", KeyPosition: safeValue(slot, 64)}, nil)
}

func (p *auditRotationProbe) End() {}

type auditKMSProbe struct {
	keys.NoOpKMSRotateProbe
	observer *Observer
	started  time.Time
	keyName  string
}

// The key name identifies which signing key an event is about. Trust domain
// and namespace are not recorded here.
func (o *Observer) KMSRotateStarted(ctx context.Context, _, _, keyName string) (context.Context, keys.KMSRotateProbe) {
	return ctx, &auditKMSProbe{observer: o, started: time.Now(), keyName: safeValue(keyName, 256)}
}

func (p *auditKMSProbe) emit(action string, outcome AuditOutcome) {
	reason := ""
	if outcome == AuditOutcomeFailure {
		reason = auditctx.ReasonDependencyFailure
	}
	p.observer.emitLifecycle("key_rotation", action, outcome, reason, p.started, lifecycleResource{Type: "signing_key", KeyName: p.keyName}, nil)
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

func (o *Observer) fillPrincipal(dst *principal, result *trust.Result) {
	if result == nil {
		return
	}
	dst.ID = safeValue(result.Subject, 256)
	dst.TrustDomain = safeValue(result.TrustDomain, 512)
	dst.Attributes = nil
	for name, paths := range o.principalClaims {
		for _, path := range paths {
			if value := safeValue(stringClaim(result.Claims, path), 256); value != "" {
				if dst.Attributes == nil {
					dst.Attributes = make(map[string]string, len(o.principalClaims))
				}
				dst.Attributes[name] = value
				break
			}
		}
	}
}

// stringClaim returns the string claim at path: a top-level claim of that
// exact name, or else a claim nested in objects along its dot-separated
// segments. Anything that is not a string yields "".
func stringClaim(claims map[string]any, path string) string {
	if value, ok := claims[path].(string); ok {
		return value
	}
	var current any = claims
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[segment]
	}
	value, _ := current.(string)
	return value
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
