// Package audit implements security audit records with configurable event names.
package audit

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
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

	logger      zerolog.Logger
	meta        Metadata
	eventPrefix string
}

// Option configures an audit observer.
type Option func(*Observer)

// WithEventPrefix sets the prefix applied to every audit event name.
func WithEventPrefix(prefix string) Option {
	return func(observer *Observer) {
		observer.eventPrefix = prefix
	}
}

func New(logger zerolog.Logger, meta Metadata, options ...Option) *Observer {
	observer := &Observer{logger: logger, meta: meta, eventPrefix: DefaultEventPrefix}
	for _, option := range options {
		option(observer)
	}
	return observer
}

// ValidEventPrefix reports whether prefix is safe to include in log_type and event.
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

type responseInfo struct {
	GRPCCode   int32 `json:"grpc_code"`
	HTTPStatus int   `json:"http_status,omitempty"`
}

type resourceInfo struct {
	Type        string   `json:"type"`
	TokenTypes  []string `json:"token_types,omitempty"`
	CacheStatus string   `json:"cache_status,omitempty"`
}

type crossAccountInfo struct {
	TargetOrgID         string `json:"target_org_id,omitempty"`
	TargetAccountNumber string `json:"target_account_number,omitempty"`
}

type requestProbe struct {
	service.NoOpAuthzCheckProbe
	service.NoOpTokenExchangeProbe
	observer     *Observer
	requestID    string
	started      time.Time
	action       string
	request      requestInfo
	subject      principal
	actor        principal
	crossAccount crossAccountInfo
	completion   service.RequestCompletion
	completed    bool
	authorize    bool
	state        *request.AuditState
	cacheStatus  string
}

func (o *Observer) AuthzCheckStarted(ctx context.Context) (context.Context, service.AuthzCheckProbe) {
	ctx, state := request.WithAuditState(ctx)
	return ctx, &requestProbe{
		observer:  o,
		requestID: safeValue(request.ID(ctx), 128),
		started:   time.Now(),
		action:    "authorize",
		request:   requestInfo{Protocol: "ext_authz"},
		authorize: true,
		state:     state,
	}
}

func (o *Observer) TokenExchangeStarted(ctx context.Context, _, requestedTokenType, _, _ string) (context.Context, service.TokenExchangeProbe) {
	ctx, state := request.WithAuditState(ctx)
	p := &requestProbe{
		observer:  o,
		requestID: safeValue(request.ID(ctx), 128),
		started:   time.Now(),
		action:    "token_exchange",
		request:   requestInfo{Protocol: "grpc", Method: http.MethodPost, Path: "/v1/token"},
		state:     state,
	}
	if tokenType := safeValue(requestedTokenType, 256); tokenType != "" {
		p.completion.TokenTypes = []service.TokenType{service.TokenType(tokenType)}
	}
	return ctx, p
}

func (p *requestProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	if attrs == nil {
		return
	}
	p.request.Method = safeValue(attrs.Method, 32)
	p.request.Path = safePath(attrs.Path)
	p.request.SourceIP = safeValue(attrs.IPAddress, 64)
	p.crossAccount = crossAccountFromCookie(attrs.Headers)
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

func (p *requestProbe) ActorCredentialExtractionFailed(error) {}
func (p *requestProbe) ActorValidationFailed(error)           {}

func (p *requestProbe) SubjectValidationSucceeded(result *trust.Result) {
	fillPrincipal(&p.subject, result)
}

func (p *requestProbe) SubjectTokenValidationSucceeded(result *trust.Result) {
	fillPrincipal(&p.subject, result)
}

func (p *requestProbe) RequestCompleted(completion service.RequestCompletion) {
	p.completion = completion
	p.completed = true
}

func (p *requestProbe) End() {
	if !p.completed {
		p.completion = service.RequestCompletion{Outcome: service.AuditOutcomeFailure, ReasonCode: ReasonInternalError}
	}
	cacheStatus, failureReason := p.state.Snapshot()
	if p.completion.Outcome == service.AuditOutcomeFailure && (p.completion.ReasonCode == "" || p.completion.ReasonCode == ReasonInternalError) && failureReason != "" {
		p.completion.ReasonCode = failureReason
	}
	p.cacheStatus = cacheStatus
	p.emit("request")

	if p.crossAccount.TargetOrgID != "" || p.crossAccount.TargetAccountNumber != "" {
		p.emit("rbac_cross_access_audit")
	}
	if p.authorize {
		p.emit("authorize")
	}
	if p.subject.CredentialType == string(trust.CredentialTypeMTLS) || p.subject.CredentialType == string(trust.CredentialTypeForwardedClientCert) {
		p.emit("validate_ssl_cert")
	}
	if p.actor.CredentialType == string(trust.CredentialTypeHeader) {
		p.emit("verify_psk")
	}
	switch p.completion.ReasonCode {
	case ReasonComplianceDenied:
		p.emit("auth_compliance_failure")
	case ReasonComplianceFailure:
		p.emit("compliance_failure")
	case ReasonSupplementalFailure:
		p.emit("supplemental_user_data_failure")
	case ReasonDependencyFailure:
		p.emit("dependency_failure")
	}
}

func (p *requestProbe) emit(suffix string) {
	name := p.observer.eventName(suffix)
	completion := p.completion
	reason := safeReasonCode(completion.ReasonCode)
	tokenTypes := make([]string, 0, len(completion.TokenTypes))
	for _, tokenType := range completion.TokenTypes {
		if value := safeTokenType(tokenType); value != "" {
			tokenTypes = append(tokenTypes, value)
		}
	}

	event := p.observer.event(completion.Outcome).
		Str("log_type", name).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", p.action).
		Str("outcome", string(completion.Outcome)).
		Str("request_id", p.requestID).
		Int64("duration_ms", time.Since(p.started).Milliseconds()).
		Interface("service", p.observer.meta).
		Interface("request", p.request).
		Interface("subject", p.subject).
		Interface("actor", p.actor).
		Interface("resource", resourceInfo{Type: "authorization_request", TokenTypes: tokenTypes, CacheStatus: p.cacheStatus}).
		Interface("response", responseInfo{GRPCCode: completion.GRPCCode, HTTPStatus: completion.HTTPStatus})
	if reason != "" {
		event = event.Str("reason_code", reason)
	}
	if p.crossAccount.TargetOrgID != "" || p.crossAccount.TargetAccountNumber != "" {
		event = event.Interface("cross_account", p.crossAccount)
	}
	event.Msg("security audit event")
}

func safeReasonCode(reason string) string {
	switch reason {
	case ReasonInvalidRequest, ReasonGrantTypeUnsupported,
		ReasonCredentialMissing, ReasonCredentialMalformed, ReasonCredentialInvalid,
		ReasonCredentialExpired, ReasonSchemeNotAllowed, ReasonPolicyDenied,
		ReasonComplianceDenied, ReasonComplianceFailure, ReasonSupplementalFailure,
		ReasonDependencyFailure, ReasonInternalError, ReasonTokenIssuanceFailed,
		ReasonTokenIssuanceDenied:
		return reason
	case "":
		return ""
	default:
		return ReasonInternalError
	}
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

type auditInMemoryCacheProbe struct {
	trust.NoOpInMemoryValidateProbe
	state *request.AuditState
}

func (o *Observer) InMemoryValidateStarted(ctx context.Context, _ string) (context.Context, trust.InMemoryValidateProbe) {
	return ctx, &auditInMemoryCacheProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditInMemoryCacheProbe) CacheHit()     { p.state.SetCacheStatus("hit") }
func (p *auditInMemoryCacheProbe) CacheMiss()    { p.state.SetCacheStatus("miss") }
func (p *auditInMemoryCacheProbe) CacheExpired() { p.state.SetCacheStatus("expired") }
func (p *auditInMemoryCacheProbe) SourceFailed(error) {
	p.state.SetFailureReason(ReasonDependencyFailure)
}

type auditDistributedCacheProbe struct {
	trust.NoOpDistributedValidateProbe
	state *request.AuditState
}

func (o *Observer) DistributedValidateStarted(ctx context.Context, _ string) (context.Context, trust.DistributedValidateProbe) {
	return ctx, &auditDistributedCacheProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditDistributedCacheProbe) GetFailed(error) {
	p.state.SetCacheStatus("failure")
	p.state.SetFailureReason(ReasonDependencyFailure)
}
func (p *auditDistributedCacheProbe) ResultExpired() { p.state.SetCacheStatus("expired") }

type auditDataSourceCacheProbe struct {
	datasource.NoOpCacheFetchProbe
	state         *request.AuditState
	failureReason string
}

func (o *Observer) CacheFetchStarted(ctx context.Context, name string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &auditDataSourceCacheProbe{state: request.AuditStateFrom(ctx), failureReason: dependencyReason(name)}
}
func (p *auditDataSourceCacheProbe) CacheHit()     { p.state.SetCacheStatus("hit") }
func (p *auditDataSourceCacheProbe) CacheMiss()    { p.state.SetCacheStatus("miss") }
func (p *auditDataSourceCacheProbe) CacheExpired() { p.state.SetCacheStatus("expired") }
func (p *auditDataSourceCacheProbe) FetchFailed(error) {
	p.state.SetCacheStatus("failure")
	p.state.SetFailureReason(p.failureReason)
}

type auditLuaFetchProbe struct {
	datasource.NoOpLuaFetchProbe
	state         *request.AuditState
	failureReason string
}

func (o *Observer) LuaFetchStarted(ctx context.Context, name string) (context.Context, datasource.LuaFetchProbe) {
	return ctx, &auditLuaFetchProbe{state: request.AuditStateFrom(ctx), failureReason: dependencyReason(name)}
}
func (p *auditLuaFetchProbe) ScriptLoadFailed(error)       { p.state.SetFailureReason(p.failureReason) }
func (p *auditLuaFetchProbe) ScriptExecutionFailed(error)  { p.state.SetFailureReason(p.failureReason) }
func (p *auditLuaFetchProbe) InvalidReturnType(string)     { p.state.SetFailureReason(p.failureReason) }
func (p *auditLuaFetchProbe) ResultConversionFailed(error) { p.state.SetFailureReason(p.failureReason) }

type auditJWTProbe struct {
	trust.NoOpJWTValidateProbe
	state *request.AuditState
}

func (o *Observer) JWTValidateStarted(ctx context.Context, _ string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &auditJWTProbe{state: request.AuditStateFrom(ctx)}
}
func (p *auditJWTProbe) JWKSLookupFailed(error) {
	p.state.SetFailureReason(ReasonDependencyFailure)
}

func dependencyReason(name string) string {
	name = strings.ToLower(name)
	if strings.Contains(name, "compliance") {
		return ReasonComplianceFailure
	}
	if strings.Contains(name, "supplemental") || strings.Contains(name, "backoffice") || strings.Contains(name, "bop") {
		return ReasonSupplementalFailure
	}
	return ReasonDependencyFailure
}

func (o *Observer) event(outcome service.AuditOutcome) *zerolog.Event {
	switch outcome {
	case service.AuditOutcomeDenied:
		return o.logger.Warn().Timestamp()
	case service.AuditOutcomeFailure:
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

func (o *Observer) emitLifecycle(suffix, action string, outcome service.AuditOutcome, reason string, started time.Time, resource lifecycleResource, config any) {
	name := o.eventName(suffix)
	event := o.event(outcome).
		Str("log_type", name).
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
	event.Msg("security audit event")
}

func (o *Observer) ProcessReady(info server.ProcessInfo) {
	meta := o.meta
	if meta.ServiceVersion == "" {
		meta.ServiceVersion = safeValue(info.Version, 128)
	}
	name := o.eventName("process_status")
	event := o.event(service.AuditOutcomeSuccess).
		Str("log_type", name).
		Str("event", name).
		Str("schema_version", SchemaVersion).
		Str("action", "process_ready").
		Str("outcome", string(service.AuditOutcomeSuccess)).
		Int64("duration_ms", 0).
		Interface("service", meta).
		Interface("resource", lifecycleResource{Type: "process"}).
		Interface("configuration", processConfig{
			TrustDomain: safeValue(info.TrustDomain, 512),
			GRPCAddress: safeValue(info.GRPCAddress, 256),
			HTTPAddress: safeValue(info.HTTPAddress, 256),
			Commit:      safeValue(info.Commit, 128),
		})
	event.Msg("security audit event")
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
	p.observer.emitLifecycle("process_status", "process_stop", service.AuditOutcomeSuccess, "", p.started, lifecycleResource{Type: "process", InterruptedRequests: int64Pointer(interrupted)}, nil)
	p.emitted = true
}

func (p *auditStopProbe) ShutdownFailed(interrupted int64) {
	p.observer.emitLifecycle("process_status", "process_stop", service.AuditOutcomeFailure, ReasonInternalError, p.started, lifecycleResource{Type: "process", InterruptedRequests: int64Pointer(interrupted)}, nil)
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
	p.observer.emitLifecycle("key_rotation", "key_rotate", service.AuditOutcomeFailure, ReasonDependencyFailure, p.started, lifecycleResource{Type: "signing_key"}, nil)
	p.emitted = true
}

func (p *auditRotationProbe) RotationCompleted(slot string) {
	p.observer.emitLifecycle("key_rotation", "key_rotate", service.AuditOutcomeSuccess, "", p.started, lifecycleResource{Type: "signing_key", KeyPosition: safeValue(slot, 64)}, nil)
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

func (p *auditKMSProbe) emit(action string, outcome service.AuditOutcome) {
	reason := ""
	if outcome == service.AuditOutcomeFailure {
		reason = ReasonDependencyFailure
	}
	p.observer.emitLifecycle("key_rotation", action, outcome, reason, p.started, lifecycleResource{Type: "signing_key"}, nil)
}

func (p *auditKMSProbe) KeyCreated()           { p.emit("key_create", service.AuditOutcomeSuccess) }
func (p *auditKMSProbe) CreateKeyFailed(error) { p.emit("key_create", service.AuditOutcomeFailure) }
func (p *auditKMSProbe) AliasChanged(created bool) {
	action := "key_alias_update"
	if created {
		action = "key_alias_create"
	}
	p.emit(action, service.AuditOutcomeSuccess)
}
func (p *auditKMSProbe) AliasCheckFailed(error) {
	p.emit("key_alias_change", service.AuditOutcomeFailure)
}
func (p *auditKMSProbe) AliasUpdateFailed(error) {
	p.emit("key_alias_change", service.AuditOutcomeFailure)
}
func (p *auditKMSProbe) DeletionScheduled() {
	p.emit("key_deletion_schedule", service.AuditOutcomeSuccess)
}
func (p *auditKMSProbe) OldKeyDeletionFailed(string, error) {
	p.emit("key_deletion_schedule", service.AuditOutcomeFailure)
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
	if value == "" || len(value) > max {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return value
}

func crossAccountFromCookie(headers map[string]string) crossAccountInfo {
	if len(headers) == 0 {
		return crossAccountInfo{}
	}
	cookieHeader := headers["cookie"]
	if cookieHeader == "" {
		cookieHeader = headers["Cookie"]
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return crossAccountInfo{}
	}
	var result crossAccountInfo
	for _, cookie := range cookies {
		switch cookie.Name {
		case "cross_access_org_id":
			result.TargetOrgID = safeValue(cookie.Value, 256)
		case "cross_access_account_number":
			result.TargetAccountNumber = safeValue(cookie.Value, 256)
		}
	}
	return result
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
