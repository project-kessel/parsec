package observer

import (
	"context"
	"errors"
	"net/http"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// CompositeAll builds an Observer that fans out every call to all children.
//
// The composite*Probe types below are intentionally repetitive: each mirrors a
// domain probe interface with the same for-range fan-out. That keeps the
// implementation obvious and lets var _ Observer = (*compositeAll)(nil) catch
// interface drift. Shrinking this file would likely mean codegen, not shared
// reflection helpers.
func CompositeAll(children []Observer) Observer {
	if len(children) == 1 {
		return children[0]
	}
	return &compositeAll{children: children}
}

type compositeAll struct {
	children []Observer
}

// --- probe factories: each creates probes from all children and wraps them ---

func (c *compositeAll) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []service.TokenType,
) (context.Context, service.TokenIssuanceProbe) {
	probes := make([]service.TokenIssuanceProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.TokenIssuanceStarted(ctx, subject, actor, scope, tokenTypes)
	}
	return ctx, &compositeTokenIssuanceProbe{probes: probes}
}

func (c *compositeAll) TokenExchangeStarted(
	ctx context.Context,
	grantType string,
	requestedTokenType string,
	audience string,
	scope string,
) (context.Context, service.TokenExchangeProbe) {
	probes := make([]service.TokenExchangeProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.TokenExchangeStarted(ctx, grantType, requestedTokenType, audience, scope)
	}
	return ctx, &compositeTokenExchangeProbe{probes: probes}
}

func (c *compositeAll) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, service.AuthzCheckProbe) {
	probes := make([]service.AuthzCheckProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.AuthzCheckStarted(ctx)
	}
	return ctx, &compositeAuthzCheckProbe{probes: probes}
}

func (c *compositeAll) CacheFetchStarted(ctx context.Context, name string) (context.Context, datasource.CacheFetchProbe) {
	probes := make([]datasource.CacheFetchProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.CacheFetchStarted(ctx, name)
	}
	return ctx, &compositeCacheFetchProbe{probes}
}

func (c *compositeAll) LuaFetchStarted(ctx context.Context, name string) (context.Context, datasource.LuaFetchProbe) {
	probes := make([]datasource.LuaFetchProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.LuaFetchStarted(ctx, name)
	}
	return ctx, &compositeLuaFetchProbe{probes}
}

func (c *compositeAll) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	probes := make([]keys.RotationCheckProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.RotationCheckStarted(ctx)
	}
	return ctx, &compositeRotationCheckProbe{probes}
}

func (c *compositeAll) KeyCacheUpdateStarted(ctx context.Context) (context.Context, keys.KeyCacheUpdateProbe) {
	probes := make([]keys.KeyCacheUpdateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.KeyCacheUpdateStarted(ctx)
	}
	return ctx, &compositeKeyCacheUpdateProbe{probes}
}

func (c *compositeAll) KMSRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, keys.KMSRotateProbe) {
	probes := make([]keys.KMSRotateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.KMSRotateStarted(ctx, trustDomain, namespace, keyName)
	}
	return ctx, &compositeKMSRotateProbe{probes}
}

func (c *compositeAll) DiskRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, keys.DiskRotateProbe) {
	probes := make([]keys.DiskRotateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.DiskRotateStarted(ctx, trustDomain, namespace, keyName)
	}
	return ctx, &compositeDiskRotateProbe{probes}
}

func (c *compositeAll) MemoryRotateStarted(ctx context.Context) (context.Context, keys.MemoryRotateProbe) {
	probes := make([]keys.MemoryRotateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.MemoryRotateStarted(ctx)
	}
	return ctx, &compositeMemoryRotateProbe{probes}
}

func (c *compositeAll) ValidationStarted(ctx context.Context) (context.Context, trust.ValidationProbe) {
	probes := make([]trust.ValidationProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.ValidationStarted(ctx)
	}
	return ctx, &compositeValidationProbe{probes}
}

func (c *compositeAll) ForActorStarted(ctx context.Context) (context.Context, trust.ForActorProbe) {
	probes := make([]trust.ForActorProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.ForActorStarted(ctx)
	}
	return ctx, &compositeForActorProbe{probes}
}

func (c *compositeAll) JWTValidateStarted(ctx context.Context, issuer string) (context.Context, trust.JWTValidateProbe) {
	probes := make([]trust.JWTValidateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.JWTValidateStarted(ctx, issuer)
	}
	return ctx, &compositeJWTValidateProbe{probes}
}

func (c *compositeAll) LuaValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.LuaValidateProbe) {
	probes := make([]trust.LuaValidateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.LuaValidateStarted(ctx, validatorName)
	}
	return ctx, &compositeLuaValidateProbe{probes}
}

func (c *compositeAll) InMemoryValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.InMemoryValidateProbe) {
	probes := make([]trust.InMemoryValidateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.InMemoryValidateStarted(ctx, validatorName)
	}
	return ctx, &compositeInMemoryValidateProbe{probes}
}

func (c *compositeAll) DistributedValidateStarted(ctx context.Context, validatorName string) (context.Context, trust.DistributedValidateProbe) {
	probes := make([]trust.DistributedValidateProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.DistributedValidateStarted(ctx, validatorName)
	}
	return ctx, &compositeDistributedValidateProbe{probes}
}

func (c *compositeAll) InitPopulationStarted(ctx context.Context) (context.Context, server.InitPopulationProbe) {
	probes := make([]server.InitPopulationProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.InitPopulationStarted(ctx)
	}
	return ctx, &compositeInitPopulationProbe{probes}
}

func (c *compositeAll) CacheRefreshStarted(ctx context.Context) (context.Context, server.CacheRefreshProbe) {
	probes := make([]server.CacheRefreshProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.CacheRefreshStarted(ctx)
	}
	return ctx, &compositeCacheRefreshProbe{probes}
}

func (c *compositeAll) GRPCServeFailed(err error) {
	for _, ch := range c.children {
		ch.GRPCServeFailed(err)
	}
}

func (c *compositeAll) HTTPServeFailed(err error) {
	for _, ch := range c.children {
		ch.HTTPServeFailed(err)
	}
}

func (c *compositeAll) StopStarted(ctx context.Context) (context.Context, server.StopProbe) {
	probes := make([]server.StopProbe, len(c.children))
	for i, ch := range c.children {
		ctx, probes[i] = ch.StopStarted(ctx)
	}
	return ctx, &compositeStopProbe{probes}
}

func (c *compositeAll) Shutdown(ctx context.Context) error {
	var errs []error
	for _, ch := range c.children {
		if err := ch.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *compositeAll) ConfigureHTTPMux(mux *http.ServeMux) {
	for _, ch := range c.children {
		ch.ConfigureHTTPMux(mux)
	}
}

// --- composite probes: fan out each event to all children ---

type compositeCacheFetchProbe struct {
	probes []datasource.CacheFetchProbe
}

func (m *compositeCacheFetchProbe) CacheHit() {
	for _, p := range m.probes {
		p.CacheHit()
	}
}
func (m *compositeCacheFetchProbe) CacheMiss() {
	for _, p := range m.probes {
		p.CacheMiss()
	}
}
func (m *compositeCacheFetchProbe) CacheExpired() {
	for _, p := range m.probes {
		p.CacheExpired()
	}
}
func (m *compositeCacheFetchProbe) FetchFailed(err error) {
	for _, p := range m.probes {
		p.FetchFailed(err)
	}
}
func (m *compositeCacheFetchProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeLuaFetchProbe struct {
	probes []datasource.LuaFetchProbe
}

func (m *compositeLuaFetchProbe) ScriptLoadFailed(err error) {
	for _, p := range m.probes {
		p.ScriptLoadFailed(err)
	}
}
func (m *compositeLuaFetchProbe) ScriptExecutionFailed(err error) {
	for _, p := range m.probes {
		p.ScriptExecutionFailed(err)
	}
}
func (m *compositeLuaFetchProbe) InvalidReturnType(got string) {
	for _, p := range m.probes {
		p.InvalidReturnType(got)
	}
}
func (m *compositeLuaFetchProbe) FetchCompleted() {
	for _, p := range m.probes {
		p.FetchCompleted()
	}
}
func (m *compositeLuaFetchProbe) FetchCompletedNil() {
	for _, p := range m.probes {
		p.FetchCompletedNil()
	}
}
func (m *compositeLuaFetchProbe) ResultConversionFailed(err error) {
	for _, p := range m.probes {
		p.ResultConversionFailed(err)
	}
}
func (m *compositeLuaFetchProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeRotationCheckProbe struct{ probes []keys.RotationCheckProbe }

func (m *compositeRotationCheckProbe) RotationCheckFailed(err error) {
	for _, p := range m.probes {
		p.RotationCheckFailed(err)
	}
}
func (m *compositeRotationCheckProbe) RotationCompleted(slot string) {
	for _, p := range m.probes {
		p.RotationCompleted(slot)
	}
}
func (m *compositeRotationCheckProbe) RotationSkippedVersionRace(slot string) {
	for _, p := range m.probes {
		p.RotationSkippedVersionRace(slot)
	}
}
func (m *compositeRotationCheckProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeKeyCacheUpdateProbe struct{ probes []keys.KeyCacheUpdateProbe }

func (m *compositeKeyCacheUpdateProbe) KeyCacheUpdateFailed(err error) {
	for _, p := range m.probes {
		p.KeyCacheUpdateFailed(err)
	}
}
func (m *compositeKeyCacheUpdateProbe) KeyProviderNotFound(prov, slot string) {
	for _, p := range m.probes {
		p.KeyProviderNotFound(prov, slot)
	}
}
func (m *compositeKeyCacheUpdateProbe) KeyHandleFailed(slot string, err error) {
	for _, p := range m.probes {
		p.KeyHandleFailed(slot, err)
	}
}
func (m *compositeKeyCacheUpdateProbe) PublicKeyFailed(slot string, err error) {
	for _, p := range m.probes {
		p.PublicKeyFailed(slot, err)
	}
}
func (m *compositeKeyCacheUpdateProbe) ThumbprintFailed(slot string, err error) {
	for _, p := range m.probes {
		p.ThumbprintFailed(slot, err)
	}
}
func (m *compositeKeyCacheUpdateProbe) MetadataFailed(slot string, err error) {
	for _, p := range m.probes {
		p.MetadataFailed(slot, err)
	}
}
func (m *compositeKeyCacheUpdateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeKMSRotateProbe struct{ probes []keys.KMSRotateProbe }

func (m *compositeKMSRotateProbe) CreateKeyFailed(err error) {
	for _, p := range m.probes {
		p.CreateKeyFailed(err)
	}
}
func (m *compositeKMSRotateProbe) AliasCheckFailed(err error) {
	for _, p := range m.probes {
		p.AliasCheckFailed(err)
	}
}
func (m *compositeKMSRotateProbe) AliasUpdateFailed(err error) {
	for _, p := range m.probes {
		p.AliasUpdateFailed(err)
	}
}
func (m *compositeKMSRotateProbe) OldKeyDeletionFailed(keyID string, err error) {
	for _, p := range m.probes {
		p.OldKeyDeletionFailed(keyID, err)
	}
}
func (m *compositeKMSRotateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeDiskRotateProbe struct{ probes []keys.DiskRotateProbe }

func (m *compositeDiskRotateProbe) KeyGenerationFailed(err error) {
	for _, p := range m.probes {
		p.KeyGenerationFailed(err)
	}
}
func (m *compositeDiskRotateProbe) KeyWriteFailed(err error) {
	for _, p := range m.probes {
		p.KeyWriteFailed(err)
	}
}
func (m *compositeDiskRotateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeMemoryRotateProbe struct{ probes []keys.MemoryRotateProbe }

func (m *compositeMemoryRotateProbe) KeyGenerationFailed(err error) {
	for _, p := range m.probes {
		p.KeyGenerationFailed(err)
	}
}
func (m *compositeMemoryRotateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeValidationProbe struct{ probes []trust.ValidationProbe }

func (m *compositeValidationProbe) ValidatorFailed(name string, ct trust.CredentialType, err error) {
	for _, p := range m.probes {
		p.ValidatorFailed(name, ct, err)
	}
}
func (m *compositeValidationProbe) AllValidatorsFailed(ct trust.CredentialType, n int, err error) {
	for _, p := range m.probes {
		p.AllValidatorsFailed(ct, n, err)
	}
}
func (m *compositeValidationProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeForActorProbe struct{ probes []trust.ForActorProbe }

func (m *compositeForActorProbe) ValidatorFiltered(name, actor string) {
	for _, p := range m.probes {
		p.ValidatorFiltered(name, actor)
	}
}
func (m *compositeForActorProbe) FilterEvaluationFailed(name string, err error) {
	for _, p := range m.probes {
		p.FilterEvaluationFailed(name, err)
	}
}
func (m *compositeForActorProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeJWTValidateProbe struct{ probes []trust.JWTValidateProbe }

func (m *compositeJWTValidateProbe) JWKSLookupFailed(err error) {
	for _, p := range m.probes {
		p.JWKSLookupFailed(err)
	}
}
func (m *compositeJWTValidateProbe) TokenExpired() {
	for _, p := range m.probes {
		p.TokenExpired()
	}
}
func (m *compositeJWTValidateProbe) TokenInvalid(err error) {
	for _, p := range m.probes {
		p.TokenInvalid(err)
	}
}
func (m *compositeJWTValidateProbe) ClaimsExtractionFailed(err error) {
	for _, p := range m.probes {
		p.ClaimsExtractionFailed(err)
	}
}
func (m *compositeJWTValidateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeLuaValidateProbe struct{ probes []trust.LuaValidateProbe }

func (m *compositeLuaValidateProbe) ScriptLoadFailed(err error) {
	for _, p := range m.probes {
		p.ScriptLoadFailed(err)
	}
}
func (m *compositeLuaValidateProbe) ScriptExecutionFailed(err error) {
	for _, p := range m.probes {
		p.ScriptExecutionFailed(err)
	}
}
func (m *compositeLuaValidateProbe) InvalidReturnType(got string) {
	for _, p := range m.probes {
		p.InvalidReturnType(got)
	}
}
func (m *compositeLuaValidateProbe) TokenInvalid(err error) {
	for _, p := range m.probes {
		p.TokenInvalid(err)
	}
}
func (m *compositeLuaValidateProbe) ValidationRejected() {
	for _, p := range m.probes {
		p.ValidationRejected()
	}
}
func (m *compositeLuaValidateProbe) ResultConversionFailed(err error) {
	for _, p := range m.probes {
		p.ResultConversionFailed(err)
	}
}
func (m *compositeLuaValidateProbe) ValidationCompleted() {
	for _, p := range m.probes {
		p.ValidationCompleted()
	}
}
func (m *compositeLuaValidateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeInMemoryValidateProbe struct {
	probes []trust.InMemoryValidateProbe
}

func (m *compositeInMemoryValidateProbe) CacheKeyFailed(err error) {
	for _, p := range m.probes {
		p.CacheKeyFailed(err)
	}
}
func (m *compositeInMemoryValidateProbe) CacheHit() {
	for _, p := range m.probes {
		p.CacheHit()
	}
}
func (m *compositeInMemoryValidateProbe) CacheExpired() {
	for _, p := range m.probes {
		p.CacheExpired()
	}
}
func (m *compositeInMemoryValidateProbe) CacheMiss() {
	for _, p := range m.probes {
		p.CacheMiss()
	}
}
func (m *compositeInMemoryValidateProbe) SourceFailed(err error) {
	for _, p := range m.probes {
		p.SourceFailed(err)
	}
}
func (m *compositeInMemoryValidateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeDistributedValidateProbe struct {
	probes []trust.DistributedValidateProbe
}

func (m *compositeDistributedValidateProbe) CacheKeyFailed(err error) {
	for _, p := range m.probes {
		p.CacheKeyFailed(err)
	}
}
func (m *compositeDistributedValidateProbe) GetFailed(err error) {
	for _, p := range m.probes {
		p.GetFailed(err)
	}
}
func (m *compositeDistributedValidateProbe) ResultExpired() {
	for _, p := range m.probes {
		p.ResultExpired()
	}
}
func (m *compositeDistributedValidateProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeInitPopulationProbe struct{ probes []server.InitPopulationProbe }

func (m *compositeInitPopulationProbe) InitialCachePopulationFailed(err error) {
	for _, p := range m.probes {
		p.InitialCachePopulationFailed(err)
	}
}
func (m *compositeInitPopulationProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeCacheRefreshProbe struct{ probes []server.CacheRefreshProbe }

func (m *compositeCacheRefreshProbe) CacheRefreshFailed(err error) {
	for _, p := range m.probes {
		p.CacheRefreshFailed(err)
	}
}
func (m *compositeCacheRefreshProbe) KeyConversionFailed(keyID string, err error) {
	for _, p := range m.probes {
		p.KeyConversionFailed(keyID, err)
	}
}
func (m *compositeCacheRefreshProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeStopProbe struct{ probes []server.StopProbe }

func (m *compositeStopProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeTokenIssuanceProbe struct {
	probes []service.TokenIssuanceProbe
}

func (m *compositeTokenIssuanceProbe) TokenTypeIssuanceStarted(tokenType service.TokenType) {
	for _, p := range m.probes {
		p.TokenTypeIssuanceStarted(tokenType)
	}
}

func (m *compositeTokenIssuanceProbe) TokenTypeIssuanceSucceeded(tokenType service.TokenType, token *service.Token) {
	for _, p := range m.probes {
		p.TokenTypeIssuanceSucceeded(tokenType, token)
	}
}

func (m *compositeTokenIssuanceProbe) TokenTypeIssuanceFailed(tokenType service.TokenType, err error) {
	for _, p := range m.probes {
		p.TokenTypeIssuanceFailed(tokenType, err)
	}
}

func (m *compositeTokenIssuanceProbe) IssuerNotFound(tokenType service.TokenType, err error) {
	for _, p := range m.probes {
		p.IssuerNotFound(tokenType, err)
	}
}

func (m *compositeTokenIssuanceProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeTokenExchangeProbe struct {
	probes []service.TokenExchangeProbe
}

func (m *compositeTokenExchangeProbe) ActorCredentialExtracted(cred trust.Credential, headersUsed []string) {
	for _, p := range m.probes {
		p.ActorCredentialExtracted(cred, headersUsed)
	}
}

func (m *compositeTokenExchangeProbe) ActorCredentialExtractionFailed(err error) {
	for _, p := range m.probes {
		p.ActorCredentialExtractionFailed(err)
	}
}

func (m *compositeTokenExchangeProbe) ActorValidationSucceeded(actor *trust.Result) {
	for _, p := range m.probes {
		p.ActorValidationSucceeded(actor)
	}
}

func (m *compositeTokenExchangeProbe) ActorValidationFailed(err error) {
	for _, p := range m.probes {
		p.ActorValidationFailed(err)
	}
}

func (m *compositeTokenExchangeProbe) RequestContextParsed(attrs *request.RequestAttributes) {
	for _, p := range m.probes {
		p.RequestContextParsed(attrs)
	}
}

func (m *compositeTokenExchangeProbe) RequestContextParseFailed(err error) {
	for _, p := range m.probes {
		p.RequestContextParseFailed(err)
	}
}

func (m *compositeTokenExchangeProbe) SubjectTokenValidationSucceeded(subject *trust.Result) {
	for _, p := range m.probes {
		p.SubjectTokenValidationSucceeded(subject)
	}
}

func (m *compositeTokenExchangeProbe) SubjectTokenValidationFailed(err error) {
	for _, p := range m.probes {
		p.SubjectTokenValidationFailed(err)
	}
}

func (m *compositeTokenExchangeProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

type compositeAuthzCheckProbe struct {
	probes []service.AuthzCheckProbe
}

func (m *compositeAuthzCheckProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	for _, p := range m.probes {
		p.RequestAttributesParsed(attrs)
	}
}

func (m *compositeAuthzCheckProbe) ActorCredentialExtracted(cred trust.Credential, headersUsed []string) {
	for _, p := range m.probes {
		p.ActorCredentialExtracted(cred, headersUsed)
	}
}

func (m *compositeAuthzCheckProbe) ActorCredentialExtractionFailed(err error) {
	for _, p := range m.probes {
		p.ActorCredentialExtractionFailed(err)
	}
}

func (m *compositeAuthzCheckProbe) ActorValidationSucceeded(actor *trust.Result) {
	for _, p := range m.probes {
		p.ActorValidationSucceeded(actor)
	}
}

func (m *compositeAuthzCheckProbe) ActorValidationFailed(err error) {
	for _, p := range m.probes {
		p.ActorValidationFailed(err)
	}
}

func (m *compositeAuthzCheckProbe) SubjectCredentialExtracted(cred trust.Credential, headersUsed []string) {
	for _, p := range m.probes {
		p.SubjectCredentialExtracted(cred, headersUsed)
	}
}

func (m *compositeAuthzCheckProbe) SubjectCredentialExtractionFailed(err error) {
	for _, p := range m.probes {
		p.SubjectCredentialExtractionFailed(err)
	}
}

func (m *compositeAuthzCheckProbe) SubjectValidationSucceeded(subject *trust.Result) {
	for _, p := range m.probes {
		p.SubjectValidationSucceeded(subject)
	}
}

func (m *compositeAuthzCheckProbe) SubjectValidationFailed(err error) {
	for _, p := range m.probes {
		p.SubjectValidationFailed(err)
	}
}

func (m *compositeAuthzCheckProbe) SubjectAnonymous() {
	for _, p := range m.probes {
		p.SubjectAnonymous()
	}
}

func (m *compositeAuthzCheckProbe) PolicyDecisionIssue(tokenTypeCount int, scope string, reason string) {
	for _, p := range m.probes {
		p.PolicyDecisionIssue(tokenTypeCount, scope, reason)
	}
}

func (m *compositeAuthzCheckProbe) PolicyDecisionAllowWithoutIssue(reason string) {
	for _, p := range m.probes {
		p.PolicyDecisionAllowWithoutIssue(reason)
	}
}

func (m *compositeAuthzCheckProbe) PolicyDecisionDeny(reason string) {
	for _, p := range m.probes {
		p.PolicyDecisionDeny(reason)
	}
}

func (m *compositeAuthzCheckProbe) PolicyEvaluationFailed(err error) {
	for _, p := range m.probes {
		p.PolicyEvaluationFailed(err)
	}
}

func (m *compositeAuthzCheckProbe) End() {
	for _, p := range m.probes {
		p.End()
	}
}

var _ Observer = (*compositeAll)(nil)
