package observer

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestNoOp_AllProbeMethodsCallable(t *testing.T) {
	obs := NoOp()
	ctx := context.Background()

	{
		ctx2, p := obs.TokenIssuanceStarted(ctx, nil, nil, "", nil)
		if ctx2 != ctx {
			t.Error("expected same context back from noop TokenIssuanceStarted")
		}
		p.TokenTypeIssuanceStarted("t")
		p.TokenTypeIssuanceSucceeded("t", nil)
		p.TokenTypeIssuanceFailed("t", errors.New("x"))
		p.IssuerNotFound("t", errors.New("x"))
		p.End()
	}
	{
		_, p := obs.TokenExchangeStarted(ctx, "", "", "", "")
		p.ActorValidationSucceeded(nil)
		p.ActorValidationFailed(errors.New("x"))
		p.RequestContextParsed(nil)
		p.RequestContextParseFailed(errors.New("x"))
		p.SubjectTokenValidationSucceeded(nil)
		p.SubjectTokenValidationFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.AuthzCheckStarted(ctx)
		p.RequestAttributesParsed(nil)
		p.ActorValidationSucceeded(nil)
		p.ActorValidationFailed(errors.New("x"))
		p.SubjectCredentialExtracted(nil, nil)
		p.SubjectCredentialExtractionFailed(errors.New("x"))
		p.SubjectValidationSucceeded(nil)
		p.SubjectValidationFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.CacheFetchStarted(ctx, "ds")
		p.CacheHit()
		p.CacheMiss()
		p.CacheExpired()
		p.FetchFailed(errors.New("x"))
	}
	{
		_, p := obs.LuaFetchStarted(ctx, "lua")
		p.ScriptLoadFailed(errors.New("x"))
		p.ScriptExecutionFailed(errors.New("x"))
		p.InvalidReturnType("number")
		p.FetchCompleted()
		p.FetchCompletedNil()
		p.ResultConversionFailed(errors.New("x"))
	}
	{
		_, p := obs.RotationCheckStarted(ctx)
		p.RotationCheckFailed(errors.New("x"))
		p.RotationCompleted("slot")
		p.RotationSkippedVersionRace("slot")
		p.End()
	}
	{
		_, p := obs.KeyCacheUpdateStarted(ctx)
		p.KeyCacheUpdateFailed(errors.New("x"))
		p.KeyProviderNotFound("p", "s")
		p.KeyHandleFailed("s", errors.New("x"))
		p.PublicKeyFailed("s", errors.New("x"))
		p.ThumbprintFailed("s", errors.New("x"))
		p.MetadataFailed("s", errors.New("x"))
	}
	{
		_, p := obs.KMSRotateStarted(ctx, "td", "ns", "key")
		p.CreateKeyFailed(errors.New("x"))
		p.AliasCheckFailed(errors.New("x"))
		p.AliasUpdateFailed(errors.New("x"))
		p.OldKeyDeletionFailed("kid", errors.New("x"))
		p.End()
	}
	{
		_, p := obs.DiskRotateStarted(ctx, "td", "ns", "key")
		p.KeyGenerationFailed(errors.New("x"))
		p.KeyWriteFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.MemoryRotateStarted(ctx)
		p.KeyGenerationFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.ValidationStarted(ctx)
		p.ValidatorFailed("v", trust.CredentialTypeJWT, errors.New("x"))
		p.AllValidatorsFailed(trust.CredentialTypeBearer, 2, errors.New("x"))
		p.End()
	}
	{
		_, p := obs.ForActorStarted(ctx)
		p.ValidatorFiltered("v", "actor")
		p.FilterEvaluationFailed("v", errors.New("x"))
		p.End()
	}
	{
		_, p := obs.JWTValidateStarted(ctx, "https://issuer.example.com")
		p.JWKSLookupFailed(errors.New("x"))
		p.TokenExpired()
		p.TokenInvalid(errors.New("x"))
		p.ClaimsExtractionFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.LuaValidateStarted(ctx, "lua-validator")
		p.ScriptLoadFailed(errors.New("x"))
		p.ScriptExecutionFailed(errors.New("x"))
		p.InvalidReturnType("number")
		p.TokenInvalid(errors.New("x"))
		p.ValidationRejected()
		p.ResultConversionFailed(errors.New("x"))
		p.ValidationCompleted()
		p.End()
	}
	{
		_, p := obs.InMemoryValidateStarted(ctx, "v")
		p.CacheKeyFailed(errors.New("x"))
		p.CacheHit()
		p.CacheExpired()
		p.CacheMiss()
		p.SourceFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.DistributedValidateStarted(ctx, "v")
		p.CacheKeyFailed(errors.New("x"))
		p.GetFailed(errors.New("x"))
		p.ResultExpired()
		p.End()
	}
	{
		_, p := obs.InitPopulationStarted(ctx)
		p.InitialCachePopulationFailed(errors.New("x"))
		p.End()
	}
	{
		_, p := obs.CacheRefreshStarted(ctx)
		p.CacheRefreshFailed(errors.New("x"))
		p.KeyConversionFailed("kid", errors.New("x"))
	}
	obs.GRPCServeFailed(errors.New("x"))
	obs.HTTPServeFailed(errors.New("x"))
	{
		_, p := obs.StopStarted(ctx)
		p.End()
	}
	if err := obs.Shutdown(ctx); err != nil {
		t.Errorf("noop Shutdown should return nil, got %v", err)
	}
	obs.ConfigureHTTPMux(http.NewServeMux())
}

func TestCompose_ShutdownCallsShutdownFn(t *testing.T) {
	var called atomic.Int32
	obs := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
		WithShutdown(func(context.Context) error {
			called.Add(1)
			return nil
		}),
	)

	if err := obs.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("expected shutdown fn called once, got %d", called.Load())
	}
}

func TestCompose_ShutdownWithoutOption_ReturnsNil(t *testing.T) {
	obs := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
	)

	if err := obs.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompose_ConfigureHTTPMuxCallsFn(t *testing.T) {
	var called atomic.Int32
	obs := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
		WithHTTPMux(func(*http.ServeMux) {
			called.Add(1)
		}),
	)

	obs.ConfigureHTTPMux(http.NewServeMux())
	if called.Load() != 1 {
		t.Errorf("expected mux fn called once, got %d", called.Load())
	}
}

func TestCompositeAll_ConfigureHTTPMuxCascadesToAllChildren(t *testing.T) {
	var c1, c2 atomic.Int32
	child1 := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
		WithHTTPMux(func(*http.ServeMux) { c1.Add(1) }),
	)
	child2 := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
		WithHTTPMux(func(*http.ServeMux) { c2.Add(1) }),
	)

	composite := CompositeAll([]Observer{child1, child2})
	composite.ConfigureHTTPMux(http.NewServeMux())

	if c1.Load() != 1 {
		t.Errorf("child1: expected 1 call, got %d", c1.Load())
	}
	if c2.Load() != 1 {
		t.Errorf("child2: expected 1 call, got %d", c2.Load())
	}
}

func TestCompositeAll_ShutdownCascadesToAllChildren(t *testing.T) {
	var c1, c2 atomic.Int32
	child1 := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
		WithShutdown(func(context.Context) error {
			c1.Add(1)
			return nil
		}),
	)
	child2 := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
		WithShutdown(func(context.Context) error {
			c2.Add(1)
			return errors.New("child2 error")
		}),
	)

	composite := CompositeAll([]Observer{child1, child2})
	err := composite.Shutdown(context.Background())

	if c1.Load() != 1 {
		t.Errorf("child1 shutdown: expected 1 call, got %d", c1.Load())
	}
	if c2.Load() != 1 {
		t.Errorf("child2 shutdown: expected 1 call, got %d", c2.Load())
	}
	if err == nil || !errors.Is(err, errors.New("")) && err.Error() != "child2 error" {
		t.Errorf("expected child2 error to propagate, got %v", err)
	}
}

func TestCompose_DelegatesToCorrectSubObserver(t *testing.T) {
	var (
		cacheCalled      atomic.Int32
		luaCalled        atomic.Int32
		keyRotCalled     atomic.Int32
		kmsCalled        atomic.Int32
		diskCalled       atomic.Int32
		memCalled        atomic.Int32
		trustCalled      atomic.Int32
		filterCalled     atomic.Int32
		jwtCalled        atomic.Int32
		luaValCalled     atomic.Int32
		inMemCacheCalled atomic.Int32
		distCacheCalled  atomic.Int32
		jwksCalled       atomic.Int32
		srvCalled        atomic.Int32
	)

	obs := Compose(
		service.NoOpServiceObserver{},
		struct {
			datasource.CacheObserver
			datasource.LuaObserver
		}{&spyDSCacheObserver{called: &cacheCalled}, &spyLuaDSObserver{called: &luaCalled}},
		&spyKeysObserver{rotCalled: &keyRotCalled, kmsCalled: &kmsCalled, diskCalled: &diskCalled, memCalled: &memCalled},
		&spyTrustObserver{
			called:           &trustCalled,
			filterCalled:     &filterCalled,
			jwtCalled:        &jwtCalled,
			luaValCalled:     &luaValCalled,
			inMemCacheCalled: &inMemCacheCalled,
			distCacheCalled:  &distCacheCalled,
		},
		struct {
			server.JWKSObserver
			server.LifecycleObserver
		}{&spyJWKSObserver{called: &jwksCalled}, &spySrvLifeObserver{called: &srvCalled}},
	)

	ctx := context.Background()

	obs.CacheFetchStarted(ctx, "ds")
	if cacheCalled.Load() != 1 {
		t.Errorf("CacheFetchStarted: expected cache observer called once, got %d", cacheCalled.Load())
	}

	obs.LuaFetchStarted(ctx, "lua")
	if luaCalled.Load() != 1 {
		t.Errorf("LuaFetchStarted: expected lua observer called once, got %d", luaCalled.Load())
	}

	obs.RotationCheckStarted(ctx)
	if keyRotCalled.Load() != 1 {
		t.Errorf("RotationCheckStarted: expected key rotation observer called once, got %d", keyRotCalled.Load())
	}

	obs.KMSRotateStarted(ctx, "td", "ns", "key")
	if kmsCalled.Load() != 1 {
		t.Errorf("KMSRotateStarted: expected KMS observer called once, got %d", kmsCalled.Load())
	}

	obs.DiskRotateStarted(ctx, "td", "ns", "key")
	if diskCalled.Load() != 1 {
		t.Errorf("DiskRotateStarted: expected disk observer called once, got %d", diskCalled.Load())
	}

	obs.MemoryRotateStarted(ctx)
	if memCalled.Load() != 1 {
		t.Errorf("MemoryRotateStarted: expected memory observer called once, got %d", memCalled.Load())
	}

	obs.ValidationStarted(ctx)
	if trustCalled.Load() != 1 {
		t.Errorf("ValidationStarted: expected trust observer called once, got %d", trustCalled.Load())
	}

	obs.ForActorStarted(ctx)
	if filterCalled.Load() != 1 {
		t.Errorf("ForActorStarted: expected filter observer called once, got %d", filterCalled.Load())
	}

	obs.JWTValidateStarted(ctx, "https://issuer.example.com")
	if jwtCalled.Load() != 1 {
		t.Errorf("JWTValidateStarted: expected JWT observer called once, got %d", jwtCalled.Load())
	}

	obs.LuaValidateStarted(ctx, "lua-validator")
	if luaValCalled.Load() != 1 {
		t.Errorf("LuaValidateStarted: expected Lua validator observer called once, got %d", luaValCalled.Load())
	}

	obs.InMemoryValidateStarted(ctx, "lua-validator")
	if inMemCacheCalled.Load() != 1 {
		t.Errorf("InMemoryValidateStarted: expected in-memory caching validator observer called once, got %d", inMemCacheCalled.Load())
	}

	obs.DistributedValidateStarted(ctx, "lua-validator")
	if distCacheCalled.Load() != 1 {
		t.Errorf("DistributedValidateStarted: expected distributed caching validator observer called once, got %d", distCacheCalled.Load())
	}

	obs.CacheRefreshStarted(ctx)
	if jwksCalled.Load() != 1 {
		t.Errorf("CacheRefreshStarted: expected JWKS observer called once, got %d", jwksCalled.Load())
	}

	obs.StopStarted(ctx)
	if srvCalled.Load() != 1 {
		t.Errorf("StopStarted: expected server lifecycle observer called once, got %d", srvCalled.Load())
	}
}

func TestCompositeAll_SingleChild_ReturnsSame(t *testing.T) {
	child := NoOp()
	result := CompositeAll([]Observer{child})
	if result != child {
		t.Error("CompositeAll with 1 child should return that child directly")
	}
}

func TestCompositeAll_FansOutAllInfraTypes(t *testing.T) {
	var (
		cache1, cache2           atomic.Int32
		lua1, lua2               atomic.Int32
		rot1, rot2               atomic.Int32
		kms1, kms2               atomic.Int32
		disk1, disk2             atomic.Int32
		mem1, mem2               atomic.Int32
		trust1, trust2           atomic.Int32
		filter1, filter2         atomic.Int32
		jwt1, jwt2               atomic.Int32
		luaVal1, luaVal2         atomic.Int32
		inMemCache1, inMemCache2 atomic.Int32
		distCache1, distCache2   atomic.Int32
		jwks1, jwks2             atomic.Int32
		srv1, srv2               atomic.Int32
	)

	child1 := Compose(
		service.NoOpServiceObserver{},
		struct {
			datasource.CacheObserver
			datasource.LuaObserver
		}{&spyDSCacheObserver{called: &cache1}, &spyLuaDSObserver{called: &lua1}},
		&spyKeysObserver{rotCalled: &rot1, kmsCalled: &kms1, diskCalled: &disk1, memCalled: &mem1},
		&spyTrustObserver{
			called:           &trust1,
			filterCalled:     &filter1,
			jwtCalled:        &jwt1,
			luaValCalled:     &luaVal1,
			inMemCacheCalled: &inMemCache1,
			distCacheCalled:  &distCache1,
		},
		struct {
			server.JWKSObserver
			server.LifecycleObserver
		}{&spyJWKSObserver{called: &jwks1}, &spySrvLifeObserver{called: &srv1}},
	)
	child2 := Compose(
		service.NoOpServiceObserver{},
		struct {
			datasource.CacheObserver
			datasource.LuaObserver
		}{&spyDSCacheObserver{called: &cache2}, &spyLuaDSObserver{called: &lua2}},
		&spyKeysObserver{rotCalled: &rot2, kmsCalled: &kms2, diskCalled: &disk2, memCalled: &mem2},
		&spyTrustObserver{
			called:           &trust2,
			filterCalled:     &filter2,
			jwtCalled:        &jwt2,
			luaValCalled:     &luaVal2,
			inMemCacheCalled: &inMemCache2,
			distCacheCalled:  &distCache2,
		},
		struct {
			server.JWKSObserver
			server.LifecycleObserver
		}{&spyJWKSObserver{called: &jwks2}, &spySrvLifeObserver{called: &srv2}},
	)

	composite := CompositeAll([]Observer{child1, child2})
	ctx := context.Background()

	composite.CacheFetchStarted(ctx, "ds")
	composite.LuaFetchStarted(ctx, "lua")
	composite.RotationCheckStarted(ctx)
	composite.KMSRotateStarted(ctx, "td", "ns", "key")
	composite.DiskRotateStarted(ctx, "td", "ns", "key")
	composite.MemoryRotateStarted(ctx)
	composite.ValidationStarted(ctx)
	composite.ForActorStarted(ctx)
	composite.JWTValidateStarted(ctx, "https://issuer.example.com")
	composite.LuaValidateStarted(ctx, "lua-validator")
	composite.InMemoryValidateStarted(ctx, "lua-validator")
	composite.DistributedValidateStarted(ctx, "lua-validator")
	composite.CacheRefreshStarted(ctx)
	composite.StopStarted(ctx)

	for _, tc := range []struct {
		name   string
		c1, c2 *atomic.Int32
	}{
		{"DataSourceCache", &cache1, &cache2},
		{"LuaDataSource", &lua1, &lua2},
		{"KeyRotation", &rot1, &rot2},
		{"KMSProvider", &kms1, &kms2},
		{"DiskProvider", &disk1, &disk2},
		{"MemoryProvider", &mem1, &mem2},
		{"TrustValidation", &trust1, &trust2},
		{"TrustForActor", &filter1, &filter2},
		{"JWTValidate", &jwt1, &jwt2},
		{"LuaValidate", &luaVal1, &luaVal2},
		{"InMemoryValidate", &inMemCache1, &inMemCache2},
		{"DistributedValidate", &distCache1, &distCache2},
		{"JWKS", &jwks1, &jwks2},
		{"ServerLifecycle", &srv1, &srv2},
	} {
		if tc.c1.Load() != 1 {
			t.Errorf("%s: child1 expected 1 call, got %d", tc.name, tc.c1.Load())
		}
		if tc.c2.Load() != 1 {
			t.Errorf("%s: child2 expected 1 call, got %d", tc.name, tc.c2.Load())
		}
	}
}

func TestCompositeAll_FansOutServiceTypes(t *testing.T) {
	var (
		tokenIss1, tokenIss2   atomic.Int32
		tokenExch1, tokenExch2 atomic.Int32
		authz1, authz2         atomic.Int32
	)

	child1 := Compose(
		&spyServiceObserver{
			tokenIssuanceCalled: &tokenIss1,
			tokenExchangeCalled: &tokenExch1,
			authzCheckCalled:    &authz1,
		},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
	)
	child2 := Compose(
		&spyServiceObserver{
			tokenIssuanceCalled: &tokenIss2,
			tokenExchangeCalled: &tokenExch2,
			authzCheckCalled:    &authz2,
		},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
	)

	composite := CompositeAll([]Observer{child1, child2})
	ctx := context.Background()

	composite.TokenIssuanceStarted(ctx, nil, nil, "", nil)
	composite.TokenExchangeStarted(ctx, "", "", "", "")
	composite.AuthzCheckStarted(ctx)

	for _, tc := range []struct {
		name   string
		c1, c2 *atomic.Int32
	}{
		{"TokenIssuance", &tokenIss1, &tokenIss2},
		{"TokenExchange", &tokenExch1, &tokenExch2},
		{"AuthzCheck", &authz1, &authz2},
	} {
		if tc.c1.Load() != 1 {
			t.Errorf("%s: child1 expected 1 call, got %d", tc.name, tc.c1.Load())
		}
		if tc.c2.Load() != 1 {
			t.Errorf("%s: child2 expected 1 call, got %d", tc.name, tc.c2.Load())
		}
	}
}

func TestCompositeAll_MultiProbe_FansOutEvents(t *testing.T) {
	var hits1, hits2 atomic.Int32

	child1 := Compose(
		service.NoOpServiceObserver{},
		struct {
			datasource.CacheObserver
			datasource.LuaObserver
		}{&spyDSCacheObserver{called: new(atomic.Int32), hitCalled: &hits1}, datasource.NoOpDataSourceObserver{}},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
	)
	child2 := Compose(
		service.NoOpServiceObserver{},
		struct {
			datasource.CacheObserver
			datasource.LuaObserver
		}{&spyDSCacheObserver{called: new(atomic.Int32), hitCalled: &hits2}, datasource.NoOpDataSourceObserver{}},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		server.NoOpServerObserver{},
	)

	composite := CompositeAll([]Observer{child1, child2})
	_, p := composite.CacheFetchStarted(context.Background(), "ds")
	p.CacheHit()

	if hits1.Load() != 1 {
		t.Errorf("child1 CacheHit: expected 1, got %d", hits1.Load())
	}
	if hits2.Load() != 1 {
		t.Errorf("child2 CacheHit: expected 1, got %d", hits2.Load())
	}
}

// --- spy implementations for testing delegation ---

type spyDSCacheObserver struct {
	called    *atomic.Int32
	hitCalled *atomic.Int32
}

func (s *spyDSCacheObserver) CacheFetchStarted(ctx context.Context, _ string) (context.Context, datasource.CacheFetchProbe) {
	s.called.Add(1)
	return ctx, &spyDSCacheProbe{hitCalled: s.hitCalled}
}

type spyDSCacheProbe struct{ hitCalled *atomic.Int32 }

func (s *spyDSCacheProbe) CacheHit() {
	if s.hitCalled != nil {
		s.hitCalled.Add(1)
	}
}
func (s *spyDSCacheProbe) CacheMiss()        {}
func (s *spyDSCacheProbe) CacheExpired()     {}
func (s *spyDSCacheProbe) FetchFailed(error) {}
func (s *spyDSCacheProbe) End()              {}

type spyLuaDSObserver struct{ called *atomic.Int32 }

func (s *spyLuaDSObserver) LuaFetchStarted(_ context.Context, _ string) (context.Context, datasource.LuaFetchProbe) {
	s.called.Add(1)
	return datasource.NoOpDataSourceObserver{}.LuaFetchStarted(context.Background(), "")
}

type spyKeysObserver struct {
	keys.NoOpKeysObserver
	rotCalled  *atomic.Int32
	kmsCalled  *atomic.Int32
	diskCalled *atomic.Int32
	memCalled  *atomic.Int32
}

func (s *spyKeysObserver) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	s.rotCalled.Add(1)
	return ctx, keys.NoOpRotationCheckProbe{}
}

func (s *spyKeysObserver) KMSRotateStarted(ctx context.Context, _, _, _ string) (context.Context, keys.KMSRotateProbe) {
	s.kmsCalled.Add(1)
	return ctx, keys.NoOpKMSRotateProbe{}
}

func (s *spyKeysObserver) DiskRotateStarted(ctx context.Context, _, _, _ string) (context.Context, keys.DiskRotateProbe) {
	s.diskCalled.Add(1)
	return ctx, keys.NoOpDiskRotateProbe{}
}

func (s *spyKeysObserver) MemoryRotateStarted(ctx context.Context) (context.Context, keys.MemoryRotateProbe) {
	s.memCalled.Add(1)
	return ctx, keys.NoOpMemoryRotateProbe{}
}

type spyTrustObserver struct {
	called           *atomic.Int32
	filterCalled     *atomic.Int32
	jwtCalled        *atomic.Int32
	luaValCalled     *atomic.Int32
	inMemCacheCalled *atomic.Int32
	distCacheCalled  *atomic.Int32
}

func (s *spyTrustObserver) ValidationStarted(_ context.Context) (context.Context, trust.ValidationProbe) {
	if s.called != nil {
		s.called.Add(1)
	}
	return trust.NoOpTrustObserver{}.ValidationStarted(context.Background())
}

func (s *spyTrustObserver) ForActorStarted(_ context.Context) (context.Context, trust.ForActorProbe) {
	if s.filterCalled != nil {
		s.filterCalled.Add(1)
	}
	return trust.NoOpTrustObserver{}.ForActorStarted(context.Background())
}

func (s *spyTrustObserver) JWTValidateStarted(_ context.Context, _ string) (context.Context, trust.JWTValidateProbe) {
	if s.jwtCalled != nil {
		s.jwtCalled.Add(1)
	}
	return trust.NoOpTrustObserver{}.JWTValidateStarted(context.Background(), "")
}

func (s *spyTrustObserver) LuaValidateStarted(_ context.Context, _ string) (context.Context, trust.LuaValidateProbe) {
	if s.luaValCalled != nil {
		s.luaValCalled.Add(1)
	}
	return trust.NoOpTrustObserver{}.LuaValidateStarted(context.Background(), "")
}

func (s *spyTrustObserver) InMemoryValidateStarted(_ context.Context, _ string) (context.Context, trust.InMemoryValidateProbe) {
	if s.inMemCacheCalled != nil {
		s.inMemCacheCalled.Add(1)
	}
	return trust.NoOpTrustObserver{}.InMemoryValidateStarted(context.Background(), "")
}

func (s *spyTrustObserver) DistributedValidateStarted(_ context.Context, _ string) (context.Context, trust.DistributedValidateProbe) {
	if s.distCacheCalled != nil {
		s.distCacheCalled.Add(1)
	}
	return trust.NoOpTrustObserver{}.DistributedValidateStarted(context.Background(), "")
}

type spyJWKSObserver struct {
	server.NoOpJWKSObserver
	called *atomic.Int32
}

func (s *spyJWKSObserver) CacheRefreshStarted(_ context.Context) (context.Context, server.CacheRefreshProbe) {
	s.called.Add(1)
	return server.NoOpServerObserver{}.CacheRefreshStarted(context.Background())
}

type spySrvLifeObserver struct {
	server.NoOpLifecycleObserver
	called *atomic.Int32
}

func (s *spySrvLifeObserver) StopStarted(_ context.Context) (context.Context, server.StopProbe) {
	s.called.Add(1)
	return server.NoOpServerObserver{}.StopStarted(context.Background())
}

type spyServiceObserver struct {
	service.NoOpServiceObserver
	tokenIssuanceCalled *atomic.Int32
	tokenExchangeCalled *atomic.Int32
	authzCheckCalled    *atomic.Int32
}

func (s *spyServiceObserver) TokenIssuanceStarted(ctx context.Context, _ *trust.Result, _ *trust.Result, _ string, _ []service.TokenType) (context.Context, service.TokenIssuanceProbe) {
	s.tokenIssuanceCalled.Add(1)
	return ctx, service.NoOpTokenIssuanceProbe{}
}

func (s *spyServiceObserver) TokenExchangeStarted(ctx context.Context, _ string, _ string, _ string, _ string) (context.Context, service.TokenExchangeProbe) {
	s.tokenExchangeCalled.Add(1)
	return ctx, service.NoOpTokenExchangeProbe{}
}

func (s *spyServiceObserver) AuthzCheckStarted(ctx context.Context) (context.Context, service.AuthzCheckProbe) {
	s.authzCheckCalled.Add(1)
	return ctx, service.NoOpAuthzCheckProbe{}
}
