package trust

import "context"

// StoreObserver mirrors the Store component tree.
// It embeds FilteredStoreObserver.
// Implementations should embed NoOpStoreObserver for forward compatibility.
type StoreObserver interface {
	FilteredStoreObserver
}

// ValidationProbe tracks a single Store.Validate invocation.
// Implementations should embed NoOpValidationProbe for forward compatibility.
type ValidationProbe interface {
	ValidatorFailed(validatorName string, credType CredentialType, err error)
	AllValidatorsFailed(credType CredentialType, attempted int, lastErr error)
	End()
}

// FilteredStoreObserver is called at key points during FilteredStore.ForActor.
// Implementations should embed NoOpFilteredStoreObserver for forward compatibility.
type FilteredStoreObserver interface {
	ValidationStarted(ctx context.Context) (context.Context, ValidationProbe)
	ForActorStarted(ctx context.Context) (context.Context, ForActorProbe)
}

// ForActorProbe tracks a single FilteredStore.ForActor evaluation.
// Implementations should embed NoOpForActorProbe for forward compatibility.
type ForActorProbe interface {
	ValidatorFiltered(validatorName string, actorSubject string)
	FilterEvaluationFailed(validatorName string, err error)
	End()
}

// JWTValidatorObserver is called at key points during JWTValidator.Validate.
// Implementations should embed NoOpJWTValidatorObserver for forward compatibility.
type JWTValidatorObserver interface {
	JWTValidateStarted(ctx context.Context, issuer string) (context.Context, JWTValidateProbe)
}

// JWTValidateProbe tracks a single JWTValidator.Validate invocation.
// Implementations should embed NoOpJWTValidateProbe for forward compatibility.
type JWTValidateProbe interface {
	JWKSLookupFailed(err error)
	TokenExpired()
	TokenInvalid(err error)
	ClaimsExtractionFailed(err error)
	End()
}

// LuaValidatorObserver is called at key points during LuaValidator.Validate.
// Implementations should embed NoOpLuaValidatorObserver for forward compatibility.
type LuaValidatorObserver interface {
	LuaValidateStarted(ctx context.Context, validatorName string) (context.Context, LuaValidateProbe)
}

// LuaValidateProbe tracks a single LuaValidator.Validate invocation.
// Implementations should embed NoOpLuaValidateProbe for forward compatibility.
type LuaValidateProbe interface {
	ScriptLoadFailed(err error)
	ScriptExecutionFailed(err error)
	InvalidReturnType(got string)
	TokenInvalid(err error)
	ValidationRejected()
	ResultConversionFailed(err error)
	ValidationCompleted()
	End()
}

// InMemoryCachingValidatorObserver is called at key points during InMemoryCachingValidator.Validate.
// Implementations should embed NoOpInMemoryCachingValidatorObserver for forward compatibility.
type InMemoryCachingValidatorObserver interface {
	InMemoryValidateStarted(ctx context.Context, validatorName string) (context.Context, InMemoryValidateProbe)
}

// InMemoryValidateProbe tracks a single InMemoryCachingValidator.Validate invocation.
// Implementations should embed NoOpInMemoryValidateProbe for forward compatibility.
type InMemoryValidateProbe interface {
	CacheKeyFailed(err error)
	CacheHit()
	CacheExpired()
	CacheMiss()
	SourceFailed(err error)
	End()
}

// DistributedCachingValidatorObserver is called at key points during DistributedCachingValidator.Validate.
// Implementations should embed NoOpDistributedCachingValidatorObserver for forward compatibility.
type DistributedCachingValidatorObserver interface {
	DistributedValidateStarted(ctx context.Context, validatorName string) (context.Context, DistributedValidateProbe)
}

// DistributedValidateProbe tracks a single DistributedCachingValidator.Validate invocation.
// Implementations should embed NoOpDistributedValidateProbe for forward compatibility.
type DistributedValidateProbe interface {
	CacheKeyFailed(err error)
	GetFailed(err error)
	ResultExpired()
	End()
}

// ValidatorObserver mirrors the Validator component tree.
// It embeds leaf observers for validator implementations and wrappers.
// Implementations should embed NoOpValidatorObserver for forward compatibility.
type ValidatorObserver interface {
	JWTValidatorObserver
	LuaValidatorObserver
	InMemoryCachingValidatorObserver
	DistributedCachingValidatorObserver
}

// TrustObserver is the per-package aggregate for all trust observer interfaces.
type TrustObserver interface {
	StoreObserver
	ValidatorObserver
}

// --- NoOp implementations ---

type NoOpValidationProbe struct{}

func (NoOpValidationProbe) ValidatorFailed(string, CredentialType, error)  {}
func (NoOpValidationProbe) AllValidatorsFailed(CredentialType, int, error) {}
func (NoOpValidationProbe) End()                                           {}

type NoOpForActorProbe struct{}

func (NoOpForActorProbe) ValidatorFiltered(string, string)     {}
func (NoOpForActorProbe) FilterEvaluationFailed(string, error) {}
func (NoOpForActorProbe) End()                                 {}

type NoOpJWTValidateProbe struct{}

func (NoOpJWTValidateProbe) JWKSLookupFailed(error)       {}
func (NoOpJWTValidateProbe) TokenExpired()                {}
func (NoOpJWTValidateProbe) TokenInvalid(error)           {}
func (NoOpJWTValidateProbe) ClaimsExtractionFailed(error) {}
func (NoOpJWTValidateProbe) End()                         {}

type NoOpLuaValidateProbe struct{}

func (NoOpLuaValidateProbe) ScriptLoadFailed(error)       {}
func (NoOpLuaValidateProbe) ScriptExecutionFailed(error)  {}
func (NoOpLuaValidateProbe) InvalidReturnType(string)     {}
func (NoOpLuaValidateProbe) TokenInvalid(error)           {}
func (NoOpLuaValidateProbe) ValidationRejected()          {}
func (NoOpLuaValidateProbe) ResultConversionFailed(error) {}
func (NoOpLuaValidateProbe) ValidationCompleted()         {}
func (NoOpLuaValidateProbe) End()                         {}

type NoOpInMemoryValidateProbe struct{}

func (NoOpInMemoryValidateProbe) CacheKeyFailed(error) {}
func (NoOpInMemoryValidateProbe) CacheHit()            {}
func (NoOpInMemoryValidateProbe) CacheExpired()        {}
func (NoOpInMemoryValidateProbe) CacheMiss()           {}
func (NoOpInMemoryValidateProbe) SourceFailed(error)   {}
func (NoOpInMemoryValidateProbe) End()                 {}

type NoOpDistributedValidateProbe struct{}

func (NoOpDistributedValidateProbe) CacheKeyFailed(error) {}
func (NoOpDistributedValidateProbe) GetFailed(error)      {}
func (NoOpDistributedValidateProbe) ResultExpired()       {}
func (NoOpDistributedValidateProbe) End()                 {}

type NoOpStoreObserver struct {
	NoOpFilteredStoreObserver
}

type NoOpFilteredStoreObserver struct{}

func (NoOpFilteredStoreObserver) ForActorStarted(ctx context.Context) (context.Context, ForActorProbe) {
	return ctx, NoOpForActorProbe{}
}

func (NoOpFilteredStoreObserver) ValidationStarted(ctx context.Context) (context.Context, ValidationProbe) {
	return ctx, NoOpValidationProbe{}
}

type NoOpJWTValidatorObserver struct{}

func (NoOpJWTValidatorObserver) JWTValidateStarted(ctx context.Context, _ string) (context.Context, JWTValidateProbe) {
	return ctx, NoOpJWTValidateProbe{}
}

type NoOpLuaValidatorObserver struct{}

func (NoOpLuaValidatorObserver) LuaValidateStarted(ctx context.Context, _ string) (context.Context, LuaValidateProbe) {
	return ctx, NoOpLuaValidateProbe{}
}

type NoOpInMemoryCachingValidatorObserver struct{}

func (NoOpInMemoryCachingValidatorObserver) InMemoryValidateStarted(ctx context.Context, _ string) (context.Context, InMemoryValidateProbe) {
	return ctx, NoOpInMemoryValidateProbe{}
}

type NoOpDistributedCachingValidatorObserver struct{}

func (NoOpDistributedCachingValidatorObserver) DistributedValidateStarted(ctx context.Context, _ string) (context.Context, DistributedValidateProbe) {
	return ctx, NoOpDistributedValidateProbe{}
}

type NoOpValidatorObserver struct {
	NoOpJWTValidatorObserver
	NoOpLuaValidatorObserver
	NoOpInMemoryCachingValidatorObserver
	NoOpDistributedCachingValidatorObserver
}

// NoOpTrustObserver satisfies TrustObserver with empty probes.
type NoOpTrustObserver struct {
	NoOpStoreObserver
	NoOpValidatorObserver
}

var _ TrustObserver = NoOpTrustObserver{}
