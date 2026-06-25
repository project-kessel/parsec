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

// ValidatorObserver mirrors the Validator component tree.
// It embeds JWTValidatorObserver and will embed future validator observers.
// Implementations should embed NoOpValidatorObserver for forward compatibility.
type ValidatorObserver interface {
	JWTValidatorObserver
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

type NoOpValidatorObserver struct {
	NoOpJWTValidatorObserver
}

// NoOpTrustObserver satisfies TrustObserver with empty probes.
type NoOpTrustObserver struct {
	NoOpStoreObserver
	NoOpValidatorObserver
}

var _ TrustObserver = NoOpTrustObserver{}
