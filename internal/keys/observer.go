package keys

import "context"

// DualSlotRotatingSignerObserver is called at key points during key rotation operations.
// Implementations should embed NoOpDualSlotRotatingSignerObserver for forward compatibility
// with new methods added to this interface.
type DualSlotRotatingSignerObserver interface {
	// RotationCheckStarted is called when a rotation check begins.
	RotationCheckStarted(ctx context.Context) (context.Context, RotationCheckProbe)
	// KeyCacheUpdateStarted is called when the active key cache is being rebuilt.
	KeyCacheUpdateStarted(ctx context.Context) (context.Context, KeyCacheUpdateProbe)
}

// RotationCheckProbe tracks a single rotation check invocation.
// Implementations should embed NoOpRotationCheckProbe for forward compatibility.
type RotationCheckProbe interface {
	RotationCheckFailed(err error)
	RotationCompleted(slot string)
	RotationSkippedVersionRace(slot string)
	End()
}

// KeyCacheUpdateProbe tracks a single active-key-cache rebuild.
// Implementations should embed NoOpKeyCacheUpdateProbe for forward compatibility.
type KeyCacheUpdateProbe interface {
	KeyCacheUpdateFailed(err error)
	KeyProviderNotFound(provider, slot string)
	KeyHandleFailed(slot string, err error)
	PublicKeyFailed(slot string, err error)
	ThumbprintFailed(slot string, err error)
	MetadataFailed(slot string, err error)
	End()
}

// AWSKMSProviderObserver is called during AWS KMS key rotation.
// Implementations should embed NoOpAWSKMSProviderObserver for forward compatibility.
type AWSKMSProviderObserver interface {
	KMSRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, KMSRotateProbe)
}

// KMSRotateProbe tracks a single AWS KMS key rotation.
type KMSRotateProbe interface {
	KeyCreated()
	CreateKeyFailed(err error)
	AliasChanged(created bool)
	AliasCheckFailed(err error)
	AliasUpdateFailed(err error)
	DeletionScheduled()
	OldKeyDeletionFailed(keyID string, err error)
	End()
}

// DiskProviderObserver is called during disk-based key rotation.
// Implementations should embed NoOpDiskProviderObserver for forward compatibility.
type DiskProviderObserver interface {
	DiskRotateStarted(ctx context.Context, trustDomain string, namespace string, keyName string) (context.Context, DiskRotateProbe)
}

// DiskRotateProbe tracks a single disk key rotation.
type DiskRotateProbe interface {
	KeyGenerationFailed(err error)
	KeyWriteFailed(err error)
	End()
}

// InMemoryProviderObserver is called during in-memory key rotation.
// Implementations should embed NoOpInMemoryProviderObserver for forward compatibility.
type InMemoryProviderObserver interface {
	MemoryRotateStarted(ctx context.Context) (context.Context, MemoryRotateProbe)
}

// MemoryRotateProbe tracks a single in-memory key rotation.
type MemoryRotateProbe interface {
	KeyGenerationFailed(err error)
	End()
}

// RotatingSignerObserver mirrors the RotatingSigner component tree.
// It embeds DualSlotRotatingSignerObserver (DualSlotRotatingSigner level).
// Implementations should embed NoOpRotatingSignerObserver for forward compatibility.
type RotatingSignerObserver interface {
	DualSlotRotatingSignerObserver
}

// KeyProviderObserver mirrors the KeyProvider component tree.
// It embeds all provider-specific observers.
// Implementations should embed NoOpKeyProviderObserver for forward compatibility.
type KeyProviderObserver interface {
	AWSKMSProviderObserver
	DiskProviderObserver
	InMemoryProviderObserver
}

// KeysObserver is the per-package aggregate for all keys observer interfaces.
type KeysObserver interface {
	RotatingSignerObserver
	KeyProviderObserver
}

// --- NoOp implementations ---

// NoOpRotationCheckProbe is a no-op implementation of RotationCheckProbe.
type NoOpRotationCheckProbe struct{}

func (NoOpRotationCheckProbe) RotationCheckFailed(error)         {}
func (NoOpRotationCheckProbe) RotationCompleted(string)          {}
func (NoOpRotationCheckProbe) RotationSkippedVersionRace(string) {}
func (NoOpRotationCheckProbe) End()                              {}

// NoOpKeyCacheUpdateProbe is a no-op implementation of KeyCacheUpdateProbe.
type NoOpKeyCacheUpdateProbe struct{}

func (NoOpKeyCacheUpdateProbe) KeyCacheUpdateFailed(error)         {}
func (NoOpKeyCacheUpdateProbe) KeyProviderNotFound(string, string) {}
func (NoOpKeyCacheUpdateProbe) KeyHandleFailed(string, error)      {}
func (NoOpKeyCacheUpdateProbe) PublicKeyFailed(string, error)      {}
func (NoOpKeyCacheUpdateProbe) ThumbprintFailed(string, error)     {}
func (NoOpKeyCacheUpdateProbe) MetadataFailed(string, error)       {}
func (NoOpKeyCacheUpdateProbe) End()                               {}

// NoOpDualSlotRotatingSignerObserver is a no-op implementation of DualSlotRotatingSignerObserver.
type NoOpDualSlotRotatingSignerObserver struct{}

func (NoOpDualSlotRotatingSignerObserver) RotationCheckStarted(ctx context.Context) (context.Context, RotationCheckProbe) {
	return ctx, NoOpRotationCheckProbe{}
}

func (NoOpDualSlotRotatingSignerObserver) KeyCacheUpdateStarted(ctx context.Context) (context.Context, KeyCacheUpdateProbe) {
	return ctx, NoOpKeyCacheUpdateProbe{}
}

type NoOpKMSRotateProbe struct{}

func (NoOpKMSRotateProbe) KeyCreated()                        {}
func (NoOpKMSRotateProbe) CreateKeyFailed(error)              {}
func (NoOpKMSRotateProbe) AliasChanged(bool)                  {}
func (NoOpKMSRotateProbe) AliasCheckFailed(error)             {}
func (NoOpKMSRotateProbe) AliasUpdateFailed(error)            {}
func (NoOpKMSRotateProbe) DeletionScheduled()                 {}
func (NoOpKMSRotateProbe) OldKeyDeletionFailed(string, error) {}
func (NoOpKMSRotateProbe) End()                               {}

type NoOpAWSKMSProviderObserver struct{}

func (NoOpAWSKMSProviderObserver) KMSRotateStarted(ctx context.Context, _, _, _ string) (context.Context, KMSRotateProbe) {
	return ctx, NoOpKMSRotateProbe{}
}

type NoOpDiskRotateProbe struct{}

func (NoOpDiskRotateProbe) KeyGenerationFailed(error) {}
func (NoOpDiskRotateProbe) KeyWriteFailed(error)      {}
func (NoOpDiskRotateProbe) End()                      {}

type NoOpDiskProviderObserver struct{}

func (NoOpDiskProviderObserver) DiskRotateStarted(ctx context.Context, _, _, _ string) (context.Context, DiskRotateProbe) {
	return ctx, NoOpDiskRotateProbe{}
}

type NoOpMemoryRotateProbe struct{}

func (NoOpMemoryRotateProbe) KeyGenerationFailed(error) {}
func (NoOpMemoryRotateProbe) End()                      {}

type NoOpInMemoryProviderObserver struct{}

func (NoOpInMemoryProviderObserver) MemoryRotateStarted(ctx context.Context) (context.Context, MemoryRotateProbe) {
	return ctx, NoOpMemoryRotateProbe{}
}

type NoOpRotatingSignerObserver struct {
	NoOpDualSlotRotatingSignerObserver
}

type NoOpKeyProviderObserver struct {
	NoOpAWSKMSProviderObserver
	NoOpDiskProviderObserver
	NoOpInMemoryProviderObserver
}

// NoOpKeysObserver satisfies KeysObserver with empty probes.
type NoOpKeysObserver struct {
	NoOpRotatingSignerObserver
	NoOpKeyProviderObserver
}

var _ KeysObserver = NoOpKeysObserver{}
