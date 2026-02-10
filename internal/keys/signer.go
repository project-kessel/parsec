package keys

import (
	"context"
	"crypto"
	"errors"

	"github.com/project-kessel/parsec/internal/service"
)

var (
	// ErrKeyMismatch is returned when the key used for signing does not match the expected key ID
	ErrKeyMismatch = errors.New("key mismatch during signing")
)

// KeyID is a unique identifier for a cryptographic key
type KeyID string

// Algorithm is a cryptographic algorithm identifier (e.g., "ES256", "RS256")
type Algorithm string

// KeyHandle represents a logical key version (e.g. a specific file or KMS key version/alias).
// It provides access to signing operations and key metadata.
type KeyHandle interface {
	// Sign signs data. Returns signature and the ID of the key actually used.
	// This allows callers to verify if the key rotated underneath them (if using aliases).
	Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) (signature []byte, usedKeyID string, err error)

	// Metadata returns the expected Key ID and Algorithm for this handle.
	Metadata(ctx context.Context) (keyID string, alg string, err error)

	// Public returns the public key.
	Public(ctx context.Context) (crypto.PublicKey, error)

	// Rotate rotates this key (creates a new version).
	Rotate(ctx context.Context) error
}

// RotatingSigner manages active keys and rotation.
type RotatingSigner interface {
	// GetCurrentSigner returns a signer bound to the provided context and the current active key.
	//
	// The returned signer MUST only be used within the bounds of the provided context.
	// As a result, this method is usually called for every request. The signer is not reused.
	//
	// Getting the current signer does not typically involve I/O, however using the returned signer usually does.
	// Due to this, there are race conditions where the signature may be generated with a different key
	// than the one identified by the returned [keyID].
	// If this happens, the signer detects this and returns an [ErrKeyMismatch].
	// Because keys are generally only changed once they are no longer used,
	// this should be extremely rare.
	GetCurrentSigner(ctx context.Context) (signer crypto.Signer, keyID KeyID, alg Algorithm, err error)

	// PublicKeys returns the current set of valid public keys.
	PublicKeys(ctx context.Context) ([]service.PublicKey, error)

	// Start begins background rotation tasks.
	Start(ctx context.Context) error

	// Stop stops background tasks.
	Stop()
}

// KeyProvider manages creating/retrieving KeyHandles.
type KeyProvider interface {
	// GetKeyHandle returns a handle for a specific trust domain, namespace, and key name.
	// trustDomain provides global isolation (e.g., "example.com").
	// namespace provides logical grouping within the trust domain (e.g., "access-tokens").
	GetKeyHandle(ctx context.Context, trustDomain, namespace, keyName string) (KeyHandle, error)
}

// KeyType represents the cryptographic key type
type KeyType string

const (
	KeyTypeECP256  KeyType = "EC-P256"
	KeyTypeECP384  KeyType = "EC-P384"
	KeyTypeRSA2048 KeyType = "RSA-2048"
	KeyTypeRSA4096 KeyType = "RSA-4096"
)
