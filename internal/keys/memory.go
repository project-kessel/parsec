package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
)

// memoryKey represents a private key for signing
type memoryKey struct {
	ID        string
	Algorithm string
	Signer    crypto.Signer
}

// InMemoryKeyProvider is an in-memory implementation of KeyProvider for testing and development.
type InMemoryKeyProvider struct {
	mu         sync.RWMutex
	keyType    KeyType               // The key type this provider creates
	algorithm  string                // The signing algorithm to use
	keys       map[string]*memoryKey // Current keys by namespace:keyName
	oldKeys    []*memoryKey          // Keys scheduled for deletion
	keyCounter int                   // Counter for generating unique key IDs
}

// NewInMemoryKeyProvider creates a new in-memory key provider
func NewInMemoryKeyProvider(keyType KeyType, algorithm string) *InMemoryKeyProvider {
	if algorithm == "" {
		// Determine default algorithm
		switch keyType {
		case KeyTypeECP256:
			algorithm = "ES256"
		case KeyTypeECP384:
			algorithm = "ES384"
		case KeyTypeRSA2048, KeyTypeRSA4096:
			algorithm = "RS256"
		}
	}

	return &InMemoryKeyProvider{
		keyType:    keyType,
		algorithm:  algorithm,
		keys:       make(map[string]*memoryKey),
		oldKeys:    make([]*memoryKey, 0),
		keyCounter: 0,
	}
}

// GetKeyHandle returns a handle for a specific trust domain, namespace, and key name.
func (m *InMemoryKeyProvider) GetKeyHandle(ctx context.Context, trustDomain, namespace, keyName string) (KeyHandle, error) {
	return &memoryKeyHandle{
		manager:     m,
		trustDomain: trustDomain,
		namespace:   namespace,
		keyName:     keyName,
	}, nil
}

func (m *InMemoryKeyProvider) rotateKey(trustDomain, namespace, keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	storageKey := m.storageKey(trustDomain, namespace, keyName)

	// If key exists with this identifier, move to oldKeys (simulate deletion scheduling)
	if existing, ok := m.keys[storageKey]; ok {
		m.oldKeys = append(m.oldKeys, existing)
	}

	// Generate new key based on configured keyType
	var signer crypto.Signer
	var err error

	switch m.keyType {
	case KeyTypeECP256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECP384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeRSA2048:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA4096:
		signer, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return fmt.Errorf("unsupported key type: %s", m.keyType)
	}
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	m.keyCounter++
	// Build key ID from trust domain, namespace, and key name for clarity
	var kid string
	if trustDomain != "" && namespace != "" {
		kid = fmt.Sprintf("%s/%s-%s-%d", trustDomain, namespace, keyName, m.keyCounter)
	} else if trustDomain != "" {
		kid = fmt.Sprintf("%s-%s-%d", trustDomain, keyName, m.keyCounter)
	} else if namespace != "" {
		kid = fmt.Sprintf("%s-%s-%d", namespace, keyName, m.keyCounter)
	} else {
		kid = fmt.Sprintf("%s-%d", keyName, m.keyCounter)
	}

	key := &memoryKey{
		ID:        kid,
		Algorithm: m.algorithm,
		Signer:    signer,
	}

	m.keys[storageKey] = key
	return nil
}

func (m *InMemoryKeyProvider) getKey(trustDomain, namespace, keyName string) (*memoryKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.keys[m.storageKey(trustDomain, namespace, keyName)]
	if !ok {
		return nil, fmt.Errorf("key not found: %s/%s:%s", trustDomain, namespace, keyName)
	}
	return key, nil
}

func (m *InMemoryKeyProvider) storageKey(trustDomain, namespace, keyName string) string {
	// Build storage key with all components for unambiguous lookup
	var parts []string
	if trustDomain != "" {
		parts = append(parts, trustDomain)
	}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	parts = append(parts, keyName)

	// Join with ":" to create storage key
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += ":"
		}
		result += part
	}
	return result
}

type memoryKeyHandle struct {
	manager     *InMemoryKeyProvider
	trustDomain string
	namespace   string
	keyName     string
}

func (h *memoryKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	key, err := h.manager.getKey(h.trustDomain, h.namespace, h.keyName)
	if err != nil {
		return nil, "", err
	}

	sig, err := key.Signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, "", err
	}

	return sig, key.ID, nil
}

func (h *memoryKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	key, err := h.manager.getKey(h.trustDomain, h.namespace, h.keyName)
	if err != nil {
		return "", "", err
	}
	return key.ID, key.Algorithm, nil
}

func (h *memoryKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	key, err := h.manager.getKey(h.trustDomain, h.namespace, h.keyName)
	if err != nil {
		return nil, err
	}
	return key.Signer.Public(), nil
}

func (h *memoryKeyHandle) Rotate(ctx context.Context) error {
	return h.manager.rotateKey(h.trustDomain, h.namespace, h.keyName)
}
