package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/project-kessel/parsec/internal/fs"
	"github.com/google/uuid"
)

// DiskKeyProvider is a KeyProvider that stores keys on disk as JSON files.
// It's suitable for single-pod Kubernetes deployments with ReadWriteOnce persistent volumes.
type DiskKeyProvider struct {
	mu        sync.RWMutex
	keyType   KeyType       // The key type this provider creates
	algorithm string        // The signing algorithm to use
	keysPath  string        // Directory path for storing key files
	fs        fs.FileSystem // Filesystem abstraction for operations
}

// DiskKeyProviderConfig configures the disk key provider
type DiskKeyProviderConfig struct {
	// KeyType is the type of keys this provider creates
	KeyType KeyType

	// Algorithm is the signing algorithm to use
	Algorithm string

	// KeysPath is the directory where key files will be stored
	KeysPath string

	// FileSystem is an optional filesystem abstraction (defaults to OSFileSystem)
	FileSystem fs.FileSystem
}

// keyFileData represents the JSON structure stored on disk
type keyFileData struct {
	ID         string    `json:"id"`
	Algorithm  string    `json:"algorithm"`
	KeyType    string    `json:"key_type"`
	PrivateKey string    `json:"private_key"` // Base64-encoded DER format
	CreatedAt  time.Time `json:"created_at"`
}

// NewDiskKeyProvider creates a new disk-based key provider
func NewDiskKeyProvider(cfg DiskKeyProviderConfig) (*DiskKeyProvider, error) {
	if cfg.KeysPath == "" {
		return nil, fmt.Errorf("keys_path is required")
	}

	if cfg.KeyType == "" {
		return nil, fmt.Errorf("key_type is required")
	}

	// Validate KeyType
	switch cfg.KeyType {
	case KeyTypeECP256, KeyTypeECP384, KeyTypeRSA2048, KeyTypeRSA4096:
		// ok
	default:
		return nil, fmt.Errorf("unsupported key type: %s", cfg.KeyType)
	}

	algorithm := cfg.Algorithm
	if algorithm == "" {
		// Determine default algorithm
		switch cfg.KeyType {
		case KeyTypeECP256:
			algorithm = "ES256"
		case KeyTypeECP384:
			algorithm = "ES384"
		case KeyTypeRSA2048, KeyTypeRSA4096:
			algorithm = "RS256"
		}
	}

	// Default to OS filesystem if not provided
	filesystem := cfg.FileSystem
	if filesystem == nil {
		filesystem = fs.NewOSFileSystem()
	}

	// Create directory if it doesn't exist
	if err := filesystem.MkdirAll(cfg.KeysPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	return &DiskKeyProvider{
		keyType:   cfg.KeyType,
		algorithm: algorithm,
		keysPath:  cfg.KeysPath,
		fs:        filesystem,
	}, nil
}

func (m *DiskKeyProvider) GetKeyHandle(ctx context.Context, trustDomain, namespace, keyName string) (KeyHandle, error) {
	return &diskKeyHandle{
		manager:     m,
		trustDomain: trustDomain,
		namespace:   namespace,
		keyName:     keyName,
	}, nil
}

func (m *DiskKeyProvider) rotateKey(trustDomain, namespace, keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

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

	// Generate a unique kid using UUID
	kid := uuid.New().String()

	// Marshal private key to PKCS8 DER format
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encode to base64
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKeyDER)

	// Create key file data
	data := keyFileData{
		ID:         kid,
		Algorithm:  m.algorithm,
		KeyType:    string(m.keyType),
		PrivateKey: privateKeyB64,
		CreatedAt:  time.Now().UTC(),
	}

	// Write to disk atomically
	if err := m.writeKeyFile(trustDomain, namespace, keyName, &data); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

func (m *DiskKeyProvider) loadKey(trustDomain, namespace, keyName string) (crypto.Signer, string, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Read key file
	data, err := m.readKeyFile(trustDomain, namespace, keyName)
	if err != nil {
		return nil, "", "", err
	}

	// Validate key type matches configured type
	if data.KeyType != string(m.keyType) {
		return nil, "", "", fmt.Errorf("key type mismatch: expected %s, found %s", m.keyType, data.KeyType)
	}
	if data.Algorithm != m.algorithm {
		return nil, "", "", fmt.Errorf("algorithm mismatch: expected %s, found %s", m.algorithm, data.Algorithm)
	}

	// Decode base64 private key
	privateKeyDER, err := base64.StdEncoding.DecodeString(data.PrivateKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// Parse PKCS8 private key
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Type assert to crypto.Signer
	signer, ok := privateKeyAny.(crypto.Signer)
	if !ok {
		return nil, "", "", fmt.Errorf("private key does not implement crypto.Signer")
	}

	return signer, data.ID, data.Algorithm, nil
}

// writeKeyFile atomically writes a key file to disk
func (m *DiskKeyProvider) writeKeyFile(trustDomain, namespace, keyName string, data *keyFileData) error {
	keyFilePath := m.keyFilePath(trustDomain, namespace, keyName)

	// Ensure directory exists
	dir := filepath.Dir(keyFilePath)
	if err := m.fs.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write atomically (filesystem handles temp file + sync + rename)
	if err := m.fs.WriteFileAtomic(keyFilePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// readKeyFile reads a key file from disk
func (m *DiskKeyProvider) readKeyFile(trustDomain, namespace, keyName string) (*keyFileData, error) {
	keyFilePath := m.keyFilePath(trustDomain, namespace, keyName)

	// Read file
	jsonData, err := m.fs.ReadFile(keyFilePath)
	if err != nil {
		if m.fs.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s/%s", namespace, keyName)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Unmarshal JSON
	var data keyFileData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key file (corrupted?): %w", err)
	}

	return &data, nil
}

// keyFilePath returns the full path to a key file for a given trust domain, namespace, and keyName
func (m *DiskKeyProvider) keyFilePath(trustDomain, namespace, keyName string) string {
	// Build path components separately and sanitize each
	var parts []string
	if trustDomain != "" {
		parts = append(parts, m.sanitize(trustDomain))
	}
	if namespace != "" {
		parts = append(parts, m.sanitize(namespace))
	}

	// Join parts to create the directory path
	var dirPath string
	if len(parts) > 0 {
		dirPath = filepath.Join(append([]string{m.keysPath}, parts...)...)
	} else {
		dirPath = m.keysPath
	}

	return filepath.Join(dirPath, fmt.Sprintf("%s.json", keyName))
}

// sanitize replaces invalid path characters with underscores
func (m *DiskKeyProvider) sanitize(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

type diskKeyHandle struct {
	manager     *DiskKeyProvider
	trustDomain string
	namespace   string
	keyName     string
}

func (h *diskKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	signer, id, _, err := h.manager.loadKey(h.trustDomain, h.namespace, h.keyName)
	if err != nil {
		return nil, "", err
	}

	sig, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, "", err
	}

	return sig, id, nil
}

func (h *diskKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	_, id, alg, err := h.manager.loadKey(h.trustDomain, h.namespace, h.keyName)
	if err != nil {
		return "", "", err
	}
	return id, alg, nil
}

func (h *diskKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	signer, _, _, err := h.manager.loadKey(h.trustDomain, h.namespace, h.keyName)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

func (h *diskKeyHandle) Rotate(ctx context.Context) error {
	return h.manager.rotateKey(h.trustDomain, h.namespace, h.keyName)
}
