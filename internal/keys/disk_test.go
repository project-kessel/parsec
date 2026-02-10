package keys

import (
	"context"
	"crypto"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/fs"
)

func TestDiskKeyProvider_CreateAndGetKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		wantAlg string
	}{
		{
			name:    "EC-P256",
			keyType: KeyTypeECP256,
			wantAlg: "ES256",
		},
		{
			name:    "EC-P384",
			keyType: KeyTypeECP384,
			wantAlg: "ES384",
		},
		{
			name:    "RSA-2048",
			keyType: KeyTypeRSA2048,
			wantAlg: "RS256",
		},
		{
			name:    "RSA-4096",
			keyType: KeyTypeRSA4096,
			wantAlg: "RS256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memFS := fs.NewMemFileSystem()
			kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
				KeyType:    tt.keyType,
				KeysPath:   "/keys",
				FileSystem: memFS,
			})
			require.NoError(t, err)

			ctx := context.Background()
			trustDomain := "test.example.com"
			ns := "test-ns"
			keyName := "key-a"

			handle, err := kp.GetKeyHandle(ctx, trustDomain, ns, keyName)
			require.NoError(t, err)

			// Create a key (rotate)
			err = handle.Rotate(ctx)
			require.NoError(t, err)

			id, alg, err := handle.Metadata(ctx)
			require.NoError(t, err)
			assert.NotEmpty(t, id)
			assert.Equal(t, tt.wantAlg, alg)

			pubKey, err := handle.Public(ctx)
			require.NoError(t, err)
			assert.NotNil(t, pubKey)

			// Sign something
			msg := []byte("message to sign")
			hasher := crypto.SHA256.New()
			hasher.Write(msg)
			digest := hasher.Sum(nil)
			sig, usedID, err := handle.Sign(ctx, digest, crypto.SHA256)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)
			assert.Equal(t, id, usedID)
		})
	}
}

func TestDiskKeyProvider_KeyRotation(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	trustDomain := "test.example.com"
	ns := "test-ns"
	keyName := "key-a"

	handle, err := kp.GetKeyHandle(ctx, trustDomain, ns, keyName)
	require.NoError(t, err)

	// Create first key
	err = handle.Rotate(ctx)
	require.NoError(t, err)

	id1, _, err := handle.Metadata(ctx)
	require.NoError(t, err)

	// Create second key (rotation)
	err = handle.Rotate(ctx)
	require.NoError(t, err)

	id2, _, err := handle.Metadata(ctx)
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2)
}

func TestDiskKeyProvider_GetKeyNotFound(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	trustDomain := "test.example.com"

	// Try to get a key that doesn't exist
	handle, err := kp.GetKeyHandle(ctx, trustDomain, "test-ns", "nonexistent")
	require.NoError(t, err) // Handle creation succeeds

	// Operations should fail
	_, _, err = handle.Metadata(ctx)
	assert.Error(t, err)
}

func TestDiskKeyProvider_ConcurrentAccess(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	trustDomain := "test.example.com"
	ns := "test-ns"

	// Create initial keys
	h1, _ := kp.GetKeyHandle(ctx, trustDomain, ns, "key-a")
	h1.Rotate(ctx)

	h2, _ := kp.GetKeyHandle(ctx, trustDomain, ns, "key-b")
	h2.Rotate(ctx)

	// Concurrent reads
	const numReaders = 10
	var wg sync.WaitGroup
	wg.Add(numReaders)

	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				keyName := "key-a"
				if j%2 == 0 {
					keyName = "key-b"
				}

				h, _ := kp.GetKeyHandle(ctx, trustDomain, ns, keyName)
				_, _, err := h.Metadata(ctx)
				if err != nil {
					t.Errorf("Metadata failed: %v", err)
				}
			}
		}()
	}

	wg.Wait()
}

func TestDiskKeyProvider_CorruptedJSON(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	// Manually write corrupted JSON to the filesystem
	memFS.MkdirAll("/keys/test-ns", 0700)
	corruptedJSON := []byte("{invalid json}")
	err = memFS.WriteFileAtomic("/keys/test-ns/key-a.json", corruptedJSON, 0600)
	require.NoError(t, err)

	ctx := context.Background()
	trustDomain := "test.example.com"

	// Try to get the corrupted key
	handle, _ := kp.GetKeyHandle(ctx, trustDomain, "test-ns", "key-a")
	_, _, err = handle.Metadata(ctx)
	assert.Error(t, err)
}

func TestDiskKeyProvider_FileSystemPersistence(t *testing.T) {
	memFS := fs.NewMemFileSystem()

	// Create first key provider instance
	kp1, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	trustDomain := "test.example.com"
	ns := "test-ns"
	keyName := "key-a"

	// Create a key
	h1, _ := kp1.GetKeyHandle(ctx, trustDomain, ns, keyName)
	err = h1.Rotate(ctx)
	require.NoError(t, err)

	id1, _, _ := h1.Metadata(ctx)

	// Create second key provider instance (simulating restart)
	kp2, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	// Retrieve the key with second instance
	h2, _ := kp2.GetKeyHandle(ctx, trustDomain, ns, keyName)
	id2, _, err := h2.Metadata(ctx)
	require.NoError(t, err)

	assert.Equal(t, id1, id2)
}

func TestDiskKeyProvider_AtomicWrite(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	trustDomain := "test.example.com"
	ns := "test-ns"
	keyName := "key-a"

	// Create a key
	h, _ := kp.GetKeyHandle(ctx, trustDomain, ns, keyName)
	err = h.Rotate(ctx)
	require.NoError(t, err)

	// Verify the final file exists (trustDomain and namespace are separate directories)
	data, err := memFS.ReadFile("/keys/test.example.com/test-ns/key-a.json")
	require.NoError(t, err)

	// Verify it's valid JSON
	var keyData keyFileData
	err = json.Unmarshal(data, &keyData)
	require.NoError(t, err)
}

func TestDiskKeyProvider_InvalidKeyType(t *testing.T) {
	memFS := fs.NewMemFileSystem()

	// Try to create a key provider with invalid type
	_, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyType("invalid"),
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestNewDiskKeyProvider_EmptyKeysPath(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	_, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		FileSystem: memFS,
	})
	assert.Error(t, err)
}

func TestNewDiskKeyProvider_DefaultsToOSFileSystem(t *testing.T) {
	tempDir := t.TempDir()

	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:  KeyTypeECP256,
		KeysPath: tempDir,
	})
	require.NoError(t, err)

	assert.NotNil(t, kp.fs)
}

func TestDiskKeyProvider_ExplicitAlgorithm(t *testing.T) {
	memFS := fs.NewMemFileSystem()

	// Configure EC-P256 but explicitly ask for "ES256" (default)
	kp, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeECP256,
		Algorithm:  "ES256",
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	assert.Equal(t, "ES256", kp.algorithm)

	// Configure RSA-2048 but explicitly ask for "RS512" (non-default)
	kp2, err := NewDiskKeyProvider(DiskKeyProviderConfig{
		KeyType:    KeyTypeRSA2048,
		Algorithm:  "RS512",
		KeysPath:   "/keys2",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	assert.Equal(t, "RS512", kp2.algorithm)

	// Create a key and verify it uses the configured algorithm
	ctx := context.Background()
	trustDomain := "test.example.com"
	h, _ := kp2.GetKeyHandle(ctx, trustDomain, "test", "key-a")
	err = h.Rotate(ctx)
	require.NoError(t, err)

	_, alg, err := h.Metadata(ctx)
	require.NoError(t, err)
	assert.Equal(t, "RS512", alg)
}
