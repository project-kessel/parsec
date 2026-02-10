package keys

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/clock"
)

const testTokenType = "urn:ietf:params:oauth:token-type:txn_token"

// Mock KeyProvider for failure injection
type failKeyProvider struct {
	*InMemoryKeyProvider
	failCreate bool
}

func (m *failKeyProvider) GetKeyHandle(ctx context.Context, trustDomain, namespace, keyName string) (KeyHandle, error) {
	handle, err := m.InMemoryKeyProvider.GetKeyHandle(ctx, trustDomain, namespace, keyName)
	if err != nil {
		return nil, err
	}
	return &failKeyHandle{handle: handle, failCreate: m.failCreate}, nil
}

type failKeyHandle struct {
	handle     KeyHandle
	failCreate bool
}

func (h *failKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	return h.handle.Sign(ctx, digest, opts)
}
func (h *failKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	return h.handle.Metadata(ctx)
}
func (h *failKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	return h.handle.Public(ctx)
}
func (h *failKeyHandle) Rotate(ctx context.Context) error {
	if h.failCreate {
		return assert.AnError
	}
	return h.handle.Rotate(ctx)
}

// Helper to create a test DualSlotRotatingSigner with a fake clock and in memory storage
func newTestDualSlotRotatingSigner(t *testing.T, clk clock.Clock, slotStore KeySlotStore, keyProvider KeyProvider) (*DualSlotRotatingSigner, KeyProvider) {
	if keyProvider == nil {
		// Create an in-memory KeyProvider with EC-P256 key type
		keyProvider = NewInMemoryKeyProvider(KeyTypeECP256, "ES256")
	}

	// Create in-memory slot store if needed
	if slotStore == nil {
		slotStore = NewInMemoryKeySlotStore()
	}

	// Create key provider registry
	kpRegistry := map[string]KeyProvider{
		"test-provider": keyProvider,
	}

	// Create rotating signer with short timings for testing
	rs := NewDualSlotRotatingSigner(DualSlotRotatingSignerConfig{
		Namespace:           testTokenType, // Test namespace
		KeyProviderID:       "test-provider",
		KeyProviderRegistry: kpRegistry,
		SlotStore:           slotStore,
		Clock:               clk,
		// Short timings for faster tests
		KeyTTL:            30 * time.Minute, // Longer to avoid premature expiration
		RotationThreshold: 8 * time.Minute,  // Rotate when 8m remaining
		GracePeriod:       2 * time.Minute,
		CheckInterval:     10 * time.Second,
		PrepareTimeout:    1 * time.Minute,
	})

	return rs, keyProvider
}

func TestDualSlotRotatingSigner_RotationFailure_MaintainsOldKey(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	// Setup backing key provider that we can make fail
	baseProvider := NewInMemoryKeyProvider(KeyTypeECP256, "ES256")
	mockProvider := &failKeyProvider{InMemoryKeyProvider: baseProvider}

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, mockProvider)

	ctx := context.Background()

	// 1. Start (succeeds)
	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Get initial key ID
	clk.Advance(10 * time.Second)
	_, keyID1, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// 2. Advance to just before rotation threshold (22m)
	// KeyTTL=30m, Threshold=8m => Rotate at 22m
	clk.Advance(21 * time.Minute)

	// 3. Set mockProvider to fail BEFORE rotation is attempted
	mockProvider.failCreate = true

	// 4. Advance past rotation threshold (to 23m)
	clk.Advance(2 * time.Minute)

	// 5. Verify we still have the old key active (rotation failed)
	_, keyID2, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, keyID1, keyID2, "should maintain old key on rotation failure")

	// 6. Advance PAST expiration (KeyTTL = 30m, we are at ~23m + 10s)
	// Need to go past 30m total.
	clk.Advance(10 * time.Minute) // Now at ~33m

	// 7. Verify behavior - we expect it to keep using the cached key (graceful degradation)
	// even though it is expired in the store, the cache hasn't been updated because updateActiveKeyCache failed
	_, keyID3, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err, "should still have active key from cache even if expired")
	assert.Equal(t, keyID1, keyID3, "should maintain old key even after expiration if rotation fails")
}

func TestDualSlotRotatingSigner_InitialKeyGeneration(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	// Start should generate initial key
	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	signer, keyID, algorithm, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotEmpty(t, string(keyID))
	assert.Equal(t, "ES256", string(algorithm))
}

func TestDualSlotRotatingSigner_InitialKeyRotationCompletedAtIsNow(t *testing.T) {
	// Use a specific time for the clock to make assertions clear
	startTime := time.Date(2025, 10, 27, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(startTime)
	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	// Start should generate initial key
	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Check that the initial key's RotationCompletedAt is set to the current clock time
	// (not backdated to circumvent grace period)
	slotStore := rs.slotStore
	slots, _, err := slotStore.ListSlots(ctx)
	require.NoError(t, err)
	require.Len(t, slots, 1, "should have 1 slot")

	var slotA *KeySlot
	for _, s := range slots {
		if s.Position == SlotPositionA {
			slotA = s
			break
		}
	}
	require.NotNil(t, slotA, "slot A should exist")
	require.NotNil(t, slotA.RotationCompletedAt, "initial key should have RotationCompletedAt set")

	assert.Equal(t, startTime, *slotA.RotationCompletedAt,
		"initial key RotationCompletedAt should equal clock time (not backdated)")
}

func TestDualSlotRotatingSigner_InitialKeyInGracePeriod(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	// Start generates initial key (set in the past, immediately active)
	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Trigger first rotation check
	clk.Advance(10 * time.Second)

	// Initial key should be immediately active (no grace period for first key)
	signer, _, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestDualSlotRotatingSigner_PublicKeysIncludesGracePeriodKeys(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Trigger first rotation check to populate cache
	clk.Advance(10 * time.Second)

	// Public keys should include the initial key
	publicKeys, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys, 1, "should have 1 key")
	assert.Equal(t, "ES256", publicKeys[0].Algorithm)
	assert.Equal(t, "sig", publicKeys[0].Use)
}

func TestDualSlotRotatingSigner_KeyRotation(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Wait for initial key to be active
	clk.Advance(10 * time.Second) // Trigger first check

	// signer1 is wrapper
	_, keyID1, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Advance time to trigger rotation (past rotation threshold)
	// KeyTTL=30m, RotationThreshold=8m, so rotation at 22m
	clk.Advance(23 * time.Minute)

	// Should have generated a new key
	publicKeys, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys, 2, "should have 2 keys after rotation")

	// Active key should still be the old one (new key in grace period of 2m)
	_, keyID2, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, string(keyID1), string(keyID2), "active key should not change during grace period")

	// After new key's grace period, should switch to new key
	clk.Advance(3 * time.Minute) // Past 2m grace period

	_, keyID3, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, string(keyID1), string(keyID3), "active key should change after grace period")
}

func TestDualSlotRotatingSigner_KeyExpiration(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Initial key is active
	clk.Advance(10 * time.Second)

	publicKeys1, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys1, 1)

	// Trigger rotation at 22m (30m TTL - 8m threshold)
	clk.Advance(23 * time.Minute)

	publicKeys2, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys2, 2, "should have 2 keys after rotation")

	// Advance past first key's expiration (30 minutes from initial creation)
	clk.Advance(8 * time.Minute) // ~31m total, first key expires at 30m

	publicKeys3, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys3, 1, "expired key should be removed from public keys")

	// Should only have the newer key (the rotated one)
	// KeyID is now a JWK Thumbprint (base64url encoded)
	assert.NotEmpty(t, publicKeys3[0].KeyID, "should have a valid key ID")
	// Verify it's different from the first key (rotation happened)
	assert.NotEqual(t, publicKeys1[0].KeyID, publicKeys3[0].KeyID, "should have rotated to a new key")
}

func TestDualSlotRotatingSigner_AlternatingSlots(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Get initial key
	clk.Advance(10 * time.Second)

	_, keyID1, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, string(keyID1), "first key should have an ID")

	// Rotate to second slot at 22m, active at 24m
	clk.Advance(23 * time.Minute) // Trigger rotation at 22m
	clk.Advance(3 * time.Minute)  // Past 2m grace period

	_, keyID2, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, string(keyID2), "second key should have an ID")
	assert.NotEqual(t, keyID1, keyID2, "second key should be different from first")

	// Rotate back to first slot (another 22m, active at 24m from second key creation)
	clk.Advance(23 * time.Minute) // Trigger rotation
	clk.Advance(3 * time.Minute)  // Past grace period

	_, keyID3, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, string(keyID3), "third key should have an ID")
	assert.NotEqual(t, keyID2, keyID3, "third key should be different from second")
	assert.NotEqual(t, keyID1, keyID3, "third key should be different from first (new key in same slot)")
}

func TestDualSlotRotatingSigner_SigningWorks(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Wait for key to be active
	clk.Advance(10 * time.Second)

	signer, keyID, algorithm, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Sign some data (must hash first for ECDSA)
	data := []byte("test message")
	hash := crypto.SHA256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	signature, err := signer.Sign(nil, hashed, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify we get the right metadata
	assert.NotEmpty(t, string(keyID))
	assert.Equal(t, "ES256", string(algorithm))

	// Public key should be available for verification
	publicKeys, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	require.Len(t, publicKeys, 1)

	assert.Equal(t, string(keyID), publicKeys[0].KeyID)
	assert.Equal(t, signer.Public(), publicKeys[0].Key)
}

func TestDualSlotRotatingSigner_MultipleRotations(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Track key IDs through multiple rotations
	var keyIDs []string

	// Initial key
	clk.Advance(10 * time.Second)

	_, keyID, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	keyIDs = append(keyIDs, string(keyID))

	// Perform 3 rotations
	for i := 0; i < 3; i++ {
		// Trigger rotation at threshold
		clk.Advance(23 * time.Minute)

		// Wait for grace period
		clk.Advance(3 * time.Minute)

		_, keyID, _, err := rs.GetCurrentSigner(ctx)
		require.NoError(t, err)
		keyIDs = append(keyIDs, string(keyID))
	}

	// Should have 4 key IDs
	assert.Len(t, keyIDs, 4)

	// Verify they are all unique (each is a JWK Thumbprint)
	uniqueKeys := make(map[string]bool)
	for _, kid := range keyIDs {
		assert.NotEmpty(t, kid, "key ID should not be empty")
		assert.False(t, uniqueKeys[kid], "key ID %s should be unique", kid)
		uniqueKeys[kid] = true
	}
	assert.Len(t, uniqueKeys, 4, "all key IDs should be unique")
}

func TestDualSlotRotatingSigner_SlotStoreOptimisticLocking(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Wait for initial key in slot A
	clk.Advance(10 * time.Second)

	// Get the slot store
	slotStore := rs.slotStore

	// Get initial state and version
	slots, version1, err := slotStore.ListSlots(ctx)
	require.NoError(t, err)
	require.Len(t, slots, 1, "should have 1 slot")
	require.NotEqual(t, "", version1, "version should not be empty")

	// Find slotA
	var slotA *KeySlot
	for _, s := range slots {
		if s.Position == SlotPositionA {
			slotA = s
			break
		}
	}
	require.NotNil(t, slotA, "should find slot-a")

	// Test optimistic locking: Save with correct version should succeed
	slotA.KeyProviderID = "test-provider-2" // Modify something
	version2, err := slotStore.SaveSlot(ctx, slotA, version1)
	require.NoError(t, err, "should succeed with correct version")
	assert.NotEqual(t, version1, version2, "version should change after save")

	// Try to save with old version - should fail
	slotA.KeyProviderID = "test-provider-3"
	_, err = slotStore.SaveSlot(ctx, slotA, version1) // Old version
	assert.ErrorIs(t, err, ErrVersionMismatch, "should fail with old version")

	// Save with correct (current) version should succeed
	version3, err := slotStore.SaveSlot(ctx, slotA, version2)
	require.NoError(t, err, "should succeed with current version")
	assert.NotEqual(t, version2, version3, "version should change after second save")
}

func TestDualSlotRotatingSigner_CachedPublicKeys(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	rs, keyProvider := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Wait for initial key
	clk.Advance(10 * time.Second)

	// Get public keys (should be from cache)
	publicKeys1, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys1, 1)

	// Verify the public key matches what's in the KeyProvider
	handle, err := keyProvider.GetKeyHandle(ctx, "", testTokenType, "key-a")
	require.NoError(t, err)

	pubKey, err := handle.Public(ctx)
	require.NoError(t, err)

	assert.Equal(t, pubKey, publicKeys1[0].Key)

	// Call PublicKeys again - should return cached data (same pointer)
	publicKeys2, err := rs.PublicKeys(ctx)
	require.NoError(t, err)

	// Should be equivalent but not the same slice (we make a copy)
	assert.Equal(t, publicKeys1, publicKeys2)
}

func TestDualSlotRotatingSigner_NoKeysBeforeStart(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	// Before Start, GetCurrentSigner should fail
	_, _, _, err := rs.GetCurrentSigner(ctx)
	assert.Error(t, err)

	// PublicKeys should return empty
	publicKeys, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, publicKeys)
}

func TestDualSlotRotatingSigner_StopPreventsRotation(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)

	// Wait for initial key
	clk.Advance(10 * time.Second)

	_, keyID1, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Stop the manager
	rs.Stop()

	// Advance time past rotation threshold
	clk.Advance(25 * time.Minute)

	// Key should not have rotated (manager stopped)
	// GetCurrentSigner should still return the cached key
	_, keyID2, _, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, string(keyID1), string(keyID2))
}

func TestDualSlotRotatingSigner_AlgorithmIsCorrect(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rs, _ := newTestDualSlotRotatingSigner(t, clk, nil, nil)

	ctx := context.Background()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Wait for initial key
	clk.Advance(10 * time.Second)

	_, _, algorithm, err := rs.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ES256", string(algorithm))

	// Public keys should also have the algorithm
	publicKeys, err := rs.PublicKeys(ctx)
	require.NoError(t, err)
	require.Len(t, publicKeys, 1)
	assert.Equal(t, "ES256", publicKeys[0].Algorithm)
}

func TestDualSlotRotatingSigner_ExistingKeyInGracePeriod(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	slotStore := NewInMemoryKeySlotStore()
	rs, provider := newTestDualSlotRotatingSigner(t, clk, slotStore, nil)

	ctx := context.Background()

	startTime := clk.Now()

	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	clk.Advance(10 * time.Second)

	// Now create a new manager, reusing same slot store
	rm2, _ := newTestDualSlotRotatingSigner(t, clk, slotStore, provider)

	err = rm2.Start(ctx)
	require.NoError(t, err)
	defer rm2.Stop()

	slots, _, err := slotStore.ListSlots(ctx)
	require.NoError(t, err)
	require.Len(t, slots, 1)
	assert.Equal(t, startTime, *slots[0].RotationCompletedAt)
}

func TestDualSlotRotatingSigner_Namespacing(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	provider := NewInMemoryKeyProvider(KeyTypeECP256, "ES256")
	providerRegistry := map[string]KeyProvider{"test-provider": provider}
	slotStore := NewInMemoryKeySlotStore()

	trustDomain := "example.com"

	rs := NewDualSlotRotatingSigner(DualSlotRotatingSignerConfig{
		Namespace:           testTokenType,
		TrustDomain:         trustDomain,
		KeyProviderID:       "test-provider",
		KeyProviderRegistry: providerRegistry,
		SlotStore:           slotStore,
		Clock:               clk,
		PrepareTimeout:      1 * time.Minute,
	})

	ctx := context.Background()
	err := rs.Start(ctx)
	require.NoError(t, err)
	defer rs.Stop()

	// Check that key was created with correct namespace
	handle, err := provider.GetKeyHandle(ctx, trustDomain, testTokenType, "key-a")
	require.NoError(t, err)

	_, _, err = handle.Metadata(ctx)
	require.NoError(t, err)

	// Verify we cannot get it without trustDomain (GetKeyHandle succeeds but Metadata fails)
	handleBad, err := provider.GetKeyHandle(ctx, "", testTokenType, "key-a")
	require.NoError(t, err)

	_, _, err = handleBad.Metadata(ctx)
	assert.Error(t, err)
}
