package keys

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

const (
	// Default timing parameters (hardcoded for now, configurable later)
	defaultKeyTTL            = 24 * time.Hour
	defaultRotationThreshold = 6 * time.Hour   // Rotate when 6h remaining
	defaultGracePeriod       = 2 * time.Hour   // Don't use new key for 2h after generation
	defaultCheckInterval     = 1 * time.Minute // How often to check for rotation
)

// DualSlotRotatingSigner manages automatic key rotation using a KeyProvider
type DualSlotRotatingSigner struct {
	namespace           string                 // Logical namespace for this signer
	trustDomain         string                 // Trust domain for namespacing
	keyProviderID       string                 // Current KeyProvider to use for new keys
	keyProviderRegistry map[string]KeyProvider // All available KeyProviders
	slotStore           KeySlotStore
	prepareTimeout      time.Duration // How long to wait before retrying a stuck "preparing" state

	// Timing parameters:
	//
	// key            TTL -                 rotation time +
	// generated      rotation threshold    grace period       TTL
	// ^--------------^---------------------^------------------^-------->
	//                new key generated     new key used       previous key removed

	// How long a key is available before it is no longer valid and must not be trusted.
	keyTTL time.Duration
	// How long within the key TTL that we consider the key to be eligible for rotation
	rotationThreshold time.Duration
	// How long after a key is generated that it is not eligible for use.
	// This should be some time less than rotation threshold,
	// so that we do not mint any tokens with the old key immediately before it expires.
	// However, it should not be too small,
	// to ensure clients have enough time to download the new key before it is used.
	gracePeriod time.Duration
	// How often to check for rotation and if key state has changed from another process.
	checkInterval time.Duration

	// Cached data (updated during rotation checks, read on hot path)
	mu               sync.RWMutex
	activeHandle     KeyHandle
	activeInternalID string              // Expected internal key ID (e.g. AWS KeyId)
	activeThumbprint KeyID               // Public key ID (JWK Thumbprint)
	activeAlg        Algorithm           // JWT Algorithm
	publicKeys       []service.PublicKey // All non-expired public keys

	clock  clock.Clock
	ticker clock.Ticker
}

// DualSlotRotatingSignerConfig configures the DualSlotRotatingSigner
type DualSlotRotatingSignerConfig struct {
	Namespace           string                 // Logical namespace for this signer
	TrustDomain         string                 // Trust domain for namespacing
	KeyProviderID       string                 // Current KeyProvider to use for new keys
	KeyProviderRegistry map[string]KeyProvider // All available KeyProviders
	SlotStore           KeySlotStore
	Clock               clock.Clock

	// Optional timing overrides (uses defaults if not set)
	KeyTTL            time.Duration
	RotationThreshold time.Duration
	GracePeriod       time.Duration
	CheckInterval     time.Duration
	PrepareTimeout    time.Duration // How long to wait before retrying a stuck "preparing" state (default: 1 minute)
}

// NewDualSlotRotatingSigner creates a new dual-slot rotating signer
func NewDualSlotRotatingSigner(cfg DualSlotRotatingSignerConfig) *DualSlotRotatingSigner {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	keyTTL := cfg.KeyTTL
	if keyTTL == 0 {
		keyTTL = defaultKeyTTL
	}

	rotationThreshold := cfg.RotationThreshold
	if rotationThreshold == 0 {
		rotationThreshold = defaultRotationThreshold
	}

	gracePeriod := cfg.GracePeriod
	if gracePeriod == 0 {
		gracePeriod = defaultGracePeriod
	}

	checkInterval := cfg.CheckInterval
	if checkInterval == 0 {
		checkInterval = defaultCheckInterval
	}

	prepareTimeout := cfg.PrepareTimeout
	if prepareTimeout == 0 {
		prepareTimeout = 1 * time.Minute
	}

	return &DualSlotRotatingSigner{
		namespace:           cfg.Namespace,
		trustDomain:         cfg.TrustDomain,
		keyProviderID:       cfg.KeyProviderID,
		keyProviderRegistry: cfg.KeyProviderRegistry,
		slotStore:           cfg.SlotStore,
		keyTTL:              keyTTL,
		rotationThreshold:   rotationThreshold,
		gracePeriod:         gracePeriod,
		checkInterval:       checkInterval,
		prepareTimeout:      prepareTimeout,
		clock:               clk,
	}
}

// keyName returns the stable key name for a slot position
func (r *DualSlotRotatingSigner) keyName(p SlotPosition) string {
	if p == SlotPositionA {
		return "key-a"
	}
	return "key-b"
}

// Start begins the background key rotation process
func (r *DualSlotRotatingSigner) Start(ctx context.Context) error {
	// Ensure we have at least one key
	if err := r.ensureInitialKey(ctx); err != nil {
		return fmt.Errorf("failed to ensure initial key: %w", err)
	}

	// Initialize active key cache
	if err := r.updateActiveKeyCache(ctx); err != nil {
		return fmt.Errorf("failed to initialize active key cache: %w", err)
	}

	// Start background rotation ticker
	r.ticker = r.clock.Ticker(r.checkInterval)
	if err := r.ticker.Start(r.doRotationCheck); err != nil {
		return fmt.Errorf("failed to start rotation ticker: %w", err)
	}

	return nil
}

// Stop gracefully stops the background rotation process
func (r *DualSlotRotatingSigner) Stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
}

// doRotationCheck is called periodically by the ticker to check for rotation needs
func (r *DualSlotRotatingSigner) doRotationCheck(ctx context.Context) {
	if err := r.checkAndRotate(ctx); err != nil {
		log.Printf("Error during key rotation check: %v", err)
	}
	// Update active key cache after each check (whether rotation happened or not)
	if err := r.updateActiveKeyCache(ctx); err != nil {
		log.Printf("Error updating active key cache: %v", err)
	}
}

// contextSigner wraps a KeyHandle to implement crypto.Signer with context and mismatch detection
type contextSigner struct {
	handle     KeyHandle
	ctx        context.Context
	expectedID string
}

func (s *contextSigner) Public() crypto.PublicKey {
	pub, _ := s.handle.Public(s.ctx)
	return pub
}

func (s *contextSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, usedID, err := s.handle.Sign(s.ctx, digest, opts)
	if err != nil {
		return nil, err
	}
	if usedID != s.expectedID {
		return nil, ErrKeyMismatch
	}
	return sig, nil
}

// GetCurrentSigner returns a crypto.Signer for the current active key along with its key ID and algorithm
func (r *DualSlotRotatingSigner) GetCurrentSigner(ctx context.Context) (crypto.Signer, KeyID, Algorithm, error) {
	r.mu.RLock()
	handle := r.activeHandle
	internalID := r.activeInternalID
	thumbprint := r.activeThumbprint
	alg := r.activeAlg
	r.mu.RUnlock()

	if handle == nil {
		return nil, "", "", fmt.Errorf("no active key available")
	}

	signer := &contextSigner{
		handle:     handle,
		ctx:        ctx,
		expectedID: internalID,
	}

	return signer, thumbprint, alg, nil
}

// PublicKeys returns all non-expired public keys from cache
func (r *DualSlotRotatingSigner) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	r.mu.RLock()
	keys := make([]service.PublicKey, len(r.publicKeys))
	copy(keys, r.publicKeys)
	r.mu.RUnlock()

	return keys, nil
}

// ensureInitialKey ensures at least one key exists, generating key-a if needed
func (r *DualSlotRotatingSigner) ensureInitialKey(ctx context.Context) error {
	slots, version, err := r.slotStore.ListSlots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	// Check if we have any slots for this namespace
	hasSlots := false
	for _, slot := range slots {
		if slot.Namespace == r.namespace && slot.KeyProviderID == r.keyProviderID {
			hasSlots = true
			break
		}
	}

	// If we have any slots for this namespace, we're already initialized
	if hasSlots {
		return nil
	}

	// Get current KeyProvider
	provider, ok := r.keyProviderRegistry[r.keyProviderID]
	if !ok {
		return fmt.Errorf("key provider not found: %s", r.keyProviderID)
	}

	keyName := r.keyName(SlotPositionA)
	handle, err := provider.GetKeyHandle(ctx, r.trustDomain, r.namespace, keyName)
	if err != nil {
		return fmt.Errorf("failed to get key handle: %w", err)
	}

	if err := handle.Rotate(ctx); err != nil {
		return fmt.Errorf("failed to rotate initial key: %w", err)
	}

	// Save slot
	now := r.clock.Now()
	slotA := &KeySlot{
		Position:            SlotPositionA,
		Namespace:           r.namespace,
		KeyProviderID:       r.keyProviderID,
		RotationCompletedAt: &now,
	}

	_, err = r.slotStore.SaveSlot(ctx, slotA, version)
	if err != nil {
		return fmt.Errorf("failed to save slot A: %w", err)
	}

	return nil
}

// checkAndRotate checks if rotation is needed and performs it using two-phase rotation
func (r *DualSlotRotatingSigner) checkAndRotate(ctx context.Context) error {
	// 1. Read all slots and store version
	slots, storeVersion, err := r.slotStore.ListSlots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	// Filter slots to find slotA and slotB for this token type
	var slotA, slotB *KeySlot
	for _, slot := range slots {
		if slot.Namespace != r.namespace || slot.KeyProviderID != r.keyProviderID {
			continue
		}
		switch slot.Position {
		case SlotPositionA:
			slotA = slot
		case SlotPositionB:
			slotB = slot
		default:
			return fmt.Errorf("unexpected slot position for namespace %s: %s", r.namespace, slot.Position)
		}
	}

	// 2. Determine which slot needs rotation and which slot to rotate TO
	sourceSlot, targetSlot := r.selectSlotsForRotation(slotA, slotB)
	if sourceSlot == nil || targetSlot == nil {
		return nil // No rotation needed
	}

	now := r.clock.Now()

	// 3. Check if target slot is NOT in "preparing" state - if so, mark it as preparing
	if targetSlot.PreparingAt != nil {
		if now.Sub(*targetSlot.PreparingAt) < r.prepareTimeout {
			// Already preparing and not timed out, wait for the other process
			return nil
		}
		// else: timed out, proceed to generate key
	}

	targetSlot.PreparingAt = &now
	// Use current KeyProvider for new key
	targetSlot.KeyProviderID = r.keyProviderID
	storeVersion, err = r.slotStore.SaveSlot(ctx, targetSlot, storeVersion)
	if errors.Is(err, ErrVersionMismatch) {
		return nil // Another process won, that's fine
	}
	if err != nil {
		return err
	}

	// 4. Generate key and complete rotation using current KeyProvider
	provider, ok := r.keyProviderRegistry[r.keyProviderID]
	if !ok {
		return fmt.Errorf("key provider not found: %s", r.keyProviderID)
	}

	keyName := r.keyName(targetSlot.Position)
	handle, err := provider.GetKeyHandle(ctx, r.trustDomain, r.namespace, keyName)
	if err != nil {
		return fmt.Errorf("failed to get key handle: %w", err)
	}

	if err := handle.Rotate(ctx); err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	// 5. Update slot with rotation completed, clear preparing state
	targetSlot.PreparingAt = nil
	targetSlot.RotationCompletedAt = &now

	_, err = r.slotStore.SaveSlot(ctx, targetSlot, storeVersion)
	if errors.Is(err, ErrVersionMismatch) {
		log.Printf("Another process completed rotation for slot %s, skipping", targetSlot.Position)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to save slot: %w", err)
	}

	log.Printf("Completed rotation for slot %s", targetSlot.Position)

	return nil
}

// selectSlotsForRotation determines which slot needs rotation and which slot to rotate to
// Returns (sourceSlot, targetSlot) where sourceSlot has the key that needs rotation
// and targetSlot is where the new key should be placed
func (r *DualSlotRotatingSigner) selectSlotsForRotation(slotA, slotB *KeySlot) (*KeySlot, *KeySlot) {
	now := r.clock.Now()

	// Helper to check if slot needs rotation
	needsRotation := func(slot *KeySlot) bool {
		if slot == nil {
			return false
		}

		// Check if key is expired - expired keys don't need rotation
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			if !now.Before(expiresAt) {
				// Key is expired or expiring now, don't rotate it
				return false
			}

			// Check if key is approaching expiration (within rotation threshold)
			rotateAt := expiresAt.Add(-r.rotationThreshold)
			return !now.Before(rotateAt) // >= rotateAt
		}

		return false
	}

	aNeeds := needsRotation(slotA)
	bNeeds := needsRotation(slotB)

	// If both need rotation (shouldn't normally happen), rotate the older one
	if aNeeds && bNeeds {
		// Pick the older key (earlier RotationCompletedAt)
		if slotA.RotationCompletedAt != nil && slotB.RotationCompletedAt != nil {
			if slotA.RotationCompletedAt.Before(*slotB.RotationCompletedAt) {
				return slotA, slotB
			}
			return slotB, slotA
		}
	}

	// Check slot A - if it needs rotation, rotate to slot B
	if aNeeds {
		// Initialize slot B if it doesn't exist
		if slotB == nil {
			slotB = &KeySlot{
				Position:      SlotPositionB,
				Namespace:     r.namespace,
				KeyProviderID: r.keyProviderID,
			}
		}
		// Don't rotate if target slot (B) already has a recent key
		// This prevents re-rotating A to B when B was just created
		if slotB.RotationCompletedAt != nil {
			// If B is newer than A, don't rotate A again
			if slotA.RotationCompletedAt != nil && slotB.RotationCompletedAt.After(*slotA.RotationCompletedAt) {
				return nil, nil // B is already the newer key
			}
		}
		return slotA, slotB
	}

	// Check slot B - if it needs rotation, rotate to slot A
	if bNeeds {
		// Initialize slot A if it doesn't exist (shouldn't happen but be safe)
		if slotA == nil {
			slotA = &KeySlot{
				Position:      SlotPositionA,
				Namespace:     r.namespace,
				KeyProviderID: r.keyProviderID,
			}
		}
		// Don't rotate if target slot (A) already has a recent key
		// This prevents re-rotating A to B when B was just created
		if slotA.RotationCompletedAt != nil {
			// If A is newer than B, don't rotate B again
			if slotB.RotationCompletedAt != nil && slotA.RotationCompletedAt.After(*slotB.RotationCompletedAt) {
				return nil, nil // A is already the newer key
			}
		}
		return slotB, slotA
	}

	return nil, nil
}

// updateActiveKeyCache queries the state store and updates the cached active key and public keys
func (r *DualSlotRotatingSigner) updateActiveKeyCache(ctx context.Context) error {
	slots, _, err := r.slotStore.ListSlots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	// Filter slots for this token type
	// TODO: maybe push token type filtering to the store rather than do it in memory after retrieving everything
	var mySlots []*KeySlot
	for _, slot := range slots {
		if slot.Namespace == r.namespace && slot.KeyProviderID == r.keyProviderID {
			mySlots = append(mySlots, slot)
		}
	}

	if len(mySlots) == 0 {
		return errors.New("no slots available for this token type")
	}

	now := r.clock.Now()
	var activeSlot *KeySlot
	var publicKeys []service.PublicKey

	// Build list of all non-expired keys and categorize by grace period status
	var preferredSlots []*KeySlot           // Keys past grace period
	var fallbackSlots []*KeySlot            // Keys still in grace period
	thumbprints := make(map[*KeySlot]KeyID) // Cache computed thumbprints

	for _, slot := range mySlots {
		// Check if key is expired
		isExpired := false
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			if !now.Before(expiresAt) {
				isExpired = true
			}
		}

		if isExpired {
			continue
		}

		// Get the KeyProvider that created this key
		provider, ok := r.keyProviderRegistry[slot.KeyProviderID]
		if !ok {
			log.Printf("Warning: key provider %s not found for slot %s, skipping", slot.KeyProviderID, slot.Position)
			continue
		}

		keyName := r.keyName(slot.Position)
		handle, err := provider.GetKeyHandle(ctx, r.trustDomain, r.namespace, keyName)
		if err != nil {
			log.Printf("Warning: failed to get handle %s from key provider: %v", slot.Position, err)
			continue
		}

		pubKey, err := handle.Public(ctx)
		if err != nil {
			log.Printf("Warning: failed to get public key for %s: %v", slot.Position, err)
			continue
		}

		thumbprintStr, err := ComputeThumbprint(pubKey)
		if err != nil {
			log.Printf("Warning: failed to compute thumbprint for key %s: %v", slot.Position, err)
			continue
		}
		thumbprint := KeyID(thumbprintStr)
		thumbprints[slot] = thumbprint

		_, algStr, err := handle.Metadata(ctx)
		if err != nil {
			log.Printf("Warning: failed to get metadata for %s: %v", slot.Position, err)
			continue
		}
		alg := Algorithm(algStr)

		publicKeys = append(publicKeys, service.PublicKey{
			KeyID:     string(thumbprint),
			Algorithm: string(alg),
			Key:       pubKey,
			Use:       "sig",
		})

		// Check if this key is past grace period
		pastGracePeriod := true
		if slot.RotationCompletedAt != nil {
			gracePeriodEnd := slot.RotationCompletedAt.Add(r.gracePeriod)
			if now.Before(gracePeriodEnd) {
				pastGracePeriod = false
			}
		}

		// Categorize by grace period status
		if pastGracePeriod {
			preferredSlots = append(preferredSlots, slot)
		} else {
			fallbackSlots = append(fallbackSlots, slot)
		}
	}

	// Select active key: prefer keys past grace period (newest),
	// fall back to keys in grace period (oldest for longest distribution time)
	if len(preferredSlots) > 0 {
		// Use newest key past grace period (most recently completed rotation)
		activeSlot = findNewestSlot(preferredSlots)
	} else if len(fallbackSlots) > 0 {
		// Use oldest key in grace period (gives longest time for distribution)
		activeSlot = findOldestSlot(fallbackSlots)
	}

	if activeSlot == nil {
		return errors.New("no keys available")
	}

	// Get the KeyProvider that created the active key
	provider, ok := r.keyProviderRegistry[activeSlot.KeyProviderID]
	if !ok {
		return fmt.Errorf("key provider %s not found for active slot", activeSlot.KeyProviderID)
	}

	keyName := r.keyName(activeSlot.Position)
	activeHandle, err := provider.GetKeyHandle(ctx, r.trustDomain, r.namespace, keyName)
	if err != nil {
		return fmt.Errorf("failed to get active handle %s: %w", activeSlot.Position, err)
	}

	internalID, algStr, err := activeHandle.Metadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to get active metadata %s: %w", activeSlot.Position, err)
	}
	alg := Algorithm(algStr)

	r.mu.Lock()
	r.activeHandle = activeHandle
	r.activeInternalID = internalID
	r.activeThumbprint = thumbprints[activeSlot]
	r.activeAlg = alg
	r.publicKeys = publicKeys
	r.mu.Unlock()

	return nil
}

// findNewestSlot returns the slot with the most recent RotationCompletedAt timestamp.
// This is used to select the active key from slots that are past their grace period.
func findNewestSlot(slots []*KeySlot) *KeySlot {
	if len(slots) == 0 {
		return nil
	}
	newest := slots[0]
	for _, slot := range slots[1:] {
		if slot.RotationCompletedAt != nil && newest.RotationCompletedAt != nil {
			if slot.RotationCompletedAt.After(*newest.RotationCompletedAt) {
				newest = slot
			}
		}
	}
	return newest
}

// findOldestSlot returns the slot with the earliest RotationCompletedAt timestamp.
// This is used to select a fallback key from slots still in their grace period,
// giving the key the longest time for distribution before becoming active.
func findOldestSlot(slots []*KeySlot) *KeySlot {
	if len(slots) == 0 {
		return nil
	}
	oldest := slots[0]
	for _, slot := range slots[1:] {
		if slot.RotationCompletedAt != nil && oldest.RotationCompletedAt != nil {
			if slot.RotationCompletedAt.Before(*oldest.RotationCompletedAt) {
				oldest = slot
			}
		}
	}
	return oldest
}
