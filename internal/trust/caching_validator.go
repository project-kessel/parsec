package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/project-kessel/parsec/internal/cache"
	"github.com/project-kessel/parsec/internal/clock"
)

// InMemoryCachingValidator wraps a cacheable validator with local caching.
type InMemoryCachingValidator struct {
	name      string
	source    Validator
	cacheable CacheableValidator
	cacheTTL  time.Duration
	clock     clock.Clock
	observer  InMemoryCachingValidatorObserver
	mu        sync.RWMutex
	entries   map[string]*validatorCacheEntry
}

type validatorCacheEntry struct {
	result    *Result
	expiresAt time.Time
}

// InMemoryCachingValidatorOption configures InMemoryCachingValidator.
type InMemoryCachingValidatorOption func(*InMemoryCachingValidator)

// WithValidatorCacheClock sets the cache clock.
func WithValidatorCacheClock(clk clock.Clock) InMemoryCachingValidatorOption {
	return func(v *InMemoryCachingValidator) {
		v.clock = clk
	}
}

// WithValidatorCacheTTL sets the time-to-live for cached entries.
// Return 0 to let result expiration be the only expiry bound.
func WithValidatorCacheTTL(ttl time.Duration) InMemoryCachingValidatorOption {
	return func(v *InMemoryCachingValidator) {
		v.cacheTTL = ttl
	}
}

// NewInMemoryCachingValidator wraps a validator with in-memory caching if it
// implements CacheableValidator. It returns the original validator otherwise.
func NewInMemoryCachingValidator(name string, source Validator, obs InMemoryCachingValidatorObserver, opts ...InMemoryCachingValidatorOption) Validator {
	cacheable, ok := source.(CacheableValidator)
	if !ok {
		return source
	}
	if name == "" {
		name = "validator"
	}
	if obs == nil {
		obs = NoOpTrustObserver{}
	}

	v := &InMemoryCachingValidator{
		name:      name,
		source:    source,
		cacheable: cacheable,
		clock:     clock.NewSystemClock(),
		observer:  obs,
		entries:   make(map[string]*validatorCacheEntry),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// CredentialTypes implements Validator.
func (v *InMemoryCachingValidator) CredentialTypes() []CredentialType {
	return v.source.CredentialTypes()
}

// Validate checks the cache first, then validates on a miss.
func (v *InMemoryCachingValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	ctx, p := v.observer.InMemoryValidateStarted(ctx, v.name)
	defer p.End()

	cacheInput, err := v.cacheable.CacheKey(ctx, credential)
	if err != nil {
		p.CacheKeyFailed(err)
		return v.source.Validate(ctx, credential)
	}

	cacheKey, err := serializeValidatorInput(cacheInput)
	if err != nil {
		p.CacheKeyFailed(err)
		return v.source.Validate(ctx, credential)
	}

	v.mu.RLock()
	entry, found := v.entries[cacheKey]
	v.mu.RUnlock()

	if found {
		if entry.expiresAt.IsZero() || v.clock.Now().Before(entry.expiresAt) {
			p.CacheHit()
			return entry.result, nil
		}
		p.CacheExpired()
		v.mu.Lock()
		delete(v.entries, cacheKey)
		v.mu.Unlock()
	} else {
		p.CacheMiss()
	}

	result, err := v.source.Validate(ctx, credential)
	if err != nil {
		p.SourceFailed(err)
		return nil, err
	}

	if expiresAt, ok := validatorCacheExpiry(v.clock.Now(), v.cacheTTL, result); ok {
		v.mu.Lock()
		v.entries[cacheKey] = &validatorCacheEntry{
			result:    result,
			expiresAt: expiresAt,
		}
		v.mu.Unlock()
	}

	return result, nil
}

// Size returns the number of cached entries.
func (v *InMemoryCachingValidator) Size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

// Cleanup removes expired entries.
func (v *InMemoryCachingValidator) Cleanup() {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.clock.Now()
	for key, entry := range v.entries {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(v.entries, key)
		}
	}
}

// distributedCacheLoadedKey is used to detect, within the current process,
// whether a Get resulted in a local fetch (cache miss) or was served from
// cache (hit). Values loaded by a remote peer in a distributed groupcache
// deployment cannot be distinguished this way and are reported as hits;
// this is a known limitation of groupcache's peer-to-peer design.
type distributedCacheLoadedKey struct{}

// sourceValidationError marks a loader error that is the source validator's
// verdict on the credential (bad signature, expired token), as opposed to a
// failure of the cache itself. It adds nothing to the error text. groupcache
// retries a failed peer load locally, so the error chain from this process's
// loader always reaches Validate.
type sourceValidationError struct{ err error }

func (e *sourceValidationError) Error() string { return e.err.Error() }
func (e *sourceValidationError) Unwrap() error { return e.err }

// DistributedCachingValidator wraps a cacheable validator with groupcache.
type DistributedCachingValidator struct {
	name      string
	source    Validator
	cacheable CacheableValidator
	adapter   *cache.GroupcacheAdapter[ValidatorInput, *Result]
	clock     clock.Clock
	observer  DistributedCachingValidatorObserver
}

// DistributedValidatorCachingConfig configures DistributedCachingValidator.
type DistributedValidatorCachingConfig struct {
	GroupName      string
	CacheSizeBytes int64
	Clock          clock.Clock

	// CacheTTL is the time-to-live for cached entries.
	// 0 means no TTL cap; result expiration is the only expiry bound.
	CacheTTL time.Duration
}

// NewDistributedCachingValidator wraps a validator with groupcache if it
// implements CacheableValidator. It returns the original validator otherwise.
func NewDistributedCachingValidator(name string, source Validator, obs DistributedCachingValidatorObserver, config DistributedValidatorCachingConfig) Validator {
	cacheable, ok := source.(CacheableValidator)
	if !ok {
		return source
	}
	if name == "" {
		name = "validator"
	}
	if config.GroupName == "" {
		config.GroupName = "validator:" + name
	}
	if obs == nil {
		obs = NoOpTrustObserver{}
	}
	if config.CacheSizeBytes == 0 {
		config.CacheSizeBytes = 64 << 20
	}
	clk := config.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	cacheTTL := config.CacheTTL
	adapter, err := cache.NewGroupcacheAdapter(
		config.GroupName,
		func(input ValidatorInput) (string, error) {
			return serializeValidatorInput(input)
		},
		func(key string) (ValidatorInput, error) {
			return deserializeValidatorInput(key)
		},
		func(ctx context.Context, input ValidatorInput) (*Result, error) {
			if loaded, ok := ctx.Value(distributedCacheLoadedKey{}).(*bool); ok {
				*loaded = true
			}
			result, err := source.Validate(ctx, input.Credential)
			if err != nil {
				return nil, &sourceValidationError{err: fmt.Errorf("validator failed: %w", err)}
			}
			if _, ok := validatorCacheExpiry(clk.Now(), cacheTTL, result); !ok {
				expired := fmt.Errorf("validator result is already expired")
				if result == nil {
					// A validator bug, not a verdict on the credential.
					return nil, expired
				}
				return nil, &sourceValidationError{err: expired}
			}
			return result, nil
		},
		func(result *Result) ([]byte, error) {
			return json.Marshal(result)
		},
		func(b []byte) (*Result, error) {
			var result Result
			if err := json.Unmarshal(b, &result); err != nil {
				return nil, err
			}
			return &result, nil
		},
		cache.WithClock(clk),
		cache.WithCacheSizeBytes(config.CacheSizeBytes),
		cache.WithTTL(func() cache.TTL { return cacheTTL }),
	)
	if err != nil {
		return source
	}

	return &DistributedCachingValidator{
		name:      name,
		source:    source,
		cacheable: cacheable,
		adapter:   adapter,
		clock:     clk,
		observer:  obs,
	}
}

// CredentialTypes implements Validator.
func (v *DistributedCachingValidator) CredentialTypes() []CredentialType {
	return v.source.CredentialTypes()
}

// Validate implements Validator.
func (v *DistributedCachingValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	ctx, p := v.observer.DistributedValidateStarted(ctx, v.name)
	defer p.End()

	cacheInput, err := v.cacheable.CacheKey(ctx, credential)
	if err != nil {
		p.CacheKeyFailed(err)
		return v.source.Validate(ctx, credential)
	}

	var loaded bool
	getCtx := context.WithValue(ctx, distributedCacheLoadedKey{}, &loaded)
	result, err := v.adapter.Get(getCtx, cacheInput)
	if err != nil {
		// When the source rejected the credential the cache did its job (a
		// miss followed by a load), so observers see a miss, not a cache
		// failure. The error returned to the caller is the same either way.
		var sourceErr *sourceValidationError
		if errors.As(err, &sourceErr) {
			p.CacheMiss()
		} else {
			p.GetFailed(err)
		}
		return nil, fmt.Errorf("groupcache validator get failed: %w", err)
	}

	if !result.ExpiresAt.IsZero() && !v.clock.Now().Before(result.ExpiresAt) {
		p.ResultExpired()
		return nil, ErrExpiredToken
	}

	// loaded is true only when the fetch ran in this process (a local cache
	// miss). Values served from local cache, or loaded by a remote peer in a
	// distributed deployment, are reported as hits.
	if loaded {
		p.CacheMiss()
	} else {
		p.CacheHit()
	}
	return result, nil
}

func serializeValidatorInput(input ValidatorInput) (string, error) {
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to marshal validator input: %w", err)
	}
	return string(jsonBytes), nil
}

func deserializeValidatorInput(key string) (ValidatorInput, error) {
	var input ValidatorInput
	if err := json.Unmarshal([]byte(key), &input); err != nil {
		return ValidatorInput{}, fmt.Errorf("failed to unmarshal validator input: %w", err)
	}
	return input, nil
}

func validatorCacheExpiry(now time.Time, ttl time.Duration, result *Result) (time.Time, bool) {
	if result == nil {
		return time.Time{}, false
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}
	if !result.ExpiresAt.IsZero() && (expiresAt.IsZero() || result.ExpiresAt.Before(expiresAt)) {
		expiresAt = result.ExpiresAt
	}
	if !expiresAt.IsZero() && !now.Before(expiresAt) {
		return time.Time{}, false
	}
	return expiresAt, true
}
