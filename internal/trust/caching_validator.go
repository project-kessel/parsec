package trust

import (
	"context"
	"encoding/json"
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

	cacheInput, err := v.cacheable.CacheKey(credential)
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
			result, err := source.Validate(ctx, input.Credential)
			if err != nil {
				return nil, fmt.Errorf("validator failed: %w", err)
			}
			if _, ok := validatorCacheExpiry(clk.Now(), cacheTTL, result); !ok {
				return nil, fmt.Errorf("validator result is already expired")
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

	cacheInput, err := v.cacheable.CacheKey(credential)
	if err != nil {
		p.CacheKeyFailed(err)
		return v.source.Validate(ctx, credential)
	}

	result, err := v.adapter.Get(ctx, cacheInput)
	if err != nil {
		p.GetFailed(err)
		return nil, fmt.Errorf("groupcache validator get failed: %w", err)
	}

	if !result.ExpiresAt.IsZero() && !v.clock.Now().Before(result.ExpiresAt) {
		p.ResultExpired()
		return nil, ErrExpiredToken
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
