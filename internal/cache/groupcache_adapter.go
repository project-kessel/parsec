package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/groupcache"

	"github.com/project-kessel/parsec/internal/clock"
)

// GroupcacheAdapter wraps a groupcache group with typed key/value
// serialization and TTL-bucketed cache keys.
//
// K is the domain key type (e.g. ValidatorInput, *DataSourceInput).
// V is the domain value type (e.g. *Result, *cachedEntry).
type GroupcacheAdapter[K any, V any] struct {
	group            *groupcache.Group
	clock            clock.Clock
	ttl              func() TTL
	serializeKey     func(K) (string, error)
	deserializeKey   func(string) (K, error)
	fetch            func(context.Context, K) (V, error)
	serializeValue   func(V) ([]byte, error)
	deserializeValue func([]byte) (V, error)
}

// TTL is the time-to-live for a cache entry.
type TTL = time.Duration

// groupcacheAdapterConfig holds optional configuration for a [GroupcacheAdapter].
type groupcacheAdapterConfig struct {
	clock          clock.Clock
	cacheSizeBytes int64
	ttl            func() TTL
}

// GroupcacheAdapterOption configures optional behavior of a [GroupcacheAdapter].
type GroupcacheAdapterOption func(*groupcacheAdapterConfig)

// WithClock sets the clock used for TTL bucketing.
// Default: [clock.NewSystemClock].
func WithClock(c clock.Clock) GroupcacheAdapterOption {
	return func(cfg *groupcacheAdapterConfig) {
		cfg.clock = c
	}
}

// WithCacheSizeBytes sets the maximum cache size in bytes.
// Default: 64 MB.
func WithCacheSizeBytes(n int64) GroupcacheAdapterOption {
	return func(cfg *groupcacheAdapterConfig) {
		cfg.cacheSizeBytes = n
	}
}

// WithTTL sets the function that returns the time-to-live for cached entries.
// Called on each Get to allow dynamic TTL (though typically static).
// If not set, entries are cached indefinitely.
func WithTTL(ttl func() TTL) GroupcacheAdapterOption {
	return func(cfg *groupcacheAdapterConfig) {
		cfg.ttl = ttl
	}
}

// NewGroupcacheAdapter creates a [GroupcacheAdapter].
//
// Required parameters are positional: groupName uniquely identifies the
// groupcache group within the process, and the serialize/deserialize/fetch
// functions handle domain-type conversion and origin fetches.
func NewGroupcacheAdapter[K any, V any](
	groupName string,
	serializeKey func(K) (string, error),
	deserializeKey func(string) (K, error),
	fetch func(context.Context, K) (V, error),
	serializeValue func(V) ([]byte, error),
	deserializeValue func([]byte) (V, error),
	opts ...GroupcacheAdapterOption,
) (*GroupcacheAdapter[K, V], error) {
	if groupName == "" {
		return nil, fmt.Errorf("cache: groupName is required")
	}
	if serializeKey == nil {
		return nil, fmt.Errorf("cache: serializeKey is required")
	}
	if deserializeKey == nil {
		return nil, fmt.Errorf("cache: deserializeKey is required")
	}
	if fetch == nil {
		return nil, fmt.Errorf("cache: fetch is required")
	}
	if serializeValue == nil {
		return nil, fmt.Errorf("cache: serializeValue is required")
	}
	if deserializeValue == nil {
		return nil, fmt.Errorf("cache: deserializeValue is required")
	}

	cfg := groupcacheAdapterConfig{
		clock:          clock.NewSystemClock(),
		cacheSizeBytes: 64 << 20,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	a := &GroupcacheAdapter[K, V]{
		clock:            cfg.clock,
		ttl:              cfg.ttl,
		serializeKey:     serializeKey,
		deserializeKey:   deserializeKey,
		fetch:            fetch,
		serializeValue:   serializeValue,
		deserializeValue: deserializeValue,
	}

	getter := groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {
		stripped := StripTTLSuffix(key)

		domainKey, err := a.deserializeKey(stripped)
		if err != nil {
			return fmt.Errorf("cache: failed to deserialize key: %w", err)
		}

		value, err := a.fetch(ctx, domainKey)
		if err != nil {
			return fmt.Errorf("cache: fetch failed: %w", err)
		}

		encoded, err := a.serializeValue(value)
		if err != nil {
			return fmt.Errorf("cache: failed to serialize value: %w", err)
		}

		return dest.SetBytes(encoded)
	})

	a.group = groupcache.NewGroup(groupName, cfg.cacheSizeBytes, getter)
	return a, nil
}

// Get retrieves a value from the cache, fetching from the source on a miss.
// The key is serialized, TTL-bucketed, and passed to groupcache.
func (a *GroupcacheAdapter[K, V]) Get(ctx context.Context, key K) (V, error) {
	var zero V

	keyStr, err := a.serializeKey(key)
	if err != nil {
		return zero, fmt.Errorf("cache: failed to serialize key: %w", err)
	}

	var ttl TTL
	if a.ttl != nil {
		ttl = a.ttl()
	}
	keyStr = AppendTTLSuffix(keyStr, a.clock.Now(), ttl)

	var cachedBytes []byte
	if err := a.group.Get(ctx, keyStr, groupcache.AllocatingByteSliceSink(&cachedBytes)); err != nil {
		return zero, err
	}

	value, err := a.deserializeValue(cachedBytes)
	if err != nil {
		return zero, fmt.Errorf("cache: failed to deserialize value: %w", err)
	}

	return value, nil
}
