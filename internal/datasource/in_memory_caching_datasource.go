package datasource

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

// InMemoryCachingDataSource wraps a cacheable data source with simple in-memory caching
// It implements issuer.DataSource but not Cacheable (it does the caching itself)
type InMemoryCachingDataSource struct {
	source    service.DataSource
	cacheable service.Cacheable
	clock     clock.Clock
	mu        sync.RWMutex
	entries   map[string]*cacheEntry
}

// cacheEntry stores cached data with expiration
type cacheEntry struct {
	result    *service.DataSourceResult
	expiresAt time.Time
}

// InMemoryCachingDataSourceOption is a functional option for configuring InMemoryCachingDataSource
type InMemoryCachingDataSourceOption func(*InMemoryCachingDataSource)

// WithClock sets the clock for the caching data source
func WithClock(clk clock.Clock) InMemoryCachingDataSourceOption {
	return func(ds *InMemoryCachingDataSource) {
		ds.clock = clk
	}
}

// NewInMemoryCachingDataSource wraps a data source with in-memory caching if it implements Cacheable
// Returns the original source if it doesn't implement Cacheable
func NewInMemoryCachingDataSource(source service.DataSource, opts ...InMemoryCachingDataSourceOption) service.DataSource {
	cacheable, ok := source.(service.Cacheable)
	if !ok {
		// Source is not cacheable, return as-is
		return source
	}

	ds := &InMemoryCachingDataSource{
		source:    source,
		cacheable: cacheable,
		clock:     clock.NewSystemClock(), // Default to system clock
		entries:   make(map[string]*cacheEntry),
	}

	// Apply options
	for _, opt := range opts {
		opt(ds)
	}

	return ds
}

// Name forwards to the underlying data source
func (c *InMemoryCachingDataSource) Name() string {
	return c.source.Name()
}

// Fetch checks the cache first, then fetches from source on miss
func (c *InMemoryCachingDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	// Get the cache key (which is the masked input with only relevant fields)
	maskedInput := c.cacheable.CacheKey(input)

	// Serialize the masked input into a cache key string
	cacheKeyStr, err := serializeInput(&maskedInput)
	if err != nil {
		// If serialization fails, skip caching and fetch directly
		return c.source.Fetch(ctx, input)
	}

	// Check cache
	c.mu.RLock()
	entry, found := c.entries[cacheKeyStr]
	c.mu.RUnlock()

	if found {
		// Check if entry has expired
		if entry.expiresAt.IsZero() || c.clock.Now().Before(entry.expiresAt) {
			return entry.result, nil
		}
		// Entry expired, remove it
		c.mu.Lock()
		delete(c.entries, cacheKeyStr)
		c.mu.Unlock()
	}

	// Cache miss - fetch from source using the original (full) input
	result, err := c.source.Fetch(ctx, input)
	if err != nil {
		return nil, err
	}

	// Store in cache if result is not nil
	if result != nil {
		ttl := c.cacheable.CacheTTL()
		var expiresAt time.Time
		if ttl > 0 {
			expiresAt = c.clock.Now().Add(ttl)
		}

		c.mu.Lock()
		c.entries[cacheKeyStr] = &cacheEntry{
			result:    result,
			expiresAt: expiresAt,
		}
		c.mu.Unlock()
	}

	return result, nil
}

// Cleanup removes expired entries from the cache
// This should be called periodically to prevent memory leaks
func (c *InMemoryCachingDataSource) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock.Now()
	for key, entry := range c.entries {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// Size returns the number of entries in the cache (for debugging/monitoring)
func (c *InMemoryCachingDataSource) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// serializeInput serializes a masked DataSourceInput into a cache key string
// This creates a deterministic string representation of the input
func serializeInput(input *service.DataSourceInput) (string, error) {
	// Serialize to JSON for deterministic ordering
	keyBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to serialize input: %w", err)
	}

	// Hash the serialized form to get a fixed-size key
	hash := sha256.Sum256(keyBytes)
	return fmt.Sprintf("%x", hash), nil
}
