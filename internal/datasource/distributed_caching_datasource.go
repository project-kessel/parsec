package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/project-kessel/parsec/internal/cache"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

// DistributedCachingDataSource wraps a cacheable data source with groupcache
// for distributed caching across multiple servers
type DistributedCachingDataSource struct {
	source    service.DataSource
	cacheable service.Cacheable
	adapter   *cache.GroupcacheAdapter[*service.DataSourceInput, *cachedEntry]
}

// DistributedCachingConfig configures the distributed caching data source
type DistributedCachingConfig struct {
	// GroupName is the name for this groupcache group
	// Should be unique per data source type
	GroupName string

	// CacheSizeBytes is the maximum size of the cache in bytes
	// Default: 64MB
	CacheSizeBytes int64

	// Clock provides the current time for TTL bucketing.
	// Default: system clock.
	Clock clock.Clock

	// CacheTTL is the time-to-live for cached entries.
	// 0 means no TTL-based expiration (cache indefinitely).
	CacheTTL time.Duration
}

// NewDistributedCachingDataSource wraps a data source with distributed caching using groupcache.
// Returns the original source if it doesn't implement Cacheable.
//
// Note: groupcache requires that you set up the peer pool before creating caching data sources.
// See groupcache documentation for details on setting up peers.
func NewDistributedCachingDataSource(source service.DataSource, config DistributedCachingConfig) service.DataSource {
	cacheable, ok := source.(service.Cacheable)
	if !ok {
		return source
	}

	if config.GroupName == "" {
		config.GroupName = "datasource:" + source.Name()
	}

	if config.CacheSizeBytes == 0 {
		config.CacheSizeBytes = 64 << 20
	}

	if config.Clock == nil {
		config.Clock = clock.NewSystemClock()
	}

	adapter, err := cache.NewGroupcacheAdapter(
		config.GroupName,
		func(input *service.DataSourceInput) (string, error) {
			return SerializeInputToJSON(input)
		},
		func(key string) (*service.DataSourceInput, error) {
			return DeserializeInputFromJSON(key)
		},
		func(ctx context.Context, input *service.DataSourceInput) (*cachedEntry, error) {
			result, err := source.Fetch(ctx, input)
			if err != nil {
				return nil, fmt.Errorf("data source fetch failed: %w", err)
			}
			if result == nil {
				return nil, fmt.Errorf("data source returned nil result")
			}
			return &cachedEntry{
				Data:        result.Data,
				ContentType: result.ContentType,
			}, nil
		},
		func(entry *cachedEntry) ([]byte, error) {
			return json.Marshal(entry)
		},
		func(b []byte) (*cachedEntry, error) {
			var entry cachedEntry
			if err := json.Unmarshal(b, &entry); err != nil {
				return nil, err
			}
			return &entry, nil
		},
		cache.WithClock(config.Clock),
		cache.WithCacheSizeBytes(config.CacheSizeBytes),
		cache.WithTTL(func() cache.TTL { return config.CacheTTL }),
	)
	if err != nil {
		return source
	}

	return &DistributedCachingDataSource{
		source:    source,
		cacheable: cacheable,
		adapter:   adapter,
	}
}

// cachedEntry wraps the data and content type for storage in cache
type cachedEntry struct {
	Data        []byte                        `json:"data"`
	ContentType service.DataSourceContentType `json:"content_type"`
}

// Name forwards to the underlying data source
func (c *DistributedCachingDataSource) Name() string {
	return c.source.Name()
}

// Fetch checks the distributed cache first, then fetches from source on miss
func (c *DistributedCachingDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	maskedInput := c.cacheable.CacheKey(input)

	entry, err := c.adapter.Get(ctx, &maskedInput)
	if err != nil {
		return nil, fmt.Errorf("groupcache fetch failed: %w", err)
	}

	return &service.DataSourceResult{
		Data:        entry.Data,
		ContentType: entry.ContentType,
	}, nil
}

// SerializeInputToJSON serializes a DataSourceInput to JSON (reversible).
// This is used for distributed caching where the key must be deserializable.
func SerializeInputToJSON(input *service.DataSourceInput) (string, error) {
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to marshal input to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// DeserializeInputFromJSON deserializes a JSON cache key back into a DataSourceInput.
// This is used by groupcache when fetching on a remote server.
func DeserializeInputFromJSON(key string) (*service.DataSourceInput, error) {
	var input service.DataSourceInput
	if err := json.Unmarshal([]byte(key), &input); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to input: %w", err)
	}
	return &input, nil
}
