package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang/groupcache"

	"github.com/project-kessel/parsec/internal/service"
)

// DistributedCachingDataSource wraps a cacheable data source with groupcache
// for distributed caching across multiple servers
type DistributedCachingDataSource struct {
	source    service.DataSource
	cacheable service.Cacheable
	group     *groupcache.Group
}

// DistributedCachingConfig configures the distributed caching data source
type DistributedCachingConfig struct {
	// GroupName is the name for this groupcache group
	// Should be unique per data source type
	GroupName string

	// CacheSizeBytes is the maximum size of the cache in bytes
	// Default: 64MB
	CacheSizeBytes int64
}

// NewDistributedCachingDataSource wraps a data source with distributed caching using groupcache
// Returns the original source if it doesn't implement Cacheable
//
// Note: groupcache requires that you set up the peer pool before creating caching data sources
// See groupcache documentation for details on setting up peers
func NewDistributedCachingDataSource(source service.DataSource, config DistributedCachingConfig) service.DataSource {
	cacheable, ok := source.(service.Cacheable)
	if !ok {
		// Source is not cacheable, return as-is
		return source
	}

	if config.GroupName == "" {
		config.GroupName = "datasource:" + source.Name()
	}

	if config.CacheSizeBytes == 0 {
		config.CacheSizeBytes = 64 << 20 // 64MB default
	}

	// Create the getter function that will be called on cache miss
	// This may be called on a different server in the groupcache peer pool
	getter := groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {
		// Strip TTL timestamp suffix if present (format: "...json...:ttl:timestamp")
		// The cache key may include a TTL-based timestamp for expiration
		inputJSON := stripTTLSuffix(key)

		// Deserialize the cache key back into the masked input
		maskedInput, err := DeserializeInputFromJSON(inputJSON)
		if err != nil {
			return fmt.Errorf("failed to deserialize cache key: %w", err)
		}

		// Fetch using the masked input
		// The masked input is sufficient for fetching by design of Cacheable interface
		result, err := source.Fetch(ctx, maskedInput)
		if err != nil {
			return fmt.Errorf("data source fetch failed: %w", err)
		}

		if result == nil {
			return fmt.Errorf("data source returned nil result")
		}

		// Wrap result with content type for deserialization
		entry := cachedEntry{
			Data:        result.Data,
			ContentType: result.ContentType,
		}

		// Serialize for storage in cache
		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal cache entry: %w", err)
		}

		// Store in groupcache
		// Note: groupcache handles its own eviction based on LRU and cache size
		// TTL-based expiration is implemented by including a rounded timestamp in the cache key
		return dest.SetBytes(entryBytes)
	})

	// Create the groupcache group
	group := groupcache.NewGroup(config.GroupName, config.CacheSizeBytes, getter)

	return &DistributedCachingDataSource{
		source:    source,
		cacheable: cacheable,
		group:     group,
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
	// Get the cache key (which is the masked input with only relevant fields)
	maskedInput := c.cacheable.CacheKey(input)

	// Serialize the masked input into a cache key string
	// This must be reversible (JSON) for distributed caching
	cacheKeyStr, err := SerializeInputToJSON(&maskedInput)
	if err != nil {
		// If serialization fails, fall back to direct fetch
		return c.source.Fetch(ctx, input)
	}

	// Add TTL-based timestamp to cache key for effective expiration
	// This rounds the timestamp to the nearest TTL interval so that
	// entries naturally "expire" as time intervals change
	ttl := c.cacheable.CacheTTL()
	if ttl > 0 {
		roundedTimestamp := roundTimestampToInterval(time.Now(), ttl)
		cacheKeyStr = fmt.Sprintf("%s:ttl:%d", cacheKeyStr, roundedTimestamp.Unix())
	}

	// Fetch from groupcache (will hit cache or call getter)
	var cachedBytes []byte
	err = c.group.Get(ctx, cacheKeyStr, groupcache.AllocatingByteSliceSink(&cachedBytes))
	if err != nil {
		return nil, fmt.Errorf("groupcache fetch failed: %w", err)
	}

	// Deserialize the cached entry
	var entry cachedEntry
	if err := json.Unmarshal(cachedBytes, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached entry: %w", err)
	}

	return &service.DataSourceResult{
		Data:        entry.Data,
		ContentType: entry.ContentType,
	}, nil
}

// roundTimestampToInterval rounds a timestamp to the nearest interval boundary.
// This is used to create cache keys that naturally expire as time intervals change.
// For example, with a 5-minute TTL:
//   - 10:00:00 -> 10:00:00
//   - 10:02:30 -> 10:00:00
//   - 10:05:00 -> 10:05:00
//   - 10:07:30 -> 10:05:00
func roundTimestampToInterval(t time.Time, interval time.Duration) time.Time {
	unixNano := t.UnixNano()
	intervalNano := interval.Nanoseconds()
	roundedNano := (unixNano / intervalNano) * intervalNano
	return time.Unix(0, roundedNano)
}

// stripTTLSuffix removes the ":ttl:timestamp" suffix from a cache key if present.
// Cache keys may include a TTL-based timestamp for expiration: "...json...:ttl:1234567890"
// This function extracts just the JSON portion.
func stripTTLSuffix(key string) string {
	// Look for the ":ttl:" marker
	const ttlMarker = ":ttl:"
	if idx := strings.Index(key, ttlMarker); idx >= 0 {
		return key[:idx]
	}
	return key
}

// SerializeInputToJSON serializes a DataSourceInput to JSON (reversible)
// This is used for distributed caching where the key must be deserializable
func SerializeInputToJSON(input *service.DataSourceInput) (string, error) {
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to marshal input to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// DeserializeInputFromJSON deserializes a JSON cache key back into a DataSourceInput
// This is used by groupcache when fetching on a remote server
func DeserializeInputFromJSON(key string) (*service.DataSourceInput, error) {
	var input service.DataSourceInput
	if err := json.Unmarshal([]byte(key), &input); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to input: %w", err)
	}
	return &input, nil
}
