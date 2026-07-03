package datasource

import (
	"context"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestDistributedCachingDataSource(t *testing.T) {
	ctx := context.Background()

	t.Run("caches results using groupcache", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-distributed",
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-1",
			CacheSizeBytes: 1 << 20,
			CacheTTL:       1 * time.Hour,
		}

		cached := NewDistributedCachingDataSource(source, config)

		input := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user@example.com",
			},
		}

		// First fetch - should call underlying source
		result1, err := cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("first fetch failed: %v", err)
		}
		if string(result1.Data) != `{"fetch_count":1}` {
			t.Errorf("expected fetch_count 1, got %s", result1.Data)
		}
		if source.fetchCount != 1 {
			t.Errorf("expected 1 fetch, got %d", source.fetchCount)
		}

		// Second fetch - should use cache
		result2, err := cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("second fetch failed: %v", err)
		}
		if string(result2.Data) != `{"fetch_count":1}` {
			t.Errorf("expected cached fetch_count 1, got %s", result2.Data)
		}
		if source.fetchCount != 1 {
			t.Errorf("expected still 1 fetch (cached), got %d", source.fetchCount)
		}
	})

	t.Run("different cache keys result in different cache entries", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-distributed",
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-2",
			CacheSizeBytes: 1 << 20,
			CacheTTL:       1 * time.Hour,
		}

		cached := NewDistributedCachingDataSource(source, config)

		input1 := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user1@example.com",
			},
		}

		input2 := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user2@example.com",
			},
		}

		// Fetch for user1
		_, err := cached.Fetch(ctx, input1)
		if err != nil {
			t.Fatalf("fetch for user1 failed: %v", err)
		}

		// Fetch for user2
		_, err = cached.Fetch(ctx, input2)
		if err != nil {
			t.Fatalf("fetch for user2 failed: %v", err)
		}

		// Both should have triggered fetches (different cache keys)
		if source.fetchCount != 2 {
			t.Errorf("expected 2 fetches (different keys), got %d", source.fetchCount)
		}
	})

	t.Run("returns non-cacheable source as-is", func(t *testing.T) {
		source := &mockNonCacheableDataSource{
			name: "non-cacheable",
		}

		config := DistributedCachingConfig{
			GroupName: "test-group-3",
		}

		wrapped := NewDistributedCachingDataSource(source, config)

		// Should return the same instance since it's not cacheable
		if wrapped != source {
			t.Error("expected non-cacheable source to be returned as-is")
		}
	})

	t.Run("uses default values for empty config", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-defaults",
		}

		config := DistributedCachingConfig{
			CacheTTL: 1 * time.Hour,
		}

		cached := NewDistributedCachingDataSource(source, config)

		input := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user@example.com",
			},
		}

		_, err := cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("fetch with default config failed: %v", err)
		}
	})

	t.Run("respects TTL for cache expiration", func(t *testing.T) {
		clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))

		source := &mockCacheableDataSource{
			name: "test-ttl",
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-ttl",
			CacheSizeBytes: 1 << 20,
			Clock:          clk,
			CacheTTL:       5 * time.Minute,
		}

		cached := NewDistributedCachingDataSource(source, config)

		input := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user@example.com",
			},
		}

		// First fetch
		_, err := cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("first fetch failed: %v", err)
		}

		// Second fetch within same bucket - should use cache
		clk.Advance(2 * time.Minute)
		_, err = cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("second fetch failed: %v", err)
		}
		if source.fetchCount != 1 {
			t.Errorf("expected 1 fetch (cached), got %d", source.fetchCount)
		}

		// Advance past TTL bucket boundary - should refetch
		clk.Advance(4 * time.Minute)
		_, err = cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("third fetch failed: %v", err)
		}
		if source.fetchCount != 2 {
			t.Errorf("expected 2 fetches (new bucket), got %d", source.fetchCount)
		}
	})

	t.Run("no TTL means no timestamp in cache key", func(t *testing.T) {
		clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))

		source := &mockCacheableDataSource{
			name: "test-no-ttl",
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-no-ttl",
			CacheSizeBytes: 1 << 20,
			Clock:          clk,
		}

		cached := NewDistributedCachingDataSource(source, config)

		input := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user@example.com",
			},
		}

		// Fetch twice
		_, err := cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("first fetch failed: %v", err)
		}

		clk.Advance(24 * time.Hour)

		_, err = cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("second fetch failed: %v", err)
		}

		// Should have only fetched once (cached indefinitely)
		if source.fetchCount != 1 {
			t.Errorf("expected 1 fetch (cached indefinitely), got %d", source.fetchCount)
		}
	})
}

func TestSerializeDeserializeInputJSON(t *testing.T) {
	t.Run("round-trip serialization", func(t *testing.T) {
		original := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example.com",
			},
		}

		serialized, err := SerializeInputToJSON(original)
		if err != nil {
			t.Fatalf("serialization failed: %v", err)
		}

		if serialized == "" {
			t.Fatal("expected non-empty serialized string")
		}

		deserialized, err := DeserializeInputFromJSON(serialized)
		if err != nil {
			t.Fatalf("deserialization failed: %v", err)
		}

		if deserialized.Subject.Subject != original.Subject.Subject {
			t.Errorf("expected subject %s, got %s", original.Subject.Subject, deserialized.Subject.Subject)
		}
		if deserialized.Subject.Issuer != original.Subject.Issuer {
			t.Errorf("expected issuer %s, got %s", original.Subject.Issuer, deserialized.Subject.Issuer)
		}
	})

	t.Run("handles nil values", func(t *testing.T) {
		original := &service.DataSourceInput{
			Subject: nil,
		}

		serialized, err := SerializeInputToJSON(original)
		if err != nil {
			t.Fatalf("serialization failed: %v", err)
		}

		deserialized, err := DeserializeInputFromJSON(serialized)
		if err != nil {
			t.Fatalf("deserialization failed: %v", err)
		}

		if deserialized.Subject != nil {
			t.Error("expected nil subject after round-trip")
		}
	})

	t.Run("masked input serialization", func(t *testing.T) {
		fullInput := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user@example.com",
				Issuer:  "https://idp.example.com",
			},
		}

		// Simulate masking - only keep subject
		masked := service.DataSourceInput{
			Subject: &trust.Result{
				Subject: fullInput.Subject.Subject,
			},
		}

		serialized, err := SerializeInputToJSON(&masked)
		if err != nil {
			t.Fatalf("serialization failed: %v", err)
		}

		deserialized, err := DeserializeInputFromJSON(serialized)
		if err != nil {
			t.Fatalf("deserialization failed: %v", err)
		}

		if deserialized.Subject.Subject != "user@example.com" {
			t.Errorf("expected subject user@example.com, got %s", deserialized.Subject.Subject)
		}
		if deserialized.Subject.Issuer != "" {
			t.Errorf("expected empty issuer (masked), got %s", deserialized.Subject.Issuer)
		}
	})
}
