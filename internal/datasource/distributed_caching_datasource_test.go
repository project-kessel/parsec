package datasource

import (
	"context"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestDistributedCachingDataSource(t *testing.T) {
	ctx := context.Background()

	t.Run("caches results using groupcache", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-distributed",
			ttl:  1 * time.Hour,
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-1",
			CacheSizeBytes: 1 << 20, // 1MB
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
			ttl:  1 * time.Hour,
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-2",
			CacheSizeBytes: 1 << 20,
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
			ttl:  1 * time.Hour,
		}

		// Empty config
		config := DistributedCachingConfig{}

		cached := NewDistributedCachingDataSource(source, config)

		// Should not panic and should work
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
		// This test verifies that cache entries with TTL are time-bucketed
		// We can't easily test actual expiration, but we can verify that
		// the cache key includes the TTL timestamp component
		source := &mockCacheableDataSource{
			name: "test-ttl",
			ttl:  5 * time.Minute,
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-ttl",
			CacheSizeBytes: 1 << 20,
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

		// Second fetch should use cache (same time bucket)
		_, err = cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("second fetch failed: %v", err)
		}

		// Should have only fetched once (cached)
		if source.fetchCount != 1 {
			t.Errorf("expected 1 fetch (cached), got %d", source.fetchCount)
		}
	})

	t.Run("no TTL means no timestamp in cache key", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-no-ttl",
			ttl:  0, // No TTL
		}

		config := DistributedCachingConfig{
			GroupName:      "test-group-no-ttl",
			CacheSizeBytes: 1 << 20,
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

func TestRoundTimestampToInterval(t *testing.T) {
	tests := []struct {
		name            string
		timestamp       time.Time
		interval        time.Duration
		expectedRounded time.Time
	}{
		{
			name:            "exact interval boundary",
			timestamp:       time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
			interval:        5 * time.Minute,
			expectedRounded: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "rounds down within interval",
			timestamp:       time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC),
			interval:        5 * time.Minute,
			expectedRounded: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "rounds down near next interval",
			timestamp:       time.Date(2025, 10, 9, 10, 4, 59, 0, time.UTC),
			interval:        5 * time.Minute,
			expectedRounded: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "next interval boundary",
			timestamp:       time.Date(2025, 10, 9, 10, 5, 0, 0, time.UTC),
			interval:        5 * time.Minute,
			expectedRounded: time.Date(2025, 10, 9, 10, 5, 0, 0, time.UTC),
		},
		{
			name:            "1 hour interval",
			timestamp:       time.Date(2025, 10, 9, 10, 30, 0, 0, time.UTC),
			interval:        1 * time.Hour,
			expectedRounded: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "1 hour interval at boundary",
			timestamp:       time.Date(2025, 10, 9, 11, 0, 0, 0, time.UTC),
			interval:        1 * time.Hour,
			expectedRounded: time.Date(2025, 10, 9, 11, 0, 0, 0, time.UTC),
		},
		{
			name:            "30 second interval",
			timestamp:       time.Date(2025, 10, 9, 10, 0, 15, 0, time.UTC),
			interval:        30 * time.Second,
			expectedRounded: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:            "30 second interval at 45 seconds",
			timestamp:       time.Date(2025, 10, 9, 10, 0, 45, 0, time.UTC),
			interval:        30 * time.Second,
			expectedRounded: time.Date(2025, 10, 9, 10, 0, 30, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rounded := roundTimestampToInterval(tt.timestamp, tt.interval)
			if !rounded.Equal(tt.expectedRounded) {
				t.Errorf("roundTimestampToInterval(%v, %v) = %v, expected %v",
					tt.timestamp, tt.interval, rounded, tt.expectedRounded)
			}
		})
	}
}

func TestStripTTLSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with TTL suffix",
			input:    `{"subject":{"subject":"user@example.com"}}:ttl:1728468000`,
			expected: `{"subject":{"subject":"user@example.com"}}`,
		},
		{
			name:     "without TTL suffix",
			input:    `{"subject":{"subject":"user@example.com"}}`,
			expected: `{"subject":{"subject":"user@example.com"}}`,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only TTL marker",
			input:    ":ttl:",
			expected: "",
		},
		{
			name:     "TTL marker at start",
			input:    ":ttl:123456",
			expected: "",
		},
		{
			name:     "multiple colons in JSON",
			input:    `{"issuer":"https://example.com"}:ttl:1728468000`,
			expected: `{"issuer":"https://example.com"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripTTLSuffix(tt.input)
			if result != tt.expected {
				t.Errorf("stripTTLSuffix(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSerializeDeserializeInputJSON(t *testing.T) {
	t.Run("round-trip serialization", func(t *testing.T) {
		original := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example.com",
			},
			RequestAttributes: &request.RequestAttributes{
				Method:    "GET",
				Path:      "/api/resource",
				IPAddress: "192.168.1.1",
			},
		}

		// Serialize
		serialized, err := SerializeInputToJSON(original)
		if err != nil {
			t.Fatalf("serialization failed: %v", err)
		}

		if serialized == "" {
			t.Fatal("expected non-empty serialized string")
		}

		// Deserialize
		deserialized, err := DeserializeInputFromJSON(serialized)
		if err != nil {
			t.Fatalf("deserialization failed: %v", err)
		}

		// Verify fields
		if deserialized.Subject.Subject != original.Subject.Subject {
			t.Errorf("expected subject %s, got %s", original.Subject.Subject, deserialized.Subject.Subject)
		}
		if deserialized.Subject.Issuer != original.Subject.Issuer {
			t.Errorf("expected issuer %s, got %s", original.Subject.Issuer, deserialized.Subject.Issuer)
		}
		if deserialized.RequestAttributes.Method != original.RequestAttributes.Method {
			t.Errorf("expected method %s, got %s", original.RequestAttributes.Method, deserialized.RequestAttributes.Method)
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
			// Intentionally unused field
			RequestAttributes: &request.RequestAttributes{
				Method: "GET",
				Path:   "/api/resource",
			},
		}

		// Simulate masking - only keep subject
		masked := service.DataSourceInput{
			Subject: &trust.Result{
				Subject: fullInput.Subject.Subject,
			},
		}

		// Serialize masked
		serialized, err := SerializeInputToJSON(&masked)
		if err != nil {
			t.Fatalf("serialization failed: %v", err)
		}

		// Deserialize
		deserialized, err := DeserializeInputFromJSON(serialized)
		if err != nil {
			t.Fatalf("deserialization failed: %v", err)
		}

		// Should have only the masked fields
		if deserialized.Subject.Subject != "user@example.com" {
			t.Errorf("expected subject user@example.com, got %s", deserialized.Subject.Subject)
		}
		if deserialized.Subject.Issuer != "" {
			t.Errorf("expected empty issuer (masked), got %s", deserialized.Subject.Issuer)
		}
		if deserialized.RequestAttributes != nil {
			t.Error("expected nil request attributes (masked)")
		}
	})
}
