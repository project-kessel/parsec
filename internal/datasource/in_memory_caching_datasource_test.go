package datasource

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// mockCacheableDataSource is a test data source that implements Cacheable
type mockCacheableDataSource struct {
	name       string
	fetchCount int // Track how many times Fetch is called
	ttl        time.Duration
}

func (m *mockCacheableDataSource) Name() string {
	return m.name
}

func (m *mockCacheableDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	m.fetchCount++
	return &service.DataSourceResult{
		Data:        []byte(fmt.Sprintf(`{"fetch_count":%d}`, m.fetchCount)),
		ContentType: service.ContentTypeJSON,
	}, nil
}

func (m *mockCacheableDataSource) CacheKey(input *service.DataSourceInput) service.DataSourceInput {
	// Only cache by subject
	masked := service.DataSourceInput{}
	if input.Subject != nil {
		masked.Subject = &trust.Result{
			Subject: input.Subject.Subject,
		}
	}
	return masked
}

func (m *mockCacheableDataSource) CacheTTL() time.Duration {
	return m.ttl
}

// mockNonCacheableDataSource doesn't implement Cacheable
type mockNonCacheableDataSource struct {
	name       string
	fetchCount int
}

func (m *mockNonCacheableDataSource) Name() string {
	return m.name
}

func (m *mockNonCacheableDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	m.fetchCount++
	return &service.DataSourceResult{
		Data:        []byte(fmt.Sprintf(`{"fetch_count":%d}`, m.fetchCount)),
		ContentType: service.ContentTypeJSON,
	}, nil
}

func TestInMemoryCachingDataSource(t *testing.T) {
	ctx := context.Background()

	t.Run("caches results for cacheable source", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-source",
			ttl:  1 * time.Hour,
		}

		cached := NewInMemoryCachingDataSource(source)

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

	t.Run("respects TTL expiration", func(t *testing.T) {
		// Use a fake clock to deterministically test cache expiration
		clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

		source := &mockCacheableDataSource{
			name: "test-source",
			ttl:  50 * time.Millisecond,
		}

		cached := NewInMemoryCachingDataSource(source, WithClock(clk))

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
		if source.fetchCount != 1 {
			t.Errorf("expected 1 fetch, got %d", source.fetchCount)
		}

		// Advance time past TTL
		clk.Advance(100 * time.Millisecond)

		// Second fetch - cache should have expired
		_, err = cached.Fetch(ctx, input)
		if err != nil {
			t.Fatalf("second fetch failed: %v", err)
		}
		if source.fetchCount != 2 {
			t.Errorf("expected 2 fetches (cache expired), got %d", source.fetchCount)
		}
	})

	t.Run("different cache keys result in different cache entries", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-source",
			ttl:  1 * time.Hour,
		}

		cached := NewInMemoryCachingDataSource(source)

		input1 := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user1@example.com",
			},
		}

		input2 := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user2@example.com", // Different subject
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

		wrapped := NewInMemoryCachingDataSource(source)

		// Should return the same instance since it's not cacheable
		if wrapped != source {
			t.Error("expected non-cacheable source to be returned as-is")
		}
	})

	t.Run("cleanup removes expired entries", func(t *testing.T) {
		// Use a fake clock to deterministically test cleanup
		clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

		source := &mockCacheableDataSource{
			name: "test-source",
			ttl:  50 * time.Millisecond,
		}

		cached := NewInMemoryCachingDataSource(source, WithClock(clk)).(*InMemoryCachingDataSource)

		input := &service.DataSourceInput{
			Subject: &trust.Result{
				Subject: "user@example.com",
			},
		}

		// Fetch to populate cache
		_, _ = cached.Fetch(ctx, input)

		if cached.Size() != 1 {
			t.Errorf("expected cache size 1, got %d", cached.Size())
		}

		// Advance time past expiration
		clk.Advance(100 * time.Millisecond)

		// Cleanup
		cached.Cleanup()

		if cached.Size() != 0 {
			t.Errorf("expected cache size 0 after cleanup, got %d", cached.Size())
		}
	})
}
