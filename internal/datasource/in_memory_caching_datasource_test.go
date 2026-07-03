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

// recordingCacheFetchProbe captures which cache-outcome method was called.
type recordingCacheFetchProbe struct {
	NoOpCacheFetchProbe
	hitCalled     bool
	missCalled    bool
	expiredCalled bool
}

func (p *recordingCacheFetchProbe) CacheHit()     { p.hitCalled = true }
func (p *recordingCacheFetchProbe) CacheMiss()    { p.missCalled = true }
func (p *recordingCacheFetchProbe) CacheExpired() { p.expiredCalled = true }

// recordingCacheObserver collects a probe per Fetch call.
type recordingCacheObserver struct {
	NoOpCacheObserver
	probes []*recordingCacheFetchProbe
}

func (o *recordingCacheObserver) CacheFetchStarted(ctx context.Context, _ string) (context.Context, CacheFetchProbe) {
	p := &recordingCacheFetchProbe{}
	o.probes = append(o.probes, p)
	return ctx, p
}

// newTestCachingDataSource wraps a source with in-memory caching and a
// NoOpDataSourceObserver. Callers can pass additional options (e.g. WithClock).
func newTestCachingDataSource(t *testing.T, source service.DataSource, opts ...InMemoryCachingDataSourceOption) service.DataSource {
	t.Helper()
	return NewInMemoryCachingDataSource(source, NoOpDataSourceObserver{}, opts...)
}

func TestInMemoryCachingDataSource(t *testing.T) {
	ctx := context.Background()

	t.Run("caches results for cacheable source", func(t *testing.T) {
		source := &mockCacheableDataSource{
			name: "test-source",
		}

		cached := newTestCachingDataSource(t, source, WithCacheTTL(1*time.Hour))

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
		}

		cached := newTestCachingDataSource(t, source, WithClock(clk), WithCacheTTL(50*time.Millisecond))

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
		}

		cached := newTestCachingDataSource(t, source, WithCacheTTL(1*time.Hour))

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

		wrapped := NewInMemoryCachingDataSource(source, NoOpDataSourceObserver{})

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
		}

		cached := newTestCachingDataSource(t, source, WithClock(clk), WithCacheTTL(50*time.Millisecond)).(*InMemoryCachingDataSource)

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

func TestInMemoryCachingDataSource_CacheOutcomesAreMutuallyExclusive(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	source := &mockCacheableDataSource{name: "test-source"}
	obs := &recordingCacheObserver{}
	cached := NewInMemoryCachingDataSource(source, obs, WithClock(clk), WithCacheTTL(50*time.Millisecond))

	input := &service.DataSourceInput{
		Subject: &trust.Result{Subject: "user@example.com"},
	}

	// Call 0: cold miss — entry not in cache.
	if _, err := cached.Fetch(context.Background(), input); err != nil {
		t.Fatalf("cold miss: %v", err)
	}
	p := obs.probes[0]
	if !p.missCalled {
		t.Fatal("cold miss: expected CacheMiss")
	}
	if p.hitCalled || p.expiredCalled {
		t.Fatalf("cold miss: unexpected hit=%v expired=%v", p.hitCalled, p.expiredCalled)
	}

	// Call 1: cache hit.
	if _, err := cached.Fetch(context.Background(), input); err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	p = obs.probes[1]
	if !p.hitCalled {
		t.Fatal("cache hit: expected CacheHit")
	}
	if p.missCalled || p.expiredCalled {
		t.Fatalf("cache hit: unexpected miss=%v expired=%v", p.missCalled, p.expiredCalled)
	}

	// Call 2: expired — entry found but stale. CacheExpired only, not CacheMiss.
	clk.Advance(100 * time.Millisecond)
	if _, err := cached.Fetch(context.Background(), input); err != nil {
		t.Fatalf("expired: %v", err)
	}
	p = obs.probes[2]
	if !p.expiredCalled {
		t.Fatal("expired: expected CacheExpired")
	}
	if p.missCalled {
		t.Fatal("expired: CacheMiss must not be called when CacheExpired was called")
	}
	if p.hitCalled {
		t.Fatalf("expired: unexpected CacheHit")
	}
}
