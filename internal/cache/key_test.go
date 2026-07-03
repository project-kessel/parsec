package cache_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/cache"
)

func TestStripTTLSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with TTL suffix",
			input:    `{"subject":"user@example.com"}:ttl:1728468000`,
			expected: `{"subject":"user@example.com"}`,
		},
		{
			name:     "without TTL suffix",
			input:    `{"subject":"user@example.com"}`,
			expected: `{"subject":"user@example.com"}`,
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
			name:     "multiple colons in JSON value",
			input:    `{"issuer":"https://example.com"}:ttl:1728468000`,
			expected: `{"issuer":"https://example.com"}`,
		},
		{
			name:     "inner :ttl: in key body preserved",
			input:    `{"claim":":ttl:value"}:ttl:1728468000`,
			expected: `{"claim":":ttl:value"}`,
		},
		{
			name:     "multiple inner :ttl: substrings preserved",
			input:    `a:ttl:b:ttl:c:ttl:1728468000`,
			expected: `a:ttl:b:ttl:c`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cache.StripTTLSuffix(tt.input)
			if result != tt.expected {
				t.Errorf("StripTTLSuffix(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRoundTimestampToInterval(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		interval time.Duration
		expected time.Time
	}{
		{
			name:     "exact boundary",
			time:     time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
			interval: 5 * time.Minute,
			expected: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:     "rounds down mid-interval",
			time:     time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC),
			interval: 5 * time.Minute,
			expected: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:     "rounds down near next boundary",
			time:     time.Date(2025, 10, 9, 10, 4, 59, 0, time.UTC),
			interval: 5 * time.Minute,
			expected: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:     "next boundary",
			time:     time.Date(2025, 10, 9, 10, 5, 0, 0, time.UTC),
			interval: 5 * time.Minute,
			expected: time.Date(2025, 10, 9, 10, 5, 0, 0, time.UTC),
		},
		{
			name:     "1 hour interval",
			time:     time.Date(2025, 10, 9, 10, 30, 0, 0, time.UTC),
			interval: 1 * time.Hour,
			expected: time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			name:     "30 second interval",
			time:     time.Date(2025, 10, 9, 10, 0, 45, 0, time.UTC),
			interval: 30 * time.Second,
			expected: time.Date(2025, 10, 9, 10, 0, 30, 0, time.UTC),
		},
		{
			name:     "zero interval returns original time",
			time:     time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC),
			interval: 0,
			expected: time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC),
		},
		{
			name:     "negative interval returns original time",
			time:     time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC),
			interval: -5 * time.Minute,
			expected: time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cache.RoundTimestampToInterval(tt.time, tt.interval)
			if !result.Equal(tt.expected) {
				t.Errorf("RoundTimestampToInterval(%v, %v) = %v, want %v",
					tt.time, tt.interval, result, tt.expected)
			}
		})
	}
}

func TestAppendTTLSuffix(t *testing.T) {
	baseKey := `{"subject":"user@example.com"}`
	now := time.Date(2025, 10, 9, 10, 2, 30, 0, time.UTC)

	t.Run("appends rounded timestamp", func(t *testing.T) {
		result := cache.AppendTTLSuffix(baseKey, now, 5*time.Minute)
		// 10:02:30 rounds down to 10:00:00
		expected := time.Date(2025, 10, 9, 10, 0, 0, 0, time.UTC)
		want := baseKey + ":ttl:" + fmt.Sprintf("%d", expected.Unix())
		if result != want {
			t.Errorf("AppendTTLSuffix = %q, want %q", result, want)
		}
	})

	t.Run("zero TTL returns key unchanged", func(t *testing.T) {
		result := cache.AppendTTLSuffix(baseKey, now, 0)
		if result != baseKey {
			t.Errorf("AppendTTLSuffix with zero TTL = %q, want %q", result, baseKey)
		}
	})

	t.Run("negative TTL returns key unchanged", func(t *testing.T) {
		result := cache.AppendTTLSuffix(baseKey, now, -1*time.Minute)
		if result != baseKey {
			t.Errorf("AppendTTLSuffix with negative TTL = %q, want %q", result, baseKey)
		}
	})

	t.Run("round-trips with StripTTLSuffix", func(t *testing.T) {
		withSuffix := cache.AppendTTLSuffix(baseKey, now, 5*time.Minute)
		stripped := cache.StripTTLSuffix(withSuffix)
		if stripped != baseKey {
			t.Errorf("round-trip: got %q, want %q", stripped, baseKey)
		}
	})

	t.Run("round-trips key containing inner ttl marker", func(t *testing.T) {
		key := `{"claim":":ttl:value"}`
		withSuffix := cache.AppendTTLSuffix(key, now, 5*time.Minute)
		stripped := cache.StripTTLSuffix(withSuffix)
		if stripped != key {
			t.Errorf("round-trip with inner marker: got %q, want %q", stripped, key)
		}
	})
}
