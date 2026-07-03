// Package cache provides shared distributed caching infrastructure.
//
// It centralizes the TTL-bucketed key lifecycle used by groupcache-based
// distributed caches throughout parsec, ensuring consistent clock injection,
// key formatting, and time-bucket rounding.
package cache

import (
	"fmt"
	"strings"
	"time"
)

const ttlMarker = ":ttl:"

// AppendTTLSuffix appends a time-bucketed TTL suffix to a cache key.
// The timestamp is rounded down to the nearest TTL interval so that keys
// naturally "expire" when the current time crosses into the next bucket.
// If ttl is zero or negative, the key is returned unchanged.
func AppendTTLSuffix(key string, now time.Time, ttl time.Duration) string {
	if ttl <= 0 {
		return key
	}
	rounded := RoundTimestampToInterval(now, ttl)
	return fmt.Sprintf("%s%s%d", key, ttlMarker, rounded.Unix())
}

// StripTTLSuffix removes the trailing ":ttl:<timestamp>" suffix appended by
// [AppendTTLSuffix].  It trims only the last marker so that keys whose body
// happens to contain a literal ":ttl:" substring are preserved intact.
// If the marker is not present, the key is returned unchanged.
func StripTTLSuffix(key string) string {
	if idx := strings.LastIndex(key, ttlMarker); idx >= 0 {
		return key[:idx]
	}
	return key
}

// RoundTimestampToInterval rounds a timestamp down to the nearest interval
// boundary. If interval is zero or negative, t is returned unchanged.
// For example, with a 5-minute interval:
//
//   - 10:02:30 → 10:00:00
//   - 10:05:00 → 10:05:00
//   - 10:07:30 → 10:05:00
func RoundTimestampToInterval(t time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return t
	}
	unixNano := t.UnixNano()
	intervalNano := interval.Nanoseconds()
	roundedNano := (unixNano / intervalNano) * intervalNano
	return time.Unix(0, roundedNano)
}
