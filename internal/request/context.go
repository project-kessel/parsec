package request

import (
	"context"
	"strings"
	"sync"
	"unicode"
)

type requestIDKey struct{}
type extractedKey struct{}
type canonicalHeaderKey struct{}
type auditStateKey struct{}

// CacheLayer records the cache status observed by a specific pipeline component.
type CacheLayer struct {
	Layer  string `json:"layer"`
	Status string `json:"status"`
}

// maxCacheLayers bounds the per-request cache layer slice to prevent unbounded growth.
const maxCacheLayers = 8

// maxLayerNameLength bounds the layer name recorded in a CacheLayer entry.
// Layer names are built from static component names plus a configured
// datasource name (e.g. "datasource:backoffice"); this cap and the control
// character check are defense-in-depth against unexpectedly long or
// malformed configuration values reaching the audit schema.
const maxLayerNameLength = 128

// AuditState carries only bounded classifications between nested probes in a
// single request. It never contains request values, credentials, or errors.
//
// cacheStatus is the last-observed cache classification for the request
// ("hit", "miss", "expired", or "failure"). Multiple nested cache probes
// (in-memory JWT, distributed JWT, datasource) may overwrite it via
// RecordCacheLayer; the value at emit time is the terminal classification.
//
// cacheLayers records per-component cache results so audit consumers can
// attribute cache behavior to specific layers (e.g. "validator_memory",
// "validator_distributed", "datasource:backoffice").
//
// failureReason is the classified failure reason from the first nested probe
// failure (first-writer-wins). Subsequent failures do not overwrite it,
// ensuring the audit record reflects the root-cause failure.
type AuditState struct {
	mu            sync.RWMutex
	cacheStatus   string
	cacheLayers   []CacheLayer
	failureReason string
}

// WithID adds a request correlation identifier to ctx.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// ID returns the request correlation identifier in ctx, if any.
func ID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// WithIDExtraction stores whether the request ID was extracted from an
// incoming header (true) or generated locally (false), along with the
// canonical header name used for response propagation. This allows
// downstream handlers to decide whether to propagate the ID upstream.
func WithIDExtraction(ctx context.Context, extracted bool, canonicalHeader string) context.Context {
	ctx = context.WithValue(ctx, extractedKey{}, extracted)
	return context.WithValue(ctx, canonicalHeaderKey{}, canonicalHeader)
}

// IDExtracted reports whether the request correlation ID was extracted from
// an incoming header. Returns false when no extraction metadata is present
// or when the ID was generated locally.
func IDExtracted(ctx context.Context) bool {
	v, _ := ctx.Value(extractedKey{}).(bool)
	return v
}

// CanonicalRequestIDHeader returns the canonical request-ID header name
// stored by the interceptor, or an empty string when not set.
func CanonicalRequestIDHeader(ctx context.Context) string {
	v, _ := ctx.Value(canonicalHeaderKey{}).(string)
	return v
}

func WithAuditState(ctx context.Context) (context.Context, *AuditState) {
	state := &AuditState{}
	return context.WithValue(ctx, auditStateKey{}, state), state
}

func AuditStateFrom(ctx context.Context) *AuditState {
	state, _ := ctx.Value(auditStateKey{}).(*AuditState)
	return state
}

// validCacheStatus reports whether status is one of the known cache
// classification values. Invalid values are silently dropped by
// RecordCacheLayer to prevent typos from polluting the audit schema.
func validCacheStatus(status string) bool {
	switch status {
	case "hit", "miss", "expired", "failure":
		return true
	default:
		return false
	}
}

// safeLayerName bounds and sanitizes a cache layer name before it is
// recorded. Layer names containing control characters, or that are empty
// after trimming, are replaced with "unknown" rather than being dropped
// entirely so the cache status is still observable. Overlong names are
// truncated to maxLayerNameLength.
func safeLayerName(layer string) string {
	layer = strings.TrimSpace(layer)
	if layer == "" {
		return "unknown"
	}
	for _, r := range layer {
		if unicode.IsControl(r) {
			return "unknown"
		}
	}
	if len(layer) > maxLayerNameLength {
		layer = layer[:maxLayerNameLength]
	}
	return layer
}

// RecordCacheLayer appends a per-component cache observation and updates the
// terminal cacheStatus. Invalid status values are silently dropped. The
// layer name is sanitized via safeLayerName before being recorded.
func (s *AuditState) RecordCacheLayer(layer, status string) {
	if s == nil || !validCacheStatus(status) {
		return
	}
	layer = safeLayerName(layer)
	s.mu.Lock()
	s.cacheStatus = status
	if len(s.cacheLayers) < maxCacheLayers {
		s.cacheLayers = append(s.cacheLayers, CacheLayer{Layer: layer, Status: status})
	}
	s.mu.Unlock()
}

// SetFailureReason records a classified failure reason using first-writer-wins
// semantics. Once set, subsequent calls are no-ops, ensuring the audit record
// reflects the root-cause failure rather than the last one.
func (s *AuditState) SetFailureReason(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.failureReason == "" {
		s.failureReason = reason
	}
	s.mu.Unlock()
}

// Snapshot returns a consistent point-in-time copy of the audit
// classifications. The returned cacheLayers slice is a copy.
func (s *AuditState) Snapshot() (cacheStatus string, cacheLayers []CacheLayer, failureReason string) {
	if s == nil {
		return "", nil, ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	layers := make([]CacheLayer, len(s.cacheLayers))
	copy(layers, s.cacheLayers)
	return s.cacheStatus, layers, s.failureReason
}
