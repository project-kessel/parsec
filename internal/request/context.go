package request

import (
	"context"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

type requestIDKey struct{}
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
// cacheLayers records per-component cache results so audit consumers can
// attribute cache behavior to specific layers (e.g. "validator_memory",
// "validator_distributed", "datasource:backoffice").
//
// failureReason is the classified failure reason from the first nested probe
// failure (first-writer-wins). Subsequent failures do not overwrite it,
// ensuring the audit record reflects the root-cause failure.
type AuditState struct {
	mu               sync.RWMutex
	cacheLayers      []CacheLayer
	failureReason    string
	failedComponent  string
	dependencyOutage bool
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
		end := maxLayerNameLength
		for end > 0 && !utf8.RuneStart(layer[end]) {
			end--
		}
		layer = layer[:end]
	}
	return layer
}

// RecordCacheLayer appends a per-component cache observation. Invalid status
// values are silently dropped. The
// layer name is sanitized via safeLayerName before being recorded.
func (s *AuditState) RecordCacheLayer(layer, status string) {
	if s == nil || !validCacheStatus(status) {
		return
	}
	layer = safeLayerName(layer)
	s.mu.Lock()
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

// SetFailedComponent records the identity of the first component that failed
// (first-writer-wins). The name is sanitized the same way cache layer names
// are to prevent malformed configuration values from reaching the audit schema.
func (s *AuditState) SetFailedComponent(component string) {
	if s == nil {
		return
	}
	component = safeLayerName(component)
	s.mu.Lock()
	if s.failedComponent == "" {
		s.failedComponent = component
	}
	s.mu.Unlock()
}

// SetDependencyOutage marks a real infrastructure outage (JWKS down,
// distributed cache unreachable) as distinct from credential validation
// failures that happen to fire SourceFailed.
func (s *AuditState) SetDependencyOutage() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.dependencyOutage = true
	s.mu.Unlock()
}

// Snapshot returns a consistent point-in-time copy of the audit
// classifications. The returned cacheLayers slice is a copy.
func (s *AuditState) Snapshot() (cacheLayers []CacheLayer, failureReason string, failedComponent string, dependencyOutage bool) {
	if s == nil {
		return nil, "", "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	layers := make([]CacheLayer, len(s.cacheLayers))
	copy(layers, s.cacheLayers)
	return layers, s.failureReason, s.failedComponent, s.dependencyOutage
}
