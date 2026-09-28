package request

import (
	"context"
	"sync"
)

type requestIDKey struct{}
type auditStateKey struct{}

// AuditState carries only bounded classifications between nested probes in a
// single request. It never contains request values, credentials, or errors.
type AuditState struct {
	mu            sync.RWMutex
	cacheStatus   string
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

func WithAuditState(ctx context.Context) (context.Context, *AuditState) {
	state := &AuditState{}
	return context.WithValue(ctx, auditStateKey{}, state), state
}

func AuditStateFrom(ctx context.Context) *AuditState {
	state, _ := ctx.Value(auditStateKey{}).(*AuditState)
	return state
}

func (s *AuditState) SetCacheStatus(status string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cacheStatus = status
	s.mu.Unlock()
}

func (s *AuditState) SetFailureReason(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.failureReason = reason
	s.mu.Unlock()
}

func (s *AuditState) Snapshot() (cacheStatus, failureReason string) {
	if s == nil {
		return "", ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cacheStatus, s.failureReason
}
