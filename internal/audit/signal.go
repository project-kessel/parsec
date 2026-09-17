// Package audit defines the generic, request-scoped audit extension contract.
package audit

import (
	"context"
	"strings"
	"sync"
)

type contextKey struct{}

const (
	MaxOperationLength      = 128
	MaxClassificationLength = 128
	MaxMetadataKeys         = 8
	MaxMetadataValueLength  = 256

	SourceValidator  = "validator"
	SourceDataSource = "data_source"
	SourceMapper     = "mapper"
	SourcePolicy     = "policy"

	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailure = "failure"
)

// Allowlisted metadata keys that Lua scripts and other extensions may emit.
// Only these keys are permitted to prevent secrets leakage (credentials, tokens,
// claims, headers, raw dependency responses).
var allowedMetadataKeys = map[string]bool{
	"cache_status":            true,
	"classification":          true,
	"target_account_number":   true,
	"target_org_id":           true,
	"employee_user_id":        true,
	"employee_account_number": true,
	"employee_org_id":         true,
	"dependency_name":         true,
	"dependency_status":       true,
}

// Signal is bounded, deployment-neutral audit metadata emitted by an extension.
type Signal struct {
	Source         string            `json:"source"`
	Operation      string            `json:"operation"`
	Outcome        string            `json:"outcome"`
	ReasonCode     string            `json:"reason_code,omitempty"`
	Classification string            `json:"classification,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Reporter accepts validated audit signals for the current request.
type Reporter interface{ Record(Signal) }

// NoOpReporter is safe to use when audit collection is disabled.
type NoOpReporter struct{}

func (NoOpReporter) Record(Signal) {}

// Collector stores a bounded list of valid signals for one request.
type Collector struct {
	mu      sync.Mutex
	signals []Signal
}

func (c *Collector) Record(signal Signal) {
	if c == nil || !Valid(signal) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.signals) < 32 {
		// Clone metadata to prevent caller mutations from bypassing validation
		cloned := signal
		if signal.Metadata != nil {
			cloned.Metadata = make(map[string]string, len(signal.Metadata))
			for k, v := range signal.Metadata {
				cloned.Metadata[k] = v
			}
		}
		c.signals = append(c.signals, cloned)
	}
}

func (c *Collector) Signals() []Signal {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Signal(nil), c.signals...)
}

func WithReporter(ctx context.Context, reporter Reporter) context.Context {
	if reporter == nil {
		reporter = NoOpReporter{}
	}
	return context.WithValue(ctx, contextKey{}, reporter)
}

func ReporterFrom(ctx context.Context) Reporter {
	if ctx == nil {
		return NoOpReporter{}
	}
	if reporter, ok := ctx.Value(contextKey{}).(Reporter); ok && reporter != nil {
		return reporter
	}
	return NoOpReporter{}
}

func Valid(signal Signal) bool {
	if !validEnum(signal.Source, SourceValidator, SourceDataSource, SourceMapper, SourcePolicy) ||
		!validEnum(signal.Outcome, OutcomeSuccess, OutcomeDenied, OutcomeFailure) ||
		!validText(signal.Operation, MaxOperationLength) ||
		(signal.Classification != "" && !validText(signal.Classification, MaxClassificationLength)) {
		return false
	}
	if signal.ReasonCode != "" && !validReason(signal.ReasonCode) {
		return false
	}
	return validMetadata(signal.Metadata)
}

func validMetadata(md map[string]string) bool {
	if len(md) > MaxMetadataKeys {
		return false
	}
	for k, v := range md {
		// Reject non-allowlisted keys to prevent secrets leakage
		if !allowedMetadataKeys[k] {
			return false
		}
		if !validText(k, MaxOperationLength) {
			return false
		}
		if len(v) > MaxMetadataValueLength || strings.TrimSpace(v) != v {
			return false
		}
	}
	return true
}

func validEnum(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validText(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return false
	}
	return true
}

func validReason(reason string) bool {
	if !validText(reason, 128) {
		return false
	}
	switch reason {
	case "credential_missing", "credential_malformed", "credential_invalid", "credential_expired",
		"invalid_request", "grant_type_unsupported", "scheme_not_allowed", "policy_denied",
		"compliance_denied", "compliance_failure", "supplemental_user_data_failure", "dependency_failure",
		"cross_account_denied",
		"internal_error", "token_issuance_failed", "token_issuance_denied":
		return true
	default:
		return false
	}
}
