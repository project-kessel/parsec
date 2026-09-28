// Package audit defines the generic, request-scoped audit extension contract.
package audit

import (
	"context"
	"strings"
	"sync"
	"unicode/utf8"
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
// When allowedKeys is empty, metadata keys are accepted after text/length
// checks only. When non-empty, only listed keys are permitted.
type Collector struct {
	mu          sync.Mutex
	signals     []Signal
	allowedKeys map[string]bool
}

// NewCollector returns a Collector that enforces allowedKeys when non-empty.
// A nil or empty allowlist means allow-all (text/length validation only).
func NewCollector(allowedKeys map[string]bool) *Collector {
	return &Collector{allowedKeys: allowedKeys}
}

func (c *Collector) Record(signal Signal) {
	if c == nil {
		return
	}
	// Sanitize metadata values before validating/storing. This also clones
	// the map, preventing caller mutations from bypassing validation.
	signal.Metadata = SanitizeMetadata(signal.Metadata)
	if !c.valid(signal) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.signals) < 32 {
		c.signals = append(c.signals, signal)
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

// Valid reports whether signal passes structural validation with no metadata
// key allowlist (allow-all). Prefer Collector validation when an allowlist
// is configured for the request.
func Valid(signal Signal) bool {
	return (&Collector{}).valid(signal)
}

func (c *Collector) valid(signal Signal) bool {
	if !validEnum(signal.Source, SourceValidator, SourceDataSource, SourceMapper, SourcePolicy) ||
		!validEnum(signal.Outcome, OutcomeSuccess, OutcomeDenied, OutcomeFailure) ||
		!validText(signal.Operation, MaxOperationLength) ||
		(signal.Classification != "" && !validText(signal.Classification, MaxClassificationLength)) {
		return false
	}
	if signal.ReasonCode != "" && !validReason(signal.ReasonCode) {
		return false
	}
	return c.validMetadata(signal.Metadata)
}

// SanitizeMetadata trims surrounding whitespace and truncates each metadata
// value to MaxMetadataValueLength (without splitting a multi-byte UTF-8
// rune), returning a new map. Values commonly originate from attacker-
// influenced input surfaced by Lua/CEL scripts (request cookies, headers,
// claims); without sanitization, a single oversized or padded value would
// cause validMetadata to reject the *entire* signal, silently dropping a
// security-relevant audit event (e.g. a cross-account access denial).
// Truncating/trimming here preserves the event with a bounded value instead.
// Keys are left unmodified: callers are expected to use fixed,
// script-defined key names, not attacker-controlled strings.
func SanitizeMetadata(md map[string]string) map[string]string {
	if md == nil {
		return nil
	}
	sanitized := make(map[string]string, len(md))
	for k, v := range md {
		sanitized[k] = sanitizeMetadataValue(v)
	}
	return sanitized
}

func sanitizeMetadataValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= MaxMetadataValueLength {
		return v
	}
	end := MaxMetadataValueLength
	for end > 0 && !utf8.RuneStart(v[end]) {
		end--
	}
	return strings.TrimSpace(v[:end])
}

func (c *Collector) validMetadata(md map[string]string) bool {
	if len(md) > MaxMetadataKeys {
		return false
	}
	for k, v := range md {
		// When an allowlist is configured, reject non-allowlisted keys.
		// Empty allowlist means allow-all (still enforce text/length rules).
		if len(c.allowedKeys) > 0 && !c.allowedKeys[k] {
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
