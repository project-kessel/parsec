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

// Reason codes are the closed set of values an audit record or signal may
// carry in reason_code. Deployment-specific detail belongs in a signal's
// classification, not in a new reason code.
const (
	ReasonCredentialMissing    = "credential_missing"
	ReasonCredentialMalformed  = "credential_malformed"
	ReasonCredentialInvalid    = "credential_invalid"
	ReasonCredentialExpired    = "credential_expired"
	ReasonInvalidRequest       = "invalid_request"
	ReasonGrantTypeUnsupported = "grant_type_unsupported"
	ReasonPolicyDenied         = "policy_denied"
	ReasonComplianceDenied     = "compliance_denied"
	ReasonComplianceFailure    = "compliance_failure"
	ReasonSupplementalFailure  = "supplemental_user_data_failure"
	ReasonDependencyFailure    = "dependency_failure"
	ReasonInternalError        = "internal_error"
	ReasonTokenIssuanceFailed  = "token_issuance_failed"
	ReasonTokenIssuanceDenied  = "token_issuance_denied"
)

var reasonCodes = map[string]bool{
	ReasonCredentialMissing:    true,
	ReasonCredentialMalformed:  true,
	ReasonCredentialInvalid:    true,
	ReasonCredentialExpired:    true,
	ReasonInvalidRequest:       true,
	ReasonGrantTypeUnsupported: true,
	ReasonPolicyDenied:         true,
	ReasonComplianceDenied:     true,
	ReasonComplianceFailure:    true,
	ReasonSupplementalFailure:  true,
	ReasonDependencyFailure:    true,
	ReasonInternalError:        true,
	ReasonTokenIssuanceFailed:  true,
	ReasonTokenIssuanceDenied:  true,
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
type Reporter interface{ Record(Signal) bool }

// NoOpReporter is safe to use when audit collection is disabled.
type NoOpReporter struct{}

func (NoOpReporter) Record(Signal) bool { return true }

// Collector stores a bounded list of valid signals for one request.
// When allowedKeys is non-nil, metadata keys that are not listed are stripped
// and the signal is kept; a non-nil empty map strips all metadata. A nil map
// means allow-all (text/length validation only). Production deployments
// should always configure an explicit allowlist via audit_metadata_keys.
type Collector struct {
	mu           sync.Mutex
	signals      []Signal
	dropped      int
	rejected     int
	strippedKeys int
	allowedKeys  map[string]bool
}

// NewCollector returns a Collector that enforces allowedKeys.
// A nil allowlist means allow-all (text/length validation only).
// A non-nil empty map strips all metadata keys.
// Production deployments should configure an explicit allowlist.
func NewCollector(allowedKeys map[string]bool) *Collector {
	return &Collector{allowedKeys: allowedKeys}
}

func (c *Collector) Record(signal Signal) bool {
	if c == nil {
		return false
	}
	// Sanitize metadata values before validating/storing. This also clones
	// the map, preventing caller mutations from bypassing validation.
	signal.Metadata = SanitizeMetadata(signal.Metadata)
	// A key outside the allowlist costs only that key. Dropping the whole
	// signal would lose a security-relevant event over a config omission.
	stripped := 0
	if c.allowedKeys != nil {
		for k := range signal.Metadata {
			if !c.allowedKeys[k] {
				delete(signal.Metadata, k)
				stripped++
			}
		}
		if len(signal.Metadata) == 0 {
			signal.Metadata = nil
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.strippedKeys += stripped
	if !Valid(signal) {
		c.rejected++
		return false
	}
	if len(c.signals) < 32 {
		c.signals = append(c.signals, signal)
		return true
	}
	c.dropped++
	return false
}

// Rejected returns the number of signals refused because they failed
// validation.
func (c *Collector) Rejected() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rejected
}

// StrippedKeys returns the number of metadata keys removed from recorded
// signals because they are not on the allowlist.
func (c *Collector) StrippedKeys() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.strippedKeys
}

// Dropped returns the number of valid signals rejected because the
// 32-signal limit was hit. Invalid signals are not counted.
func (c *Collector) Dropped() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

func (c *Collector) Signals() []Signal {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Signal, len(c.signals))
	for i, s := range c.signals {
		out[i] = s
		if s.Metadata != nil {
			m := make(map[string]string, len(s.Metadata))
			for k, v := range s.Metadata {
				m[k] = v
			}
			out[i].Metadata = m
		}
	}
	return out
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

// Valid reports whether signal passes structural validation. The metadata key
// allowlist is not part of validity: a Collector strips keys it does not
// allow and keeps the signal.
func Valid(signal Signal) bool {
	if !validEnum(signal.Source, SourceValidator, SourceDataSource, SourceMapper, SourcePolicy) ||
		!validEnum(signal.Outcome, OutcomeSuccess, OutcomeDenied, OutcomeFailure) ||
		!validText(signal.Operation, MaxOperationLength) ||
		(signal.Classification != "" && !validText(signal.Classification, MaxClassificationLength)) {
		return false
	}
	if signal.ReasonCode != "" && !ValidReasonCode(signal.ReasonCode) {
		return false
	}
	return validMetadata(signal.Metadata)
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

func validMetadata(md map[string]string) bool {
	if len(md) > MaxMetadataKeys {
		return false
	}
	for k, v := range md {
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

// ValidReasonCode reports whether reason is one of the known audit reason
// codes.
func ValidReasonCode(reason string) bool {
	return reasonCodes[reason]
}
