package audit

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestCollectorBoundsAndPreservesSignals(t *testing.T) {
	collector := NewCollector(nil)
	valid := Signal{Source: SourcePolicy, Operation: "authorization", Outcome: OutcomeSuccess}
	collector.Record(valid)
	collector.Record(Signal{Source: "unknown", Operation: "authorization", Outcome: OutcomeSuccess})
	require.Equal(t, []Signal{valid}, collector.Signals())
}

func TestReporterFromMissingContextIsNoOp(t *testing.T) {
	require.NotPanics(t, func() {
		ReporterFrom(context.Background()).Record(Signal{Source: SourcePolicy, Operation: "authorization", Outcome: OutcomeSuccess})
	})
}

func TestSignalMetadataValidation(t *testing.T) {
	base := Signal{Source: SourceValidator, Operation: "cross_account_access", Outcome: OutcomeSuccess}

	valid := base
	valid.Metadata = map[string]string{"target_org_id": "org-123", "target_account_number": "acct-456"}
	require.True(t, Valid(valid))

	collector := NewCollector(nil)
	collector.Record(valid)
	require.Len(t, collector.Signals(), 1)
	require.Equal(t, "org-123", collector.Signals()[0].Metadata["target_org_id"])

	tooMany := base
	tooMany.Metadata = make(map[string]string)
	for i := range MaxMetadataKeys + 1 {
		tooMany.Metadata[string(rune('a'+i))] = "value"
	}
	require.False(t, Valid(tooMany))

	badValue := base
	badValue.Metadata = map[string]string{"target_org_id": " leading-space"}
	require.False(t, Valid(badValue))
}

func TestCollectorEnforcesMetadataAllowlist(t *testing.T) {
	base := Signal{Source: SourceValidator, Operation: "cross_account_access", Outcome: OutcomeSuccess}
	allowlist := map[string]bool{
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
	collector := NewCollector(allowlist)

	// Keys outside the allowlist are stripped; the signal itself is kept.
	for _, md := range []map[string]string{
		{"authorization": "Bearer secret-token"},
		{"jwt_claims": `{"sub":"user-1"}`},
		{"password": "secret123", "target_org_id": "org-123"},
	} {
		c := NewCollector(allowlist)
		s := base
		s.Metadata = md
		require.True(t, c.Record(s))
		signals := c.Signals()
		require.Len(t, signals, 1, "a disallowed key must not drop the signal")
		for k := range md {
			if !allowlist[k] {
				require.NotContains(t, signals[0].Metadata, k)
			}
		}
		require.Equal(t, 1, c.StrippedKeys())
		require.Zero(t, c.Rejected())
	}

	allowlisted := base
	allowlisted.Metadata = map[string]string{
		"cache_status":            "hit",
		"classification":          "compliance",
		"target_account_number":   "999999",
		"target_org_id":           "org-123",
		"employee_user_id":        "emp-1",
		"employee_account_number": "111111",
		"employee_org_id":         "emp-org",
		"dependency_name":         "rbac",
	}
	collector.Record(allowlisted)
	require.Len(t, collector.Signals(), 1, "all allowlisted keys should be accepted")
}

func TestCollectorAllowAllWhenAllowlistNil(t *testing.T) {
	collector := NewCollector(nil)
	signal := Signal{
		Source:    SourceValidator,
		Operation: "cross_account_access",
		Outcome:   OutcomeSuccess,
		Metadata:  map[string]string{"custom_key": "custom-value"},
	}
	collector.Record(signal)
	require.Len(t, collector.Signals(), 1, "nil allowlist must accept any valid key")
}

func TestCollectorStripsAllMetadataWhenAllowlistEmptyNonNil(t *testing.T) {
	collector := NewCollector(map[string]bool{})
	signal := Signal{
		Source:    SourceValidator,
		Operation: "cross_account_access",
		Outcome:   OutcomeSuccess,
		Metadata:  map[string]string{"custom_key": "custom-value"},
	}
	require.True(t, collector.Record(signal))
	signals := collector.Signals()
	require.Len(t, signals, 1, "empty non-nil allowlist must keep the signal")
	require.Nil(t, signals[0].Metadata, "empty non-nil allowlist must strip all metadata keys")
	require.Equal(t, 1, collector.StrippedKeys())
}

func TestCollectorCountsRejectedSignals(t *testing.T) {
	collector := NewCollector(nil)
	require.False(t, collector.Record(Signal{Source: SourceValidator, Operation: "bad operation", Outcome: OutcomeFailure}))
	require.Empty(t, collector.Signals())
	require.Equal(t, 1, collector.Rejected())
	require.Zero(t, collector.Dropped(), "an invalid signal is rejected, not dropped for capacity")
}

func TestSanitizeMetadataTrimsAndTruncatesLongValues(t *testing.T) {
	longValue := ""
	for range MaxMetadataValueLength + 50 {
		longValue += "x"
	}

	sanitized := SanitizeMetadata(map[string]string{
		"padded":     "  value-with-padding  ",
		"oversized":  longValue,
		"unaffected": "fine",
	})

	require.Equal(t, "value-with-padding", sanitized["padded"])
	require.Len(t, sanitized["oversized"], MaxMetadataValueLength)
	require.Equal(t, "fine", sanitized["unaffected"])
}

func TestSanitizeMetadataTruncatesOnRuneBoundary(t *testing.T) {
	// Build a value whose truncation point (byte MaxMetadataValueLength)
	// would otherwise land in the middle of a multi-byte rune.
	prefix := ""
	for range MaxMetadataValueLength - 1 {
		prefix += "x"
	}
	value := prefix + "\u00e9\u00e9" // 2-byte runes straddling the boundary

	sanitized := SanitizeMetadata(map[string]string{"key": value})

	require.True(t, len(sanitized["key"]) <= MaxMetadataValueLength)
	require.True(t, utf8.ValidString(sanitized["key"]), "truncation must not split a multi-byte rune")
}

// TestCollectorRecordSanitizesInsteadOfDropping guards against a regression
// where attacker-controlled metadata values (e.g. cross-account cookie
// values surfaced via a Lua data source) exceeding MaxMetadataValueLength,
// or carrying incidental whitespace, would cause the *entire* audit signal
// to be silently discarded — losing a security-relevant denial event.
func TestCollectorRecordSanitizesInsteadOfDropping(t *testing.T) {
	longValue := ""
	for range MaxMetadataValueLength + 50 {
		longValue += "a"
	}

	collector := NewCollector(nil)
	collector.Record(Signal{
		Source:     SourceDataSource,
		Operation:  "cross_account_access",
		Outcome:    OutcomeDenied,
		ReasonCode: "policy_denied",
		Metadata:   map[string]string{"target_account_number": longValue},
	})

	signals := collector.Signals()
	require.Len(t, signals, 1, "oversized metadata value must be truncated, not dropped")
	require.Len(t, signals[0].Metadata["target_account_number"], MaxMetadataValueLength)

	collector2 := NewCollector(nil)
	collector2.Record(Signal{
		Source:    SourceDataSource,
		Operation: "cross_account_access",
		Outcome:   OutcomeDenied,
		Metadata:  map[string]string{"target_org_id": "  padded-org  "},
	})

	signals2 := collector2.Signals()
	require.Len(t, signals2, 1, "whitespace-padded metadata value must be trimmed, not dropped")
	require.Equal(t, "padded-org", signals2[0].Metadata["target_org_id"])
}

func TestCollectorClonesMetadataToPreventMutation(t *testing.T) {
	collector := NewCollector(map[string]bool{
		"target_org_id":         true,
		"target_account_number": true,
	})

	metadata := map[string]string{
		"target_org_id":         "org-123",
		"target_account_number": "acct-456",
	}
	signal := Signal{
		Source:    SourceValidator,
		Operation: "cross_account_access",
		Outcome:   OutcomeSuccess,
		Metadata:  metadata,
	}

	collector.Record(signal)

	metadata["authorization"] = "Bearer secret-token"
	metadata["password"] = "secret123"

	stored := collector.Signals()
	require.Len(t, stored, 1)
	require.Equal(t, "org-123", stored[0].Metadata["target_org_id"])
	require.Equal(t, "acct-456", stored[0].Metadata["target_account_number"])

	_, hasAuth := stored[0].Metadata["authorization"]
	require.False(t, hasAuth, "stored signal must not contain authorization added after recording")

	_, hasPassword := stored[0].Metadata["password"]
	require.False(t, hasPassword, "stored signal must not contain password added after recording")

	require.Len(t, stored[0].Metadata, 2, "stored signal should only have original 2 keys")
}

// metadata_keys_stripped describes recorded signals only: keys on a signal
// that was rejected or dropped are already accounted for by those counters.
func TestCollectorCountsStrippedKeysOnlyForRecordedSignals(t *testing.T) {
	collector := NewCollector(map[string]bool{})
	require.False(t, collector.Record(Signal{
		Source: SourceValidator, Operation: "bad operation", Outcome: OutcomeFailure,
		Metadata: map[string]string{"a": "1", "b": "2"},
	}))
	require.Equal(t, 1, collector.Rejected())
	require.Zero(t, collector.StrippedKeys())
}

// Every Reason* constant must be accepted by ValidReasonCode. The constants
// and the lookup set are separate declarations; this keeps them in step.
func TestEveryReasonConstantIsAValidReasonCode(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "signal.go", nil, 0)
	require.NoError(t, err)
	found := 0
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if !strings.HasPrefix(name.Name, "Reason") || i >= len(spec.Values) {
				continue
			}
			lit, ok := spec.Values[i].(*ast.BasicLit)
			if !ok {
				continue
			}
			value, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			require.True(t, ValidReasonCode(value), "%s is not in reasonCodes", name.Name)
			found++
		}
		return true
	})
	require.Equal(t, len(reasonCodes), found, "reasonCodes has entries with no Reason* constant")
}
