package lua

import (
	"context"
	"testing"

	auditctx "github.com/project-kessel/parsec/internal/audit"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

func TestRegisterAuditServiceRecordsValidatedSignal(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := auditctx.NewCollector(nil)
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`audit.record({source="validator", operation="user_enrichment", outcome="failure", reason_code="dependency_failure"})`))
	require.Equal(t, []auditctx.Signal{{Source: "validator", Operation: "user_enrichment", Outcome: "failure", ReasonCode: "dependency_failure"}}, reporter.Signals())
}

// TestRegisterAuditServiceSanitizesOversizedMetadata guards against a
// regression where an attacker-controlled metadata value (e.g. a request
// cookie surfaced by a data source script) exceeding the audit metadata
// length limit, or carrying incidental whitespace, would cause audit.record
// to reject the entire signal instead of truncating/trimming the value.
func TestRegisterAuditServiceSanitizesOversizedMetadata(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := auditctx.NewCollector(nil)
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))

	longValue := ""
	for range auditctx.MaxMetadataValueLength + 50 {
		longValue += "a"
	}
	L.SetGlobal("long_value", lua.LString(longValue))

	require.NoError(t, L.DoString(`assert(audit.record({
		source = "data_source",
		operation = "lookup",
		outcome = "denied",
		reason_code = "policy_denied",
		metadata = { key_b = long_value, key_a = "  padded  " }
	}) == true)`))

	require.Len(t, reporter.Signals(), 1, "oversized/padded metadata must be sanitized, not dropped")
	require.Len(t, reporter.Signals()[0].Metadata["key_b"], auditctx.MaxMetadataValueLength)
	require.Equal(t, "padded", reporter.Signals()[0].Metadata["key_a"])
}

func TestRegisterAuditServiceRejectsUnsafeOrUnknownFields(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := auditctx.NewCollector(nil)
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="bad operation", outcome="failure"}) == false)`))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="ok", outcome="failure", secret="leak"}) == false)`))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="ok", outcome="failure", metadata="not-a-table"}) == false)`))
	require.NoError(t, L.DoString(`assert(audit.record("not-a-table") == false)`))
	require.Empty(t, reporter.Signals())
	require.Equal(t, 4, reporter.Rejected(),
		"every discarded signal is counted, whether the collector or the Lua adapter refused it")
}

func TestRegisterAuditServiceCountsMigrationAndMetadataRejections(t *testing.T) {
	for _, tt := range []struct {
		name   string
		signal string
	}{
		{"removed event field", `{source="validator", operation="ok", outcome="failure", event="old_event"}`},
		{"metadata non-string key", `{source="validator", operation="ok", outcome="failure", metadata={[1]="value"}}`},
		{"metadata unsupported value", `{source="validator", operation="ok", outcome="failure", metadata={key={}}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			reporter := auditctx.NewCollector(nil)
			RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
			require.NoError(t, L.DoString(`assert(audit.record(`+tt.signal+`) == false)`))
			require.Empty(t, reporter.Signals())
			require.Equal(t, 1, reporter.Rejected(), "each discarded signal must be counted exactly once")
		})
	}
}

// A signal whose metadata only becomes valid once disallowed keys are
// stripped must be kept, not rejected at the Lua boundary.
func TestRegisterAuditServiceStripsBeforeValidating(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := auditctx.NewCollector(map[string]bool{"k1": true})
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`assert(audit.record({
		source = "data_source", operation = "enrichment", outcome = "success",
		metadata = { k1="a", k2="b", k3="c", k4="d", k5="e", k6="f", k7="g", k8="h", k9="i" }
	}) == true)`))
	require.Equal(t, map[string]string{"k1": "a"}, reporter.Signals()[0].Metadata)
	require.Equal(t, 8, reporter.StrippedKeys())
}

// A number or boolean metadata value is recorded as a string. Rejecting it
// would lose the whole signal, uncounted, over a missing tostring().
func TestRegisterAuditServiceConvertsScalarMetadataValues(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := auditctx.NewCollector(nil)
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`assert(audit.record({
		source = "data_source", operation = "lookup", outcome = "success",
		metadata = { key_a = 12345, approved = true, key_c = "u1" }
	}) == true)`))
	require.Equal(t, map[string]string{"key_a": "12345", "approved": "true", "key_c": "u1"},
		reporter.Signals()[0].Metadata)

	require.NoError(t, L.DoString(`assert(audit.record({
		source = "data_source", operation = "lookup", outcome = "success",
		metadata = { nested = { a = 1 } }
	}) == false)`))
	require.Len(t, reporter.Signals(), 1, "a table value is still refused")
}
