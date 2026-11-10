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
		operation = "cross_account_access",
		outcome = "denied",
		reason_code = "policy_denied",
		metadata = { target_account_number = long_value, target_org_id = "  padded  " }
	}) == true)`))

	require.Len(t, reporter.Signals(), 1, "oversized/padded metadata must be sanitized, not dropped")
	require.Len(t, reporter.Signals()[0].Metadata["target_account_number"], auditctx.MaxMetadataValueLength)
	require.Equal(t, "padded", reporter.Signals()[0].Metadata["target_org_id"])
}

func TestRegisterAuditServiceRejectsUnsafeOrUnknownFields(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := auditctx.NewCollector(nil)
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="bad operation", outcome="failure"}) == false)`))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="ok", outcome="failure", secret="leak"}) == false)`))
	require.Empty(t, reporter.Signals())
	require.Equal(t, 1, reporter.Rejected(), "a structurally invalid signal must be counted by the collector")
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
		source = "data_source", operation = "cross_account_access", outcome = "success",
		metadata = { target_org_id = 12345, approved = true, employee_user_id = "u1" }
	}) == true)`))
	require.Equal(t, map[string]string{"target_org_id": "12345", "approved": "true", "employee_user_id": "u1"},
		reporter.Signals()[0].Metadata)

	require.NoError(t, L.DoString(`assert(audit.record({
		source = "data_source", operation = "cross_account_access", outcome = "success",
		metadata = { nested = { a = 1 } }
	}) == false)`))
	require.Len(t, reporter.Signals(), 1, "a table value is still refused")
}
