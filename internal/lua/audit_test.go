package lua

import (
	"context"
	"testing"

	auditctx "github.com/project-kessel/parsec/internal/audit"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

type recordingReporter struct{ signals []auditctx.Signal }

func (r *recordingReporter) Record(signal auditctx.Signal) { r.signals = append(r.signals, signal) }

func TestRegisterAuditServiceRecordsValidatedSignal(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := &recordingReporter{}
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`audit.record({source="validator", operation="user_enrichment", outcome="failure", reason_code="dependency_failure"})`))
	require.Equal(t, []auditctx.Signal{{Source: "validator", Operation: "user_enrichment", Outcome: "failure", ReasonCode: "dependency_failure"}}, reporter.signals)
}

// TestRegisterAuditServiceSanitizesOversizedMetadata guards against a
// regression where an attacker-controlled metadata value (e.g. a request
// cookie surfaced by a data source script) exceeding the audit metadata
// length limit, or carrying incidental whitespace, would cause audit.record
// to reject the entire signal instead of truncating/trimming the value.
func TestRegisterAuditServiceSanitizesOversizedMetadata(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := &recordingReporter{}
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
		reason_code = "cross_account_denied",
		metadata = { target_account_number = long_value, target_org_id = "  padded  " }
	}) == true)`))

	require.Len(t, reporter.signals, 1, "oversized/padded metadata must be sanitized, not dropped")
	require.Len(t, reporter.signals[0].Metadata["target_account_number"], auditctx.MaxMetadataValueLength)
	require.Equal(t, "padded", reporter.signals[0].Metadata["target_org_id"])
}

func TestRegisterAuditServiceRejectsUnsafeOrUnknownFields(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := &recordingReporter{}
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="bad operation", outcome="failure"}) == false)`))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="ok", outcome="failure", secret="leak"}) == false)`))
	require.Empty(t, reporter.signals)
}
