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

func TestRegisterAuditServiceRejectsUnsafeOrUnknownFields(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	reporter := &recordingReporter{}
	RegisterAuditService(L, auditctx.WithReporter(context.Background(), reporter))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="bad operation", outcome="failure"}) == false)`))
	require.NoError(t, L.DoString(`assert(audit.record({source="validator", operation="ok", outcome="failure", secret="leak"}) == false)`))
	require.Empty(t, reporter.signals)
}
