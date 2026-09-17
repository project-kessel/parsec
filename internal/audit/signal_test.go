package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollectorBoundsAndPreservesSignals(t *testing.T) {
	collector := &Collector{}
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

	collector := &Collector{}
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

	// Reject non-allowlisted keys to prevent secrets leakage
	withSecret := base
	withSecret.Metadata = map[string]string{"authorization": "Bearer secret-token"}
	require.False(t, Valid(withSecret), "should reject authorization header")

	withClaim := base
	withClaim.Metadata = map[string]string{"jwt_claims": `{"sub":"user-1","email":"user@example.com"}`}
	require.False(t, Valid(withClaim), "should reject jwt_claims")

	withPassword := base
	withPassword.Metadata = map[string]string{"password": "secret123"}
	require.False(t, Valid(withPassword), "should reject password")

	// Verify allowlisted keys still work
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
	require.True(t, Valid(allowlisted), "all allowlisted keys should be accepted")
}

func TestCollectorClonesMetadataToPreventMutation(t *testing.T) {
	collector := &Collector{}

	// Create a signal with valid metadata
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

	// Record the signal
	collector.Record(signal)

	// Attempt to mutate the original metadata map after recording
	// This simulates a malicious caller trying to inject secrets post-validation
	metadata["authorization"] = "Bearer secret-token"
	metadata["password"] = "secret123"

	// Verify the stored signal's metadata was not affected by mutations
	stored := collector.Signals()
	require.Len(t, stored, 1)
	require.Equal(t, "org-123", stored[0].Metadata["target_org_id"])
	require.Equal(t, "acct-456", stored[0].Metadata["target_account_number"])

	// Critically: verify the injected secrets are NOT in the stored signal
	_, hasAuth := stored[0].Metadata["authorization"]
	require.False(t, hasAuth, "stored signal must not contain authorization added after recording")

	_, hasPassword := stored[0].Metadata["password"]
	require.False(t, hasPassword, "stored signal must not contain password added after recording")

	// Verify only the original 2 keys exist
	require.Len(t, stored[0].Metadata, 2, "stored signal should only have original 2 keys")
}
