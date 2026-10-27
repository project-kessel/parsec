package request

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaxCacheLayersSaturation(t *testing.T) {
	state := &AuditState{}
	for i := 0; i < maxCacheLayers+1; i++ {
		status := "miss"
		if i == maxCacheLayers {
			status = "hit"
		}
		state.RecordCacheLayer("layer", status)
	}

	cacheStatus, layers, _ := state.Snapshot()
	require.Len(t, layers, maxCacheLayers,
		"cacheLayers must not grow past maxCacheLayers even though RecordCacheLayer was called more times")
	require.Equal(t, "hit", cacheStatus,
		"terminal cacheStatus must still reflect the last call even after the slice is full")
}

func TestRecordCacheLayerConcurrent(t *testing.T) {
	state := &AuditState{}
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			state.RecordCacheLayer("layer", "hit")
		}(i)
		go func(i int) {
			defer wg.Done()
			state.SetFailureReason("dependency_failure")
		}(i)
	}
	wg.Wait()

	cacheStatus, layers, failureReason := state.Snapshot()
	require.Equal(t, "hit", cacheStatus)
	require.LessOrEqual(t, len(layers), maxCacheLayers,
		"cacheLayers must never exceed maxCacheLayers under concurrent access")
	require.Equal(t, "dependency_failure", failureReason)
}

func TestLayerNameSanitized(t *testing.T) {
	tests := []struct {
		name  string
		layer string
		want  string
	}{
		{name: "empty", layer: "", want: "unknown"},
		{name: "whitespace only", layer: "   ", want: "unknown"},
		{name: "control character", layer: "datasource:back\noffice", want: "unknown"},
		{name: "oversized", layer: strings.Repeat("a", maxLayerNameLength+50), want: strings.Repeat("a", maxLayerNameLength)},
		{name: "normal", layer: "datasource:backoffice", want: "datasource:backoffice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &AuditState{}
			state.RecordCacheLayer(tt.layer, "hit")
			_, layers, _ := state.Snapshot()
			require.Len(t, layers, 1)
			require.Equal(t, tt.want, layers[0].Layer)
		})
	}
}

func TestRecordCacheLayerDropsInvalidStatus(t *testing.T) {
	state := &AuditState{}
	state.RecordCacheLayer("layer", "bogus")
	cacheStatus, layers, _ := state.Snapshot()
	require.Empty(t, cacheStatus)
	require.Empty(t, layers)
}

func TestSetFailureReasonFirstWriterWins(t *testing.T) {
	state := &AuditState{}
	state.SetFailureReason("dependency_failure")
	state.SetFailureReason("supplemental_user_data_failure")

	_, _, failureReason := state.Snapshot()
	require.Equal(t, "dependency_failure", failureReason,
		"the first failure reason must win; subsequent calls must be no-ops")
}

func TestSnapshotOnNilState(t *testing.T) {
	var state *AuditState
	cacheStatus, layers, failureReason := state.Snapshot()
	require.Empty(t, cacheStatus)
	require.Empty(t, layers)
	require.Empty(t, failureReason)

	// RecordCacheLayer and SetFailureReason must also tolerate a nil receiver.
	state.RecordCacheLayer("layer", "hit")
	state.SetFailureReason("dependency_failure")
}
