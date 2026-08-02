package server

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSinkHealth_RecordAndSnapshot(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.RecordSeen("sink-a")
	h.RecordStatus("sink-a", SinkState{
		LastSuccess:         time.Unix(1000, 0).UTC(),
		ConsecutiveFailures: 2,
		ContractVersion:     "v1",
		RenderedChangeID:    "01ABC",
	})

	snap := h.Snapshot()
	require.Contains(t, snap.States, "sink-a")
	st := snap.States["sink-a"]
	assert.Equal(t, time.Unix(1000, 0).UTC(), st.LastSuccess)
	assert.Equal(t, int64(2), st.ConsecutiveFailures)
	assert.Equal(t, "v1", st.ContractVersion)
	assert.Equal(t, "01ABC", st.RenderedChangeID)
	assert.False(t, st.LastSeen.IsZero())
}

func TestSinkHealth_StateSurvivesDisconnect(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.Connect()
	h.RecordStatus("sink-a", SinkState{LastSuccess: time.Now().UTC()})

	before := h.Snapshot().States["sink-a"]
	h.Disconnect()

	after := h.Snapshot()
	require.Contains(t, after.States, "sink-a")
	assert.Equal(t, before.LastSeen, after.States["sink-a"].LastSeen)
	assert.Equal(t, before.LastSuccess, after.States["sink-a"].LastSuccess)
}

func TestSinkHealth_ConnectedCountFloorsAtZero(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.Disconnect()
	h.Disconnect()
	assert.Equal(t, int64(0), h.Snapshot().Connected)

	h.Connect()
	assert.Equal(t, int64(1), h.Snapshot().Connected)
	h.Disconnect()
	h.Disconnect()
	assert.Equal(t, int64(0), h.Snapshot().Connected)
}

func TestSinkHealth_ConnectNeedsNoIdentity(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.Connect()
	h.Connect()
	assert.Equal(t, int64(2), h.Snapshot().Connected)
	h.Disconnect()
	assert.Equal(t, int64(1), h.Snapshot().Connected)
}

func TestSinkHealth_ReloadFailureKeepsLastSuccess(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	writeTime := time.Unix(2000, 0).UTC()
	h.RecordStatus("sink-a", SinkState{
		LastSuccess:  writeTime,
		ReloadFailed: false,
	})
	h.RecordStatus("sink-a", SinkState{
		LastSuccess:  writeTime,
		ReloadFailed: true,
	})

	st := h.Snapshot().States["sink-a"]
	assert.Equal(t, writeTime, st.LastSuccess)
	assert.True(t, st.ReloadFailed)
}

// isConverged mirrors the convergence rule the OTel callback (Task 3)
// applies: a reported RenderedChangeID that is non-empty and equal to the
// snapshot's ServerChangeID.
func isConverged(snap SinkSnapshot, cn string) bool {
	st, ok := snap.States[cn]
	if !ok {
		return false
	}
	return st.RenderedChangeID != "" && st.RenderedChangeID == snap.ServerChangeID
}

func TestSinkHealth_ConvergedWhenChangeIDMatches(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.RecordServerChange("01CHANGE")
	h.RecordStatus("sink-a", SinkState{RenderedChangeID: "01CHANGE"})
	h.RecordStatus("sink-b", SinkState{RenderedChangeID: "01OTHER"})

	snap := h.Snapshot()
	assert.True(t, isConverged(snap, "sink-a"))
	assert.False(t, isConverged(snap, "sink-b"))
}

func TestSinkHealth_NotConvergedWithoutReportedChangeID(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	// Server change ID never set (zero value ""); sink never reports one
	// either. A naive equality check would call this converged since both
	// sides are "". It must not.
	h.RecordStatus("sink-a", SinkState{})

	snap := h.Snapshot()
	assert.False(t, isConverged(snap, "sink-a"))
}

func TestSinkHealth_EvictsOldestPastCeiling(t *testing.T) {
	// Not parallel: mutates the package-level MaxTrackedSinks.
	original := MaxTrackedSinks
	MaxTrackedSinks = 3
	t.Cleanup(func() { MaxTrackedSinks = original })

	h := NewSinkHealth()
	h.RecordSeen("sink-1")
	time.Sleep(2 * time.Millisecond)
	h.RecordSeen("sink-2")
	time.Sleep(2 * time.Millisecond)
	h.RecordSeen("sink-3")
	time.Sleep(2 * time.Millisecond)
	// A 4th distinct identity pushes the registry past MaxTrackedSinks=3,
	// evicting sink-1 (oldest LastSeen).
	h.RecordSeen("sink-4")

	snap := h.Snapshot()
	assert.Len(t, snap.States, 3)
	assert.NotContains(t, snap.States, "sink-1")
	assert.Contains(t, snap.States, "sink-2")
	assert.Contains(t, snap.States, "sink-3")
	assert.Contains(t, snap.States, "sink-4")
}

func TestSinkHealth_SnapshotIsACopy(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.RecordSeen("sink-a")

	snap := h.Snapshot()
	snap.States["sink-a"] = SinkState{ContractVersion: "mutated"}
	snap.States["sink-b"] = SinkState{}

	snap2 := h.Snapshot()
	assert.NotContains(t, snap2.States, "sink-b")
	assert.NotEqual(t, "mutated", snap2.States["sink-a"].ContractVersion)
}

func TestSinkHealth_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n*2 + 1)

	for i := range n {
		i := i
		go func() {
			defer wg.Done()
			h.RecordStatus(concurrentCN(i), SinkState{ConsecutiveFailures: int64(i)})
		}()
		go func() {
			defer wg.Done()
			h.RecordSeen(concurrentCN(i))
		}()
	}
	go func() {
		defer wg.Done()
		for range 20 {
			_ = h.Snapshot()
		}
	}()

	wg.Wait()
}

func concurrentCN(i int) string {
	return "sink-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
}

func TestSinkHealth_IdentityFailureCounts(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.Connect()
	h.RecordIdentityFailure()
	h.RecordIdentityFailure()

	snap := h.Snapshot()
	assert.Equal(t, int64(2), snap.IdentityFailures)
	assert.Equal(t, int64(1), snap.Connected)
}

func TestSinkHealth_DuplicateCNCollapsesLastWriterWins(t *testing.T) {
	t.Parallel()

	h := NewSinkHealth()
	h.RecordStatus("shared-cn", SinkState{RenderedChangeID: "01FIRST"})
	h.RecordStatus("shared-cn", SinkState{RenderedChangeID: "01SECOND"})

	snap := h.Snapshot()
	assert.Len(t, snap.States, 1)
	assert.Equal(t, "01SECOND", snap.States["shared-cn"].RenderedChangeID)
}
