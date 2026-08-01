package commands

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSinkStatus_WriteAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt.status")
	want := sinkStatus{
		LastSuccess:         time.Now().UTC().Truncate(time.Second),
		LastError:           "boom",
		ConsecutiveFailures: 3,
		ContractVersion:     "1",
		RenderedChangeID:    "01ABC",
		ReloadFailed:        true,
		LastReloadSuccess:   time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, writeSinkStatus(path, want))

	got, err := readSinkStatus(path)
	require.NoError(t, err)
	assert.True(t, want.LastSuccess.Equal(got.LastSuccess))
	assert.Equal(t, want.LastError, got.LastError)
	assert.Equal(t, want.ConsecutiveFailures, got.ConsecutiveFailures)
	assert.Equal(t, want.ContractVersion, got.ContractVersion)
	assert.Equal(t, want.RenderedChangeID, got.RenderedChangeID)
	assert.Equal(t, want.ReloadFailed, got.ReloadFailed)
	assert.True(t, want.LastReloadSuccess.Equal(got.LastReloadSuccess))
}

func TestSinkStatus_SuccessClearsError(t *testing.T) {
	var s sinkHealthState
	s.recordFailure(assert.AnError)
	require.NotEmpty(t, s.snapshot().LastError)

	now := time.Now().UTC()
	s.recordSuccess("01CHANGE", now)

	got := s.snapshot()
	assert.Empty(t, got.LastError)
	assert.Zero(t, got.ConsecutiveFailures)
	assert.True(t, now.Equal(got.LastSuccess))
	assert.Equal(t, "01CHANGE", got.RenderedChangeID)
}

func TestSinkStatus_FailurePreservesLastSuccess(t *testing.T) {
	var s sinkHealthState
	now := time.Now().UTC()
	s.recordSuccess("01CHANGE", now)

	s.recordFailure(assert.AnError)

	got := s.snapshot()
	assert.True(t, now.Equal(got.LastSuccess))
	assert.Equal(t, "01CHANGE", got.RenderedChangeID)
	assert.Equal(t, 1, got.ConsecutiveFailures)
	assert.NotEmpty(t, got.LastError)
}

func TestSinkStatus_FailurePreservesRenderedChangeID(t *testing.T) {
	var s sinkHealthState
	s.recordSuccess("01CHANGE", time.Now().UTC())
	s.recordFailure(assert.AnError)
	s.recordFailure(assert.AnError)

	got := s.snapshot()
	assert.Equal(t, "01CHANGE", got.RenderedChangeID)
	assert.Equal(t, 2, got.ConsecutiveFailures)
}

func TestSinkStatus_ReloadFailureKeepsWriteHealth(t *testing.T) {
	var s sinkHealthState
	now := time.Now().UTC()
	s.recordSuccess("01CHANGE", now)

	s.recordReloadFailure(assert.AnError, time.Now().UTC())

	got := s.snapshot()
	assert.True(t, now.Equal(got.LastSuccess))
	assert.Equal(t, "01CHANGE", got.RenderedChangeID)
	assert.Zero(t, got.ConsecutiveFailures)
	assert.True(t, got.ReloadFailed)
}

func TestSinkStatus_ReloadSuccessClearsFlag(t *testing.T) {
	var s sinkHealthState
	s.recordSuccess("01CHANGE", time.Now().UTC())
	s.recordReloadFailure(assert.AnError, time.Now().UTC())
	require.True(t, s.snapshot().ReloadFailed)

	now := time.Now().UTC()
	s.recordReloadSuccess(now)

	got := s.snapshot()
	assert.False(t, got.ReloadFailed)
	assert.True(t, now.Equal(got.LastReloadSuccess))
}

func TestSinkStatus_DefaultPath(t *testing.T) {
	assert.Equal(t, "/tmp/out.txt.status", defaultStatusPath("/tmp/out.txt"))
}

func TestSinkStatus_ReadMissingFileIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.status")

	got, err := readSinkStatus(path)
	require.NoError(t, err)
	assert.Equal(t, sinkStatus{}, got)
}

func TestSinkStatus_ReadCorruptFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.status")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))

	_, err := readSinkStatus(path)
	require.Error(t, err)
}

func TestSinkStatus_ConcurrentAccess(t *testing.T) {
	var s sinkHealthState
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.snapshot()
			}
		}
	}()

	const writers = 8
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			for range 50 {
				s.recordSuccess("id", time.Now().UTC())
				s.recordFailure(assert.AnError)
				s.recordReloadFailure(assert.AnError, time.Now().UTC())
				s.recordReloadSuccess(time.Now().UTC())
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
