package commands

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchPolicy_Defaults(t *testing.T) {
	p := DefaultWatchPolicy()
	assert.Equal(t, time.Second, p.InitialBackoff)
	assert.Equal(t, 60*time.Second, p.MaxBackoff)
	assert.Equal(t, 30*time.Second, p.StatusInterval)
	require.NotNil(t, p.Jitter)
}

func TestWatchPolicy_NormalizesZeroFields(t *testing.T) {
	p := WatchPolicy{InitialBackoff: 5 * time.Second}
	n := p.normalized()

	assert.Equal(t, 5*time.Second, n.InitialBackoff)
	assert.Equal(t, DefaultWatchPolicy().MaxBackoff, n.MaxBackoff)
	assert.Equal(t, DefaultWatchPolicy().StatusInterval, n.StatusInterval)
	require.NotNil(t, n.Jitter)
}

func TestWatchPolicy_NilJitterIsSafe(t *testing.T) {
	p := WatchPolicy{Jitter: nil}
	n := p.normalized()

	require.NotNil(t, n.Jitter)
	assert.Equal(t, 5*time.Second, n.Jitter(5*time.Second))
}

func TestWatchPolicy_DefaultJitterInRange(t *testing.T) {
	const d = 10 * time.Second
	for range 200 {
		got := defaultJitter(d)
		assert.GreaterOrEqual(t, int64(got), int64(d/2))
		assert.LessOrEqual(t, int64(got), int64(d+d/2))
	}
}
