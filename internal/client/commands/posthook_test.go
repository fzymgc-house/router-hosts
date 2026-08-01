package commands

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostWriteHook_Success(t *testing.T) {
	err := runPostWriteHook(context.Background(), "exit 0", time.Second)
	require.NoError(t, err)
}

func TestPostWriteHook_NonZeroExit(t *testing.T) {
	err := runPostWriteHook(context.Background(), "exit 7", time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "7")
}

func TestPostWriteHook_Timeout(t *testing.T) {
	err := runPostWriteHook(context.Background(), "sleep 5", 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestPostWriteHook_EmptyCommandIsNoop(t *testing.T) {
	require.NoError(t, runPostWriteHook(context.Background(), "", time.Second))
}
