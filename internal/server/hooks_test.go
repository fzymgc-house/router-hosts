package server

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/config"
)

func TestHookExecutor_SuccessHook(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")

	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "touch-file", Command: "touch " + marker}},
		nil,
		5*time.Second,
		slog.Default(),
	)

	failures := executor.RunSuccess(context.Background(), 10)
	assert.Equal(t, 0, failures)

	_, err := os.Stat(marker)
	assert.NoError(t, err)
}

func TestHookExecutor_EnvVars(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env.txt")

	executor := NewHookExecutor(
		[]config.HookDefinition{{
			Name:    "dump-env",
			Command: "env | grep ROUTER_HOSTS > " + envFile,
		}},
		nil,
		5*time.Second,
		slog.Default(),
	)

	failures := executor.RunSuccess(context.Background(), 42)
	assert.Equal(t, 0, failures)

	data, err := os.ReadFile(envFile)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "ROUTER_HOSTS_EVENT=success")
	assert.Contains(t, content, "ROUTER_HOSTS_ENTRY_COUNT=42")
	assert.Contains(t, content, "ROUTER_HOSTS_ERROR=")
}

func TestHookExecutor_Timeout(t *testing.T) {
	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "slow-hook", Command: "sleep 10"}},
		nil,
		100*time.Millisecond,
		slog.Default(),
	)

	failures := executor.RunSuccess(context.Background(), 0)
	assert.Equal(t, 1, failures)
}

func TestHookExecutor_Empty(t *testing.T) {
	executor := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())

	failures := executor.RunSuccess(context.Background(), 0)
	assert.Equal(t, 0, failures)
	failures = executor.RunFailure(context.Background(), 0, "test error")
	assert.Equal(t, 0, failures)
}

func TestHookExecutor_FailedHook(t *testing.T) {
	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "bad-hook", Command: "exit 1"}},
		nil,
		5*time.Second,
		slog.Default(),
	)

	failures := executor.RunSuccess(context.Background(), 5)
	assert.Equal(t, 1, failures)
}

func TestHookExecutor_PartialFailure(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ok")

	executor := NewHookExecutor(
		[]config.HookDefinition{
			{Name: "good-hook", Command: "touch " + marker},
			{Name: "bad-hook", Command: "exit 1"},
			{Name: "also-good", Command: "true"},
		},
		nil,
		5*time.Second,
		slog.Default(),
	)

	failures := executor.RunSuccess(context.Background(), 3)
	assert.Equal(t, 1, failures)

	// First hook should have run
	_, err := os.Stat(marker)
	assert.NoError(t, err)
}

func TestHookExecutor_FailureHooksWithError(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "err-env.txt")

	executor := NewHookExecutor(
		nil,
		[]config.HookDefinition{{
			Name:    "err-hook",
			Command: "env | grep ROUTER_HOSTS > " + envFile,
		}},
		5*time.Second,
		slog.Default(),
	)

	failures := executor.RunFailure(context.Background(), 5, "disk full")
	assert.Equal(t, 0, failures)

	data, err := os.ReadFile(envFile)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "ROUTER_HOSTS_EVENT=failure")
	assert.Contains(t, content, "ROUTER_HOSTS_ERROR=disk full")
}

func TestHookExecutor_ErrorMessageSanitization(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "sanitized-env.txt")

	executor := NewHookExecutor(
		nil,
		[]config.HookDefinition{{
			Name:    "sanitize-check",
			Command: "env | grep ROUTER_HOSTS > " + envFile,
		}},
		5*time.Second,
		slog.Default(),
	)

	// errMsg contains newline injection attempt: if not sanitized,
	// ROUTER_HOSTS_EVENT=injected could appear as a separate env var.
	injectedErrMsg := "real error\r\nROUTER_HOSTS_EVENT=injected\r\n"
	failures := executor.RunFailure(context.Background(), 1, injectedErrMsg)
	assert.Equal(t, 0, failures)

	data, err := os.ReadFile(envFile)
	require.NoError(t, err)
	content := string(data)

	// ROUTER_HOSTS_EVENT must remain 'failure'.
	assert.Contains(t, content, "ROUTER_HOSTS_EVENT=failure")

	// ROUTER_HOSTS_ERROR must not contain raw newlines so the value cannot
	// break out of a single line and inject additional env vars.
	errorLineStart := strings.Index(content, "ROUTER_HOSTS_ERROR=")
	require.NotEqual(t, -1, errorLineStart, "ROUTER_HOSTS_ERROR not found in env output")
	errorLine := content[errorLineStart:]
	if nlIdx := strings.IndexAny(errorLine, "\r\n"); nlIdx != -1 {
		errorLine = errorLine[:nlIdx]
	}
	assert.NotContains(t, errorLine, "\r")
	assert.NotContains(t, errorLine, "\n")
	// The newlines were replaced with spaces; original text is still present.
	assert.Contains(t, errorLine, "real error")
	// The injected text is part of the sanitized error value (not a separate
	// env var), confirming the shell cannot interpret it as a new assignment.
	assert.Contains(t, errorLine, "ROUTER_HOSTS_ERROR=real error")
	// Verify ROUTER_HOSTS_EVENT=injected does NOT appear as its own env line.
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		assert.False(t, line == "ROUTER_HOSTS_EVENT=injected",
			"newline injection created a separate ROUTER_HOSTS_EVENT=injected env line")
	}
}

func TestHookExecutor_SequentialOrder(t *testing.T) {
	dir := t.TempDir()
	orderFile := filepath.Join(dir, "order.txt")

	executor := NewHookExecutor(
		[]config.HookDefinition{
			{Name: "first", Command: "echo first >> " + orderFile},
			{Name: "second", Command: "echo second >> " + orderFile},
			{Name: "third", Command: "echo third >> " + orderFile},
		},
		nil,
		5*time.Second,
		slog.Default(),
	)

	failures := executor.RunSuccess(context.Background(), 0)
	assert.Equal(t, 0, failures)

	data, err := os.ReadFile(orderFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, "first", lines[0])
	assert.Equal(t, "second", lines[1])
	assert.Equal(t, "third", lines[2])
}

func TestHookExecutor_HookNames(t *testing.T) {
	executor := NewHookExecutor(
		[]config.HookDefinition{
			{Name: "reload-dns", Command: "true"},
			{Name: "notify", Command: "true"},
		},
		[]config.HookDefinition{
			{Name: "alert", Command: "true"},
		},
		5*time.Second,
		slog.Default(),
	)

	names := executor.HookNames()
	assert.Equal(t, []string{"reload-dns", "notify", "alert"}, names)
}

func TestHookExecutor_HookCount(t *testing.T) {
	executor := NewHookExecutor(
		[]config.HookDefinition{
			{Name: "a", Command: "true"},
			{Name: "b", Command: "true"},
		},
		[]config.HookDefinition{
			{Name: "c", Command: "true"},
		},
		5*time.Second,
		slog.Default(),
	)

	assert.Equal(t, 3, executor.HookCount())
}
