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

	executor.RunSuccess(context.Background(), 10)

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

	executor.RunSuccess(context.Background(), 42)

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

	// Should complete without panic; failure is logged internally.
	executor.RunSuccess(context.Background(), 0)
}

func TestHookExecutor_Empty(t *testing.T) {
	executor := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())

	executor.RunSuccess(context.Background(), 0)
	executor.RunFailure(context.Background(), 0, "test error")
}

func TestHookExecutor_FailedHook(t *testing.T) {
	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "bad-hook", Command: "exit 1"}},
		nil,
		5*time.Second,
		slog.Default(),
	)

	// Should complete without panic; failure is logged internally.
	executor.RunSuccess(context.Background(), 5)
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

	executor.RunSuccess(context.Background(), 3)

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

	executor.RunFailure(context.Background(), 5, "disk full")

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
	executor.RunFailure(context.Background(), 1, injectedErrMsg)

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

func TestHookExecutor_ErrorMessageSanitizesAllControlChars(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "ctrl-env.txt")

	executor := NewHookExecutor(
		nil,
		[]config.HookDefinition{{
			Name:    "ctrl-check",
			Command: "printenv ROUTER_HOSTS_ERROR > " + envFile,
		}},
		5*time.Second,
		slog.Default(),
	)

	// errMsg contains \r\n (CRLF), standalone \n, standalone \r, and a null byte.
	dirtyErrMsg := "before\r\nafter\nnewline\rcarriage\x00null"
	executor.RunFailure(context.Background(), 1, dirtyErrMsg)

	data, err := os.ReadFile(envFile)
	require.NoError(t, err)
	// printenv appends a trailing newline; trim it before checking so the
	// assertion does not false-positive on that shell-appended newline.
	content := strings.TrimRight(string(data), "\n")

	// None of the raw control characters must survive sanitization.
	assert.NotContains(t, content, "\r\n", "CRLF must be removed from ROUTER_HOSTS_ERROR")
	assert.NotContains(t, content, "\n", "LF must be removed from ROUTER_HOSTS_ERROR")
	assert.NotContains(t, content, "\r", "CR must be removed from ROUTER_HOSTS_ERROR")
	assert.NotContains(t, content, "\x00", "null byte must be removed from ROUTER_HOSTS_ERROR")

	// The non-control text from each segment must still be present.
	assert.Contains(t, content, "before")
	assert.Contains(t, content, "after")
	assert.Contains(t, content, "newline")
	assert.Contains(t, content, "carriage")
	assert.Contains(t, content, "null")
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

	executor.RunSuccess(context.Background(), 0)

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
