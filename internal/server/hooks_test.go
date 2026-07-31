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
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

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

// router-hosts HOOK-01 / T-09-10: a hook killed by its own deadline must
// record status="timeout", never status="failure" — os/exec surfaces a
// deadline kill as an ordinary *exec.ExitError, so the classifier must
// inspect hookCtx.Err() before the process error (RESEARCH.md Pitfall 3).
func TestHookExecutor_RecordsTimeoutStatus(t *testing.T) {
	m, reader := newTestMetrics(t)

	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "slow-hook", Command: "sleep 10"}},
		nil,
		100*time.Millisecond,
		slog.Default(),
		WithMetrics(m),
	)

	executor.RunSuccess(context.Background(), 0)

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_hook_executions_total")
	require.NotNil(t, counter, "hook_executions_total metric not found")

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected Sum[int64] data type")
	require.Len(t, sum.DataPoints, 1)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "timeout", attrs["status"], "deadline kill must record status=timeout")
	assert.NotEqual(t, "failure", attrs["status"], "deadline kill must NOT record status=failure")
	assert.Equal(t, "success", attrs["type"])
	assert.Equal(t, "slow-hook", attrs["name"])
	assert.Len(t, attrs, 3, "counter attribute key set must be exactly {name, type, status}")

	histogram := findMetric(rm, "router_hosts_hook_duration_seconds")
	require.NotNil(t, histogram, "hook_duration_seconds metric not found")
	histData, ok := histogram.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "expected Histogram[float64] data type")
	require.Len(t, histData.DataPoints, 1)
	histAttrs := make(map[string]string)
	for _, attr := range histData.DataPoints[0].Attributes.ToSlice() {
		histAttrs[string(attr.Key)] = attr.Value.AsString()
	}
	assert.Equal(t, "slow-hook", histAttrs["name"])
	assert.Equal(t, "success", histAttrs["type"])
	_, hasStatus := histAttrs["status"]
	assert.False(t, hasStatus, "duration histogram must not carry a status attribute")
}

// router-hosts HOOK-01 / T-09-10: a hook that exits non-zero well within its
// resolved timeout must record status="failure".
func TestHookExecutor_RecordsFailureStatus(t *testing.T) {
	m, reader := newTestMetrics(t)

	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "bad-hook", Command: "exit 1"}},
		nil,
		5*time.Second,
		slog.Default(),
		WithMetrics(m),
	)

	executor.RunSuccess(context.Background(), 0)

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_hook_executions_total")
	require.NotNil(t, counter, "hook_executions_total metric not found")

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected Sum[int64] data type")
	require.Len(t, sum.DataPoints, 1)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "failure", attrs["status"])
	assert.Equal(t, "success", attrs["type"])
	assert.Equal(t, "bad-hook", attrs["name"])
	assert.Len(t, attrs, 3, "counter attribute key set must be exactly {name, type, status}")
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

// router-hosts HOOK-01: an executor built without WithMetrics, and one built
// with WithMetrics(nil), must both record without panicking — both hold a
// non-nil DisabledMetrics().
func TestNewHookExecutor_DefaultsToDisabledMetrics(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran-default")

	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "touch-file", Command: "touch " + marker}},
		nil,
		5*time.Second,
		slog.Default(),
	)
	// No panic recording against the default DisabledMetrics().
	executor.RunSuccess(context.Background(), 1)
	assert.FileExists(t, marker)

	dir2 := t.TempDir()
	marker2 := filepath.Join(dir2, "ran-nil-metrics")
	executorNilMetrics := NewHookExecutor(
		[]config.HookDefinition{{Name: "touch-file", Command: "touch " + marker2}},
		nil,
		5*time.Second,
		slog.Default(),
		WithMetrics(nil),
	)
	// WithMetrics(nil) must be a no-op, not a nil metrics pointer.
	executorNilMetrics.RunSuccess(context.Background(), 1)
	assert.FileExists(t, marker2)
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
