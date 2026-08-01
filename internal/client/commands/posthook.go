package commands

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/samber/oops"
)

// defaultPostWriteHookTimeout bounds a post-write hook (D-16) when
// --exec-timeout is not set.
const defaultPostWriteHookTimeout = 30 * time.Second

// runPostWriteHook runs command (via "sh -c") after a successful artifact
// write, so a consumer can reload its resolver without operator
// intervention (D-16). An empty command is a no-op returning nil — running
// the "watch" sink without --exec is fully supported.
//
// This mirrors internal/server/hooks.go's executeHook exactly: the same
// exec.CommandContext(hookCtx, "sh", "-c", ...) shape, and the same
// classification order — hookCtx.Err() is inspected BEFORE the process
// error, so a deadline kill is reported as a timeout and not as an
// indistinguishable generic non-zero exit.
func runPostWriteHook(ctx context.Context, command string, timeout time.Duration) error {
	if command == "" {
		return nil
	}

	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(hookCtx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()

	// Classify by inspecting the hook's own context FIRST. When
	// context.WithTimeout kills the subprocess, exec.CommandContext reports
	// an ordinary *exec.ExitError indistinguishable from a hook that failed
	// on its own merits — checking hookCtx.Err() before the process error is
	// the only reliable way to tell a deadline kill from a self-inflicted
	// non-zero exit (internal/server/hooks.go's same ordering).
	switch {
	case errors.Is(hookCtx.Err(), context.DeadlineExceeded):
		return oops.Errorf("post-write hook timed out after %s (output: %s)", timeout, string(output))
	case err != nil:
		return oops.Wrapf(err, "post-write hook failed (output: %s)", string(output))
	}
	return nil
}
