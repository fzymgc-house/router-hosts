package server

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// HookExecutor runs post-edit shell hooks sequentially.
type HookExecutor struct {
	onSuccess []config.HookDefinition
	onFailure []config.HookDefinition
	timeout   time.Duration
	log       *slog.Logger
}

// NewHookExecutor creates an executor with the given hook definitions.
func NewHookExecutor(onSuccess, onFailure []config.HookDefinition, timeout time.Duration, logger *slog.Logger) *HookExecutor {
	return &HookExecutor{
		onSuccess: onSuccess,
		onFailure: onFailure,
		timeout:   timeout,
		log:       logger,
	}
}

// RunSuccess executes on-success hooks sequentially. Returns the count of
// hooks that failed.
func (h *HookExecutor) RunSuccess(ctx context.Context, entryCount int) int {
	return h.runHooks(ctx, h.onSuccess, "success", entryCount, "")
}

// RunFailure executes on-failure hooks sequentially. Returns the count of
// hooks that failed.
func (h *HookExecutor) RunFailure(ctx context.Context, entryCount int, errMsg string) int {
	return h.runHooks(ctx, h.onFailure, "failure", entryCount, errMsg)
}

// HookNames returns the names of all configured hooks (success + failure).
func (h *HookExecutor) HookNames() []string {
	names := make([]string, 0, len(h.onSuccess)+len(h.onFailure))
	for _, hook := range h.onSuccess {
		names = append(names, hook.Name)
	}
	for _, hook := range h.onFailure {
		names = append(names, hook.Name)
	}
	return names
}

// HookCount returns the total number of configured hooks.
func (h *HookExecutor) HookCount() int {
	return len(h.onSuccess) + len(h.onFailure)
}

// runHooks executes hooks sequentially, logging failures without propagating.
func (h *HookExecutor) runHooks(ctx context.Context, hooks []config.HookDefinition, event string, entryCount int, errMsg string) int {
	failures := 0
	for _, hook := range hooks {
		if err := h.executeHook(ctx, hook, event, entryCount, errMsg); err != nil {
			failures++
			h.log.Error("hook failed",
				"hook", hook.Name,
				"event", event,
				"error", err,
			)
		} else {
			h.log.Info("hook completed",
				"hook", hook.Name,
				"event", event,
			)
		}
	}
	return failures
}

// executeHook runs a single hook command with timeout and environment variables.
func (h *HookExecutor) executeHook(ctx context.Context, hook config.HookDefinition, event string, entryCount int, errMsg string) error {
	hookCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	sanitizedErrMsg := strings.ReplaceAll(errMsg, "\r\n", " ")
	sanitizedErrMsg = strings.ReplaceAll(sanitizedErrMsg, "\n", " ")
	sanitizedErrMsg = strings.ReplaceAll(sanitizedErrMsg, "\r", " ")
	sanitizedErrMsg = strings.ReplaceAll(sanitizedErrMsg, "\x00", "")

	cmd := exec.CommandContext(hookCtx, "sh", "-c", hook.Command)
	cmd.Env = append(cmd.Environ(),
		"ROUTER_HOSTS_EVENT="+event,
		"ROUTER_HOSTS_ENTRY_COUNT="+strconv.Itoa(entryCount),
		"ROUTER_HOSTS_ERROR="+sanitizedErrMsg,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return oops.Code(domain.CodeInternal).Wrapf(err, "hook %q (output: %s)", hook.Name, string(output))
	}
	return nil
}
