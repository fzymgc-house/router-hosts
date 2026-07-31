# Phase 9: Hook Reliability & Metrics - Context

**Gathered:** 2026-07-31
**Status:** Ready for planning
**Mode:** Smart discuss (autonomous)

<domain>

## Phase Boundary

Post-edit hooks become observable and can no longer stall the write path.

This phase covers exactly two defects in the existing `on_success` / `on_failure`
hook mechanism:

- **HOOK-01** — `Metrics.RecordHookExecution` is implemented but unreachable. Wire
  hook execution metrics so every hook run emits count, duration, and outcome.
- **HOOK-02** — hook execution uses a hardcoded 30s timeout and runs synchronously
  on the gRPC write path. Make the timeout configurable per hook and bound
  execution so a slow hook cannot block write processing.

In scope: `internal/server/hooks.go`, the hook wiring in `internal/server/service.go`
and `internal/client/commands/serve.go`, hook metric recording in
`internal/server/metrics.go`, hook config schema/validation in
`internal/config/server.go`, and the hook documentation in
`docs/guides/operations.md` + `docs/reference/configuration.md`.

Out of scope: the hook environment-variable contract, hook name validation rules,
the set of events that fire hooks, and any change to generator behavior.

</domain>

<decisions>

## Implementation Decisions

### Hook Execution Model

- **Detach hooks from the RPC write path.** `regenerateOutputs` hands hook
  execution to a background runner with a server-lifecycle context and returns as
  soon as outputs are written. This is safe because hook errors already never
  propagate — `regenerateOutputs` logs them and returns `void`
  (`internal/server/service.go:111-121`), so the RPC caller never observed hook
  outcomes to begin with. Detaching forfeits no signal.
- **Sequential within a batch.** Hooks inside one event batch keep running in
  declaration order — post-edit hooks are typically order-dependent (write, then
  reload the consumer). Bound the number of in-flight *batches* rather than
  parallelising hooks against each other.
- **Queue depth 1 with coalescing.** When a regeneration fires while a batch is
  still running, collapse superseded pending runs instead of queuing them
  unboundedly. Hooks react to current output-file state, so latest-wins is
  correct; a superseded run would only re-read the same files. Emit a dedicated
  metric for the coalesced run (see Metrics Semantics Q4).
- **Bounded drain on shutdown.** In-flight hooks drain within a grace period tied
  to the existing `GracefulShutdownTimeout` (`internal/server/server.go`), then
  their context is cancelled.

### Timeout Configuration Surface

- **Per-hook `timeout` field on `HookDefinition`** (`internal/config/server.go:151-156`),
  falling back to a server-level `[hooks] default_timeout`, which itself defaults
  to the current 30s. Per-hook granularity matters because a `systemctl reload`
  and a webhook POST have very different latency profiles.
- **Go duration strings in TOML** — `timeout = "10s"`, `timeout = "2m"` — parsed
  with `time.ParseDuration`. Idiomatic for a Go server and self-documenting in
  config files.
- **Must be > 0**, rejected at config-validation time using the established
  `oops.Code(domain.CodeValidation).Errorf(...)` pattern already used by
  `HookDefinition.validate` (`internal/config/server.go:369-383`). No upper cap:
  once hooks are detached from the write path, a long-running hook no longer
  stalls writes, so an arbitrary ceiling would only break legitimate slow hooks.
- **Absent `timeout` inherits the 30s default.** Existing configs keep
  byte-identical behavior. No migration, no deprecation, no breaking change.

### Metrics Semantics

- **Reuse the existing instruments unchanged.** `router_hosts_hook_executions_total`
  and `router_hosts_hook_duration_seconds` already exist with `name` / `type` /
  `status` labels deliberately matched to the Rust implementation
  (`internal/server/metrics.go:81-94`, `:241-257`). This phase wires them; it
  introduces no new names for the execution path and does not redesign labels.
- **`status` values are `success` / `failure` / `timeout`.** HOOK-02 promotes
  timeout to a first-class outcome, so it earns a distinct label value rather
  than being folded into `failure`. This is a deliberate, accepted divergence
  from strict Rust label parity.
- **`WithMetrics` functional option defaulting to `DisabledMetrics()`**
  (`internal/server/metrics.go:190`). The executor always holds a non-nil
  `*Metrics`, so there are no nil-checks at record call sites. Necessary because
  `serve.go:129-133` only constructs real metrics when `cfg.Metrics.OTel` is set.
- **Coalesced/dropped runs get their own dedicated counter** (e.g.
  `router_hosts_hook_runs_coalesced_total`) rather than a `status="skipped"`
  value on `executions_total`. Keeps `executions_total` semantically honest — it
  counts runs that actually executed a command — while still making queue
  pressure alertable.

### Claude's Discretion

- Naming of the background runner type, its internal channel/goroutine structure,
  and the exact name of the coalesced counter.
- Whether the runner lives in `hooks.go` or a sibling file.
- Test structure and the split of work across plans, subject to the repo's
  TDD and ≥80% coverage requirements.

</decisions>

<code_context>

## Existing Code Insights

### Reusable Assets

- `Metrics.RecordHookExecution(ctx, name, hookType, status string, duration time.Duration)`
  — `internal/server/metrics.go:244`. Fully implemented, instruments already
  registered. Needs only a caller.
- `DisabledMetrics()` — `internal/server/metrics.go:190`. Returns a `*Metrics`
  backed by `noop.Meter{}`; safe to call recording methods on. This is the
  no-nil-check path for the executor default.
- `HookExecutor.HookNames()` / `HookCount()` — `internal/server/hooks.go:48-62`.
  Already consumed by the health endpoint; keep their signatures stable.
- `ServiceOption` functional-option pattern — `internal/server/service.go:59-72`
  (`WithHookExecutor`, `WithUnboundGenerator`, `WithVersion`). The established
  shape for `WithMetrics`.
- `HookDefinition.validate()` / `HooksConfig.validate()` —
  `internal/config/server.go:342-383`. Where timeout validation belongs.

### Established Patterns

- **Errors:** `samber/oops` with `oops.Code(domain.CodeValidation)` for config
  errors and `oops.Code(domain.CodeInternal).Wrapf` for runtime failures
  (`hooks.go:101`).
- **Logging:** `log/slog` with key/value pairs; hook logs already carry
  `"hook"` and `"event"` keys (`hooks.go:68-78`).
- **Metrics:** OTel with attribute sets built via `otelmetric.WithAttributes`;
  duration histograms deliberately omit the `status` label to bound cardinality
  (`metrics.go:251-256`) — preserve that when adding the `timeout` status.
- **Config:** TOML struct tags with a `validate()` method per config struct.

### Integration Points

- `internal/client/commands/serve.go:100-108` — constructs `HookExecutor` with
  the hardcoded `defaultHookTimeout` const (`:19-20`) and does **not** pass
  `metrics`, which is constructed at `:129-133` and currently only reaches the
  gRPC interceptors at `:146-147`. This is the wiring gap behind HOOK-01.
- `internal/server/service.go:150-168` — the hook fire site inside
  `regenerateOutputs`; the seam where detachment happens.
- `internal/server/service.go:211, 285, 314, 594, 850` — synchronous
  `regenerateOutputs` calls from `AddHost`, `UpdateHost`, `DeleteHost`,
  `ImportHosts`, `RollbackToSnapshot`. These are the write paths currently
  exposed to N×30s of hook latency.
- `docs/guides/operations.md:5-54` — documents "Hooks run with 30s timeout"
  (`:14`); must be updated when the timeout becomes configurable.
- `docs/reference/configuration.md` — hook config reference; needs the new
  `timeout` / `default_timeout` keys.

</code_context>

<specifics>

## Specific Ideas

- The `status="timeout"` divergence from Rust parity was explicitly raised and
  explicitly accepted — do not "fix" it back to `success`/`failure` during
  planning or review.
- `router_hosts_hook_executions_total` must keep counting only real executions.
  Coalescing gets a separate instrument specifically so `executions_total` stays
  a truthful execution count.
- Existing hook configs must continue to work untouched. A config with no
  `timeout` anywhere must behave exactly as it does today.

</specifics>

<deferred>

## Deferred Ideas

- Redesigning the hook metric label set now that the instruments are finally
  reachable — rejected for this phase; the Rust-parity labels stay.
- Parallel hook execution within a batch (worker pool) — rejected in favor of
  order-preserving sequential execution; revisit only if a real workload needs it.
- Retry/backoff for failed hooks — not raised as a requirement; out of scope.

</deferred>
