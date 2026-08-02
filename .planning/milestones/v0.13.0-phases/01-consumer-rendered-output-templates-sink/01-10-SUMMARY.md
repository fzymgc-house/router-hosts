---
phase: 01-consumer-rendered-output-templates-sink
plan: 10
subsystem: config
tags: [client, config, cli, mtls, regression, gap-closure]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 01-03)
    provides: LoadClientConfig's layer-1/2/3 precedence and the strict
      unknown-key rejection this plan's explicit-path branch preserves
provides:
  - "ClientConfigOverrides.ConfigPath — selects the file layer-1 reads, bypassing XDG auto-discovery"
  - "LoadClientConfig explicit-path branch: fail-loud, no cross-layer merge, unchanged precedence"
  - "defaultNewClientFromFlags wiring Flags.Config into overrides.ConfigPath"
  - "--config precedence documented in docs/reference/cli.md and docs/guides/consumer-rendered-output.md"
affects: [01-11]

actuals:
  tokens: 3825
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Explicit-path config resolution stays in layer 1 (never inside applyClientOverrides at layer 3), so file precedence is never accidentally promoted above env vars"
    - "Two-stage RED (structural field-only compile, then behavior RED) as the mandated shape for a tracer task's TDD contract"

key-files:
  created: []
  modified:
    - internal/config/client.go
    - internal/config/client_test.go
    - internal/client/commands/connect.go
    - internal/client/commands/connect_test.go
    - docs/reference/cli.md
    - docs/guides/consumer-rendered-output.md

key-decisions:
  - "Explicit-path branch placed before findClientConfigFile in layer 1, not inside applyClientOverrides, preserving file < env < flag precedence"
  - "TestLoadClientConfig_ExplicitPathTildeExpanded asserts on the expanded absolute path in the resulting read-error text rather than writing into the real home directory, per CLAUDE.md's no-real-filesystem-writes rule"
  - "root.go:88's --config help string left unchanged — 'path to config file (default: auto-detected)' remains accurate after this fix"

patterns-established:
  - "A resolution-selecting override field (ConfigPath) is documented at its struct definition as asymmetric to the override fields around it, rather than left to be inferred from call-site behavior"

requirements-completed: [TMPL-05]

coverage:
  - id: D1
    description: "An explicit --config path is loaded directly and wins over XDG auto-discovery"
    requirement: TMPL-05
    verification:
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ExplicitPathBeatsXDG"
        status: pass
      - kind: unit
        ref: "internal/client/commands/connect_test.go#TestDefaultNewClientFromFlags_ConfigFlagSelectsFile"
        status: pass
    human_judgment: false
  - id: D2
    description: "An unreadable, unparseable, or unknown-key explicit path fails loudly and never falls back to XDG"
    requirement: TMPL-05
    verification:
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ExplicitMissingPathFailsAndDoesNotFallBack"
        status: pass
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ExplicitMalformedPathFails"
        status: pass
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ExplicitUnknownKeyFails"
        status: pass
    human_judgment: false
  - id: D3
    description: "An explicit load replaces the file layer wholesale — no field from an XDG-discovered decoy config survives"
    requirement: TMPL-05
    verification:
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ExplicitPathDoesNotMergeXDGValues"
        status: pass
    human_judgment: false
  - id: D4
    description: "Layer precedence unchanged: explicit config file < env vars < CLI value flags"
    requirement: TMPL-05
    verification:
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_EnvBeatsExplicitConfigFile"
        status: pass
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ServerOverrideBeatsExplicitConfigFile"
        status: pass
    human_judgment: false
  - id: D5
    description: "An empty ConfigPath pointer behaves identically to unset, and tilde expansion runs on the explicit path"
    requirement: TMPL-05
    verification:
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_EmptyConfigPathFallsBackToXDG"
        status: pass
      - kind: unit
        ref: "internal/config/client_test.go#TestLoadClientConfig_ExplicitPathTildeExpanded"
        status: pass
    human_judgment: false
  - id: D6
    description: "--config precedence and XDG search order documented for operators"
    verification:
      - kind: other
        ref: "rumdl check docs/reference/cli.md docs/guides/consumer-rendered-output.md"
        status: pass
    human_judgment: false

duration: ~15min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 10: Honor the explicit --config path in the client Summary

**`watch --config <path>` now loads exactly that file, bypasses XDG auto-discovery entirely, and fails loudly on a bad path instead of silently dialing whatever the search finds (closes gap G-01-1's plumbing half).**

## Performance

- **Duration:** ~15 min
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- `ClientConfigOverrides.ConfigPath` added and consumed in `LoadClientConfig`'s layer 1, ahead of `findClientConfigFile`, so an explicit `--config` path is loaded directly and the XDG search never runs when one is supplied
- `defaultNewClientFromFlags` plumbs `Flags.Config` into `overrides.ConfigPath`, closing the single-hit-in-`root.go`-only defect that was the original root-cause evidence
- Nine regression tests in `internal/config/client_test.go` pin explicit-path precedence, fail-loud behavior, anti-merge (no field from an XDG decoy survives), and unchanged file<env<flag ordering
- Two command-layer tests in `internal/client/commands/connect_test.go` prove the flag reaches the loader
- `docs/reference/cli.md` and `docs/guides/consumer-rendered-output.md` document the resolution rule, the XDG search order, and the one-config-file-per-sink deployment pattern

## Task Commits

1. **Task 1: Explicit --config path wins, wired flag-to-loader end to end** - `83efc50` (fix)
2. **Task 2: Fail loudly, never merge, never reorder — the remaining resolution contract** - `2bc48f1` (test)
3. **Task 3: Document --config precedence where operators will actually read it** - `0ae565a` (docs)

*TDD tracer task (Task 1) was single-commit: Stage A (structural RED) and Stage B (GREEN implementation) were verified as separate steps but landed together, consistent with the plan's tracer/tdd task type rather than a strict RED-commit/GREEN-commit split.*

## Files Created/Modified

- `internal/config/client.go` - `ClientConfigOverrides.ConfigPath` field + layer-1 explicit-path branch ahead of `findClientConfigFile`
- `internal/config/client_test.go` - 9 new tests: explicit-path-beats-XDG, missing/malformed/unknown-key fail-loud, anti-merge, env/CLI-still-outrank, empty-path-falls-back, tilde-expansion
- `internal/client/commands/connect.go` - `Flags.Config` plumbed into `overrides.ConfigPath`
- `internal/client/commands/connect_test.go` - `TestDefaultNewClientFromFlags_ConfigFlagSelectsFile` proving the flag reaches the loader
- `docs/reference/cli.md` - `--config` resolution rule + XDG search order subsection
- `docs/guides/consumer-rendered-output.md` - multi-sink deployment paragraph (one config file + one CN per sink)

## Decisions Made

- Explicit-path branch lives in `LoadClientConfig` layer 1 (never inside `applyClientOverrides`, which runs at layer 3 after env vars) — placement is load-bearing per the plan and is pinned by `TestLoadClientConfig_EnvBeatsExplicitConfigFile`/`TestLoadClientConfig_ServerOverrideBeatsExplicitConfigFile`.
- `TestLoadClientConfig_ExplicitPathTildeExpanded` takes the plan's specified fallback: it asserts the read error names the expanded absolute path (not a literal `~/`) rather than writing a real file under the developer's home directory, since CLAUDE.md forbids writing to the real filesystem in tests.
- `TestDefaultNewClientFromFlags_ConfigFlagSelectsFile` also took the plan's pre-authorized fallback: the dial is lazy, so the resolved address isn't directly observable through that seam. It points the explicit file at an empty `[server] address` while the XDG decoy carries a valid one, and asserts on the `server address is required` validation error — only reachable if the explicit file (not the decoy) was actually loaded.
- `root.go:88`'s `--config` flag help string ("path to config file (default: auto-detected)") was left unchanged — it remains accurate after this fix, so it was not churned.

## Stage A RED Output (Task 1, mandatory per plan)

Field-only change (`ConfigPath *string` added to `ClientConfigOverrides`, no consumption yet), both new tests written, then run:

```text
=== RUN   TestLoadClientConfig_ExplicitPathBeatsXDG
    client_test.go:338:
        	Error Trace:	/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/config/client_test.go:338
        	Error:      	Not equal:
        	            	expected: "explicit.example:18443"
        	            	actual  : "decoy.invalid:59999"
        	            	
        	            	Diff:
        	            	--- Expected
        	            	+++ Actual
        	            	@@ -1 +1 @@
        	            	-explicit.example:18443
        	            	+decoy.invalid:59999
        	Test:       	TestLoadClientConfig_ExplicitPathBeatsXDG
--- FAIL: TestLoadClientConfig_ExplicitPathBeatsXDG (0.00s)
FAIL
FAIL	github.com/fzymgc-house/router-hosts/internal/config	0.247s
```

```text
=== RUN   TestDefaultNewClientFromFlags_ConfigFlagSelectsFile
    connect_test.go:96:
        	Error Trace:	/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/client/commands/connect_test.go:96
        	Error:      	"connecting to server: building transport credentials: TLS configuration required: set cert_path, key_path, and ca_cert_path" does not contain "server address is required"
        	Test:       	TestDefaultNewClientFromFlags_ConfigFlagSelectsFile
--- FAIL: TestDefaultNewClientFromFlags_ConfigFlagSelectsFile (0.00s)
FAIL
FAIL	github.com/fzymgc-house/router-hosts/internal/client/commands	0.276s
```

Both failures are behavioral, not compile failures: the first shows the decoy address `decoy.invalid:59999` was returned where `explicit.example:18443` was expected; the second shows the decoy's non-empty address was loaded (tripping TLS validation) rather than the explicit file's empty address (which would trip the targeted `server address is required` error) — the decoy config was demonstrably the one in effect before the fix.

## Task 2 Pre-fix RED Observations (mandatory per plan)

The layer-1 explicit-path branch was temporarily disabled (`if false && ...`) and the two load-bearing tests re-run:

```text
=== RUN   TestLoadClientConfig_ExplicitMissingPathFailsAndDoesNotFallBack
    client_test.go:355:
        	Error:      	An error is expected but got nil.
        	Test:       	TestLoadClientConfig_ExplicitMissingPathFailsAndDoesNotFallBack
--- FAIL: TestLoadClientConfig_ExplicitMissingPathFailsAndDoesNotFallBack (0.00s)
```

A nil error here is exactly the G-01-1 silent-fallback failure mode: the XDG decoy was used in place of the (missing) explicit file with no signal to the operator.

```text
=== RUN   TestLoadClientConfig_ExplicitPathDoesNotMergeXDGValues
    client_test.go:414:
        	Error:      	Not equal:
        	            	expected: "explicit.example:18443"
        	            	actual  : "decoy.invalid:59999"
    client_test.go:418:
        	Error:      	Should be empty, but was /decoy/client.crt
--- FAIL: TestLoadClientConfig_ExplicitPathDoesNotMergeXDGValues (0.00s)
```

Pre-fix, both the decoy's server address and its `/decoy/client.crt` certificate path leaked through — the exact cross-layer credential-inheritance risk T-01-G1-03 mitigates. The branch was restored immediately after capturing this output and verified byte-identical to the committed version via `diff` before proceeding.

## Deviations from Plan

None - plan executed exactly as written, including both pre-authorized fallbacks named in the plan's `<deviation_policy>` (tilde-expansion assertion shape, and the empty-address discriminator for the lazy-dial seam).

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 01-11 (real-process observation of this fix from an actual OS process, the only vantage point from which G-01-1 was originally visible) can proceed; nothing in this plan blocks it.
- `task ci` and `task test:coverage:ci` (86.3% coverage) both green at plan end.
- `rg -n 'Flags\.Config' --type go` now returns 3 hits (registration in `root.go`, consumption in `connect.go`) versus the pre-fix single hit that was the original root-cause evidence.

## Self-Check: PASSED

All created/modified files found on disk; all three task commits (`83efc50`, `2bc48f1`, `0ae565a`) found in git log.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*
