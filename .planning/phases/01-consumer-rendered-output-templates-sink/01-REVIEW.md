---
phase: 01
scope: gap-closure
scope_note: >-
  This review covers ONLY the G-01-1 gap-closure changes from plans 01-10
  and 01-11 (diff range 2a0272e..HEAD). It supersedes the prior full-phase
  review committed as ee61917 for this narrower scope; it is not a re-review
  of plans 01-01..01-09.
reviewed: 2026-08-01T20:20:00-04:00
depth: standard
files_reviewed: 7
files_reviewed_list:
  - internal/config/client.go
  - internal/config/client_test.go
  - internal/client/commands/connect.go
  - internal/client/commands/connect_test.go
  - e2e/proc_harness_test.go
  - e2e/proc_e2e_test.go
  - Taskfile.yml
findings:
  critical: 0
  warning: 0
  info: 0
  total: 0
status: clean
---

# Phase 01 (gap-closure G-01-1): Code Review Report

**Reviewed:** 2026-08-01T20:20:00-04:00
**Depth:** standard
**Files Reviewed:** 7
**Status:** clean

## Summary

This reviews the gap-closure work for G-01-1 (`--config` was silently ignored,
allowing a sink to connect to the wrong server while reporting healthy) —
plans 01-10 (the fix) and 01-11 (the real-process harness that proves it).
It does not re-review plans 01-01..01-09; see `ee61917` for that.

I read all seven files in full, traced the precedence chain in
`LoadClientConfig` end to end, checked every early-return and error path for
shadowing, and verified the nil/empty `*string` semantics from `connect.go`
through to `LoadClientConfig`. I then went further than static reading: I
ran the full unit suite for both touched packages, ran `golangci-lint` on
both packages (0 issues, no `//nolint` present), built the binary and ran
the real `proc_e2e` suite against the fixed code (3/3 pass, no orphaned
processes afterward), and — as the strongest check available for "can this
regression test actually fail" — reverted `internal/config/client.go` and
`internal/client/commands/connect.go` to their pre-fix (`2a0272e`) content,
rebuilt the real binary, and re-ran the two `proc_e2e` tests that assert the
fix. Both failed with exactly the G-01-1 symptom: the cold-start test
rendered `decoy-target.example` into the artifact (the silent wrong-server
connection), and the "missing config" test wrote a full artifact via silent
XDG fallback instead of erroring. I then restored both files and confirmed
`git status` was clean and the suite passed again. This is about as direct
a confirmation as static review can get that the fix works and the tests
are not vacuous.

Findings by check:

**1. Precedence correctness.** Confirmed correct. The explicit-path branch
lives in layer 1 (`internal/config/client.go:128-141`), before
`applyClientEnv` (layer 2, line 144) and `applyClientOverrides` (layer 3,
line 149-151). `TestLoadClientConfig_EnvBeatsExplicitConfigFile` and
`TestLoadClientConfig_ServerOverrideBeatsExplicitConfigFile`
(`internal/config/client_test.go:421-457`) pin exactly this ordering and
pass.

**2. No silent fallback.** Confirmed. The `if overrides != nil &&
overrides.ConfigPath != nil && *overrides.ConfigPath != ""` branch
(`client.go:128`) is an `if/else if`, not a fallthrough — when it is taken,
`findClientConfigFile()` (the `else if` at line 135) is structurally
unreachable in the same call. Every error path inside the branch (`os.Stat`
failure via `os.ReadFile`, TOML parse failure, `meta.Undecoded()` unknown-key
rejection) is wrapped with `oops.Wrapf(loadErr, "loading client config %s",
path)` and returned immediately — none are logged-and-continued or
downgraded to defaults.

**3. No error shadowing.** Confirmed. `loadErr` in the new branch is a
fresh `:=` declaration scoped to the `if` block; it is checked and returned
before any outer `err`/`cfg` is touched. The `*cfg = *fileCfg` assignment
only happens after the nil-error check, so a load failure returns
`nil, wrapped-error` — `cfg` is never partially populated on failure. Traced
through to the caller in `connect.go:33-36`, which re-wraps with `oops.Wrapf(err,
"loading client config")` and returns; `watch.go:98-101` and every other
call site returns the error from `newClientFromFlags()` unmodified up to
`RunE`, which Cobra's `SilenceErrors: true` + `root.go:108-110`'s explicit
`fmt.Fprintln(os.Stderr, err)` + `os.Exit(1)` in `main.go` turns into a
non-zero exit with the path-bearing message on stderr — verified live via
the pre-fix/post-fix binary swap above.

**4. Empty-string vs nil semantics.** Confirmed correct on both sides.
`connect.go:29-31` only takes `&Flags.Config` when `Flags.Config != ""`, so
an absent `--config` leaves `overrides.ConfigPath` `nil` and layer 1 falls
through to `findClientConfigFile()`. `client.go`'s own guard
(`*overrides.ConfigPath != ""`) is defense-in-depth for direct callers of
`LoadClientConfig` (e.g. tests) that pass a pointer to `""` rather than
`nil` — `TestLoadClientConfig_EmptyConfigPathFallsBackToXDG` pins that this
also falls through to XDG. Both paths agree.

**5. Tilde/path expansion.** Confirmed. `expandTilde` runs on the raw
`*overrides.ConfigPath` before the file read (`client.go:129`), and the
error path names the _expanded_ absolute path, not the literal `~/...` the
user typed — `TestLoadClientConfig_ExplicitPathTildeExpanded` asserts the
error contains the expanded prefix and explicitly asserts it does NOT
contain a literal `~/`. This is a legitimate operator-diagnostics
trade-off (the expanded path is what actually failed to open), not a bug,
and it's covered by a dedicated regression test. No directory-vs-file,
symlink, or empty-result edge case produces a different failure mode:
`os.ReadFile` on a directory returns a `read` error that flows through the
same wrap.

**6. Process/resource hygiene in the harness.** Verified both by reading
and by execution. `startServerProcess` and `startSinkProcess` both use
`exec.CommandContext` plus a `t.Cleanup` that cancels the context, waits up
to 5s on a `stopped` channel fed by a `cmd.Wait()` goroutine, and
force-kills on timeout — covering normal completion, test failure (output is
dumped only in the `t.Failed()` branch), and the case where the process
never exits on cancellation. `cmd.Wait()` also fences the internal
stdout/stderr-copying goroutines, so no data race or leaked goroutine
between the `Buffer` writes and the post-`stop()` `.String()` reads in the
cleanup. All filesystem paths in both files derive from `t.TempDir()`. I
confirmed no orphaned `router-hosts serve`/`watch` processes remained after
running the full suite (`ps aux` empty for both).

**7. Test-quality anti-vacuity.** Confirmed by direct falsification, not
just reading. All three `TestProcE2E_*` tests discriminate on artifact
_content_ (`named-target.example` present AND `decoy-target.example`
absent; not just "non-empty"), and the negative test checks three
independent signals (non-zero exit via `*exec.ExitError`, the exact failed
path appearing in output, and the artifact's absence via `os.IsNotExist`)
rather than a single loose assertion. No `t.Skip` exists in either file
except the pre-existing, orthogonal root-uid guard in
`internal/config/client_test.go`. Reverting the fix and rebuilding the real
binary reproduced the exact G-01-1 symptom and made both tests fail for the
expected reason, which is the strongest available evidence these are not
vacuous.

No Critical, Warning, or Info findings were identified. The `Taskfile.yml`
addition (`test:e2e:proc`) correctly depends on `build`, and its default
binary discovery path (`../bin/router-hosts` relative to `e2e/`) matches
`task build`'s output path — confirmed by running `task build && task
test:e2e:proc` directly, which passed.

## Critical Issues

None found.

## Warnings

None found.

## Info

None found.

---

_Reviewed: 2026-08-01T20:20:00-04:00_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
