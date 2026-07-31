---
phase: 260728-ude
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - internal/operator/service_controller.go
  - internal/operator/service_controller_test.go
autonomous: true
requirements: [WR-01, WR-02]
must_haves:
  truths:
    - "A Service whose aliases annotation lists more than validation.MaxAliasesPerEntry entries produces a Warning Event with reason InvalidConfiguration on `kubectl describe service`, not a silent requeueDelayLong loop (WR-01, D-12)."
    - "A Service whose ip-address annotation is present but not a parseable IP produces a Warning Event with reason InvalidConfiguration, distinct from MissingIPAddress which still means the annotation is absent (WR-02, D-12)."
    - "Both InvalidConfiguration cases are terminal: Reconcile returns ctrl.Result{} with no RequeueAfter (D-14)."
    - "Neither InvalidConfiguration case deletes a previously published host entry — an unusable annotation freezes the published state instead of tearing it down."
    - "serviceDesiredAliases still returns a non-nil slice on every path, so a cleared aliases annotation still clears server-side aliases (RESEARCH Pitfall 2 / T-08-15)."
    - "The MaxAliasesPerEntry branch inside validation.ValidateAliases is reachable from the Service controller (T-08-14 closed)."
  artifacts:
    - internal/operator/service_controller.go
    - internal/operator/service_controller_test.go
  key_links:
    - "serviceAliasCandidates -> serviceAliasesExceedCap -> syncService InvalidConfiguration event (WR-01 path)"
    - "serviceIPOverride -> resolveServiceIP validation -> syncService empty-ip branch split (WR-02 path)"
    - "serviceAliasCandidates -> serviceDesiredAliases: one parse, two consumers, so 'which segments count' has a single definition"
---

# Quick 260728-ude — Make Two Silent Service Misconfigurations Visible

<objective>
Close WR-01 and WR-02 from `08-REVIEW.md`. Both are the same defect wearing two hats: a
misconfigured Service is rejected server-side on every reconcile, requeued at
`requeueDelayLong` forever, and emits **no** Kubernetes Event — so the Service owner sees a
Service that silently never works, with nothing in `kubectl describe service`. Neither corrupts
DNS (the server is the bounding control), so this is a visibility fix, not a correctness fix.

Purpose: make the 50-alias cap reachable client-side, format-validate the `ip-address`
override, and give both failures a `kubectl describe service` signal via a fifth Event reason,
`InvalidConfiguration` — extending D-12's four operator-visible states and following D-14's
terminal-no-requeue rule.

Output: `internal/operator/service_controller.go` plus its test file. No other package changes.
</objective>

<execution_context>
@$HOME/.claude/gsd-core/workflows/execute-plan.md
@$HOME/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/phases/08-kubernetes-service-controller/08-REVIEW.md
@.planning/phases/08-kubernetes-service-controller/08-CONTEXT.md
@internal/operator/service_controller.go
@internal/operator/service_controller_test.go
@internal/validation/validation.go
@CLAUDE.md
</context>

<design_decisions>
Read this before writing code. These resolve the ambiguities the tasks depend on.

**1. `InvalidConfiguration` is a fifth reason, not a reuse of `MissingIPAddress`.**
`MissingIPAddress` means the annotation is **absent**. `InvalidConfiguration` means an
annotation is **present but unusable**. Collapsing them would make a typo indistinguishable
from an omission in `kubectl describe service`, which is the exact invisibility WR-02 reports.
D-12 enumerated four states because this failure mode was not yet known; adding a fifth extends
D-12's intent (operator-visible states get Events) rather than contradicting it.

**2. `InvalidConfiguration` freezes, it does not tear down.**
When the branch fires, carry any previously tracked ID for the hostname forward into `newIDs`
(the same one-liner the waiting branch already uses at `service_controller.go:364-366`) so the
stale-cleanup pass does not delete the published entry. Rationale: the D-17 stale-cleanup
deletions are all **known** stop-managing transitions — opt-out, type change, hostname change,
annotation removed. A typo is not a stop-managing transition; it means "desired state unknown".
Deleting a working DNS entry because someone added a 51st alias is the destructive reading.

**3. Terminal, per D-14.** Do not set `hadError` and do not set a `RequeueAfter`. The endless
retry is the bug being fixed; the next Service edit re-triggers reconcile naturally.

**4. Signature discipline.** `serviceDesiredAliases` and `resolveServiceIP` keep their current
signatures. All nine existing `TestServiceDesiredAliases` subtests and all ten existing
`TestResolveServiceIP` subtests must compile and pass with zero edits to their assertions. The
new terminal decisions are made in `syncService`, which is where the Recorder lives.
</design_decisions>

<tasks>

<task type="tracer" tdd="true">
<name>Task 1: Validate the ip-address override and surface it as InvalidConfiguration</name>
<files>internal/operator/service_controller.go, internal/operator/service_controller_test.go</files>
<precondition>The operator package is green before any edit: `task test -- ./internal/operator/` passes and `rg -c '^func Test' internal/operator/service_controller_test.go` reports 18.</precondition>
<read_first>

- `internal/operator/service_controller.go:45-55` — the four-reason const block and its D-12/D-14 doc comment
- `internal/operator/service_controller.go:134-170` — resolveServiceIP and its evaluation-order doc comment
- `internal/operator/service_controller.go:294-388` — syncService doc comment and the inner IP switch
- `internal/validation/validation.go:21-30` — ValidateIPAddress
- `internal/operator/service_controller_test.go:104-191` — TestResolveServiceIP subtest shape
- `internal/operator/service_controller_test.go:441-586` — TestSyncService_Events, FakeRecorder assertion shape

</read_first>
<behavior>

- resolveServiceIP, NodePort with a padded override value -> returns the trimmed IP and waiting false, matching the TrimSpace the hostname path already applies.
- resolveServiceIP, NodePort with an unparseable override -> returns empty IP and waiting false: invalid is never returned as an IP.
- resolveServiceIP, LoadBalancer with a hostname pasted into the override AND a status ingress IP present -> returns empty IP, NOT the status IP: an explicit-but-broken override must not be silently papered over by falling through to LoadBalancer status.
- syncService, NodePort with an unparseable override -> emits a Warning Event whose reason is InvalidConfiguration, NOT MissingIPAddress.
- syncService, NodePort with the annotation absent -> still emits MissingIPAddress, unchanged.
- syncService, unparseable override on an already-tracked Service -> returns ctrl.Result{} with no RequeueAfter and issues no DeleteHost; the host-ids annotation still carries the previous ID.

</behavior>
<action>
Add `reasonInvalidConfiguration = "InvalidConfiguration"` to the reason const block and update
that block's doc comment: it currently describes four operator-visible failure/waiting states
and lists which are terminal — make it five, and record the absent-versus-present-but-unusable
distinction stated in design decision 1.

Add an unexported helper `serviceIPOverride(svc *corev1.Service) string` returning the
TrimSpace'd `serviceIPAddressAnnotation` value, empty when absent or blank. Both
`resolveServiceIP` and `syncService` must call it, so "the override is present" has exactly one
definition.

In `resolveServiceIP`, replace the verbatim-return override branch: take the value from
`serviceIPOverride`, and when non-empty run `validation.ValidateIPAddress` on it. On error return
an empty IP with waiting false immediately — do not fall through to `Status.LoadBalancer.Ingress`,
per the third behavior case. On success return it as today. Use the project validator, not a
stdlib address parser, so client and server agree on what valid means and no new import is
needed. Extend the function's numbered evaluation-order doc comment to cover the new outcome of
step 2.

In `syncService`'s inner IP switch, split the existing empty-ip case on whether
`serviceIPOverride(svc)` is non-empty. Non-empty means present-but-unusable: emit a Warning with
`reasonInvalidConfiguration` naming the annotation key and quoting the offending value, log at
Warn, and apply design decisions 2 and 3 — carry the existing ID forward into `newIDs` when one
exists, leave `hadError` and `waiting` untouched. Empty keeps today's `reasonMissingIPAddress`
branch byte-for-byte. Add the new state to `syncService`'s bulleted doc comment alongside the
existing four.

Tests: add three subtests to `TestResolveServiceIP` (padded-valid override, unparseable override,
unparseable override does not fall through to LoadBalancer status), one subtest to
`TestSyncService_Events` asserting the FakeRecorder message contains the Warning
InvalidConfiguration prefix, and a new top-level regression test named
`TestSyncService_InvalidIPOverrideEmitsInvalidConfiguration` covering the terminal, no-delete, and
ID-retained trio on an already-tracked Service. Reuse the existing `newReadySvc`,
`newTrackedService`, and `noAddHostMock` helpers; do not add new ones.
</action>
<verify>
<automated>task test -- -v -run 'ResolveServiceIP|SyncService_InvalidIPOverride|SyncService_Events' ./internal/operator/ 2>&amp;1 | rg -c '^--- PASS'</automated>

Expect exactly 3 top-level PASS lines (TestResolveServiceIP, TestSyncService_Events,
TestSyncService_InvalidIPOverrideEmitsInvalidConfiguration). Go's `-run` is an unanchored regex;
a lower number means a test name did not match, not that everything passed.

Print-and-inspect gates — read the printed output, never a bare exit status:

- `rg -v '^\s*//' internal/operator/service_controller.go | rg -c 'validation\.ValidateIPAddress'` prints 1
- `rg -n 'ParseIP' internal/operator/service_controller.go` prints nothing (project validator used, no new stdlib parse, no new import)
- `rg -n 'InvalidConfiguration' internal/operator/service_controller.go` prints the const plus at least one emitEvent call site

</verify>
<done>An invalid or whitespace-padded ip-address annotation is trimmed, validated, and never returned as an IP, and produces a Warning InvalidConfiguration Event; the absent-annotation path still produces MissingIPAddress; the invalid path returns ctrl.Result{} and deletes nothing. All ten pre-existing TestResolveServiceIP subtests pass with no edits.</done>
</task>

<task type="auto" tdd="true">
<name>Task 2: Make the aggregate alias cap reachable and event-visible</name>
<files>internal/operator/service_controller.go, internal/operator/service_controller_test.go</files>
<read_first>

- `internal/operator/service_controller.go:201-245` — serviceDesiredAliases and its D-07 doc comment
- `internal/operator/service_controller.go:371-387` — the inner default branch that computes aliases then calls syncServiceHost
- `internal/validation/validation.go:82-100` — ValidateAliases, its immediate-return cap branch, and the too_many_aliases code
- `internal/server/commands.go:145` — the established oops.AsOops plus Code() inspection pattern in this repo
- `internal/operator/service_controller_test.go:246-344` — the nine TestServiceDesiredAliases subtests that must not change

</read_first>
<behavior>

- serviceAliasCandidates, absent annotation -> non-nil empty slice; blank and whitespace-only segments dropped; no validation applied.
- serviceAliasesExceedCap with 51 valid candidates -> true; with 50 -> false; with 3 candidates where one is invalid -> false, because a bad alias is not a cap violation and must stay drop-with-warning rather than terminal.
- serviceDesiredAliases with 60 valid aliases -> returns all 60, un-truncated: the cap is the caller's terminal decision, and silent truncation would publish a partial alias set the user never asked for.
- syncService with 51 aliases -> emits Warning InvalidConfiguration naming the observed count and the maximum, calls neither AddHost nor UpdateHost, and returns ctrl.Result{}.
- syncService with 51 aliases on an already-tracked Service -> issues no DeleteHost and leaves the tracked ID in the host-ids annotation.
- All nine existing TestServiceDesiredAliases subtests still pass with zero edits.

</behavior>
<action>
Extract the annotation parse into `serviceAliasCandidates(svc *corev1.Service) []string`: comma
split, TrimSpace each segment, skip empties, and build the result with a zero-length make so it
is non-nil on every path. A nil alias slice reaching UpdateHost means "leave the server's aliases
alone" (`internal/operator/grpc_hostclient.go:131-133`), which is Phase 8's T-08-15 and RESEARCH
Pitfall 2. Rewrite `serviceDesiredAliases` to consume this helper instead of splitting inline; its
signature, its per-alias validation, its warn-and-drop semantics, its case-insensitive dedupe, and
its non-nil zero-length result all stay exactly as they are.

Add `serviceAliasesExceedCap(candidates []string, canonicalHostname string) bool`: call
`validation.ValidateAliases(candidates, canonicalHostname)` ONE time on the full slice and report
true when a returned error carries the too_many_aliases code, using the `oops.AsOops` plus
`Code()` inspection already used at `internal/server/commands.go:145`. This is the fix for WR-01:
the per-alias loop passes a one-element slice, where `validation.go:93`'s length branch is
structurally unreachable, so the aggregate call is the only thing that can ever trip it. Code
inspection rather than a bare length comparison keeps the controller and `internal/validation`
agreeing on one definition of the cap. Do not modify `internal/validation`.

In `syncService`'s inner default branch — the one that currently computes aliases then calls
`syncServiceHost` — compute the candidates first and gate on `serviceAliasesExceedCap` before
either call. When it trips: emit a Warning with `reasonInvalidConfiguration` reporting the
observed candidate count and `validation.MaxAliasesPerEntry`, log at Warn, apply design decisions
2 and 3 (carry any existing ID forward into `newIDs`, do not set `hadError`), and break out of the
inner switch so the stale-cleanup pass still runs. Update the `serviceDesiredAliases` doc comment
to record that the aggregate cap is enforced by the caller and that this function deliberately
does not truncate; add the new state to `syncService`'s bulleted doc comment.

Tests: add one subtest to `TestServiceDesiredAliases` pinning that a 60-alias annotation comes
back with 60 entries, generating the list in a loop; this subtest is the guard against a future
silent-truncation shortcut. Add a new top-level regression test named
`TestSyncService_AliasCapExceededEmitsInvalidConfiguration` covering the Event reason, the
no-AddHost and no-UpdateHost assertion, the ctrl.Result{} assertion, and the no-DeleteHost and
ID-retained assertion on an already-tracked Service.
</action>
<verify>
<automated>task test -- -v -run 'DesiredAliases|AliasCapExceeded' ./internal/operator/ 2>&amp;1 | rg -c '^--- PASS'</automated>

Expect exactly 2 top-level PASS lines (TestServiceDesiredAliases,
TestSyncService_AliasCapExceededEmitsInvalidConfiguration).

Subtest-count gate — the nine originals plus the new one:

- `task test -- -v -run 'DesiredAliases' ./internal/operator/ 2>&amp;1 | rg -c '^\s+--- PASS'` prints 10
- `rg -v '^\s*//' internal/operator/service_controller.go | rg -c 'MaxAliasesPerEntry'` prints at least 1
- `git diff --stat -- internal/validation/ internal/server/` prints nothing, proving the bounding control is untouched

</verify>
<done>A Service listing more than MaxAliasesPerEntry aliases emits Warning InvalidConfiguration, publishes nothing, requeues never, and deletes nothing; serviceDesiredAliases still returns a non-nil, un-truncated slice and its nine original subtests pass unedited.</done>
</task>

<task type="auto">
<name>Task 3: Negative-control, inventory, and coverage gate</name>
<files>internal/operator/service_controller_test.go</files>
<read_first>

- `Taskfile.yml:21-50` — the test and test:coverage:ci targets; `task test` forwards go test args after a bare `--`

</read_first>
<action>
Prove the two new regression tests actually gate, using the negative-control practice this phase
already followed for the chart RBAC assertions (STATE.md, Phase 08 P05). For each one:
temporarily revert the production-side fix — drop the aggregate cap gate, then separately drop
the override validation — run only that regression test, confirm it FAILS loudly with a message
naming the missing behavior, then restore the fix and confirm it passes again. Record both
observed failure messages in the SUMMARY. A regression test that passes against the un-fixed code
is not a regression test.

Then run the whole-package inventory gate. Go's `-run` is an unanchored regex, so a count is the
only trustworthy signal: capture the top-level test inventory from
`rg -c '^func Test' internal/operator/service_controller_test.go`, expected to be 20 after tasks
1 and 2; capture the summed total of `rg -c '^func Test.*Service' internal/operator/*_test.go`,
which covers every top-level test in this package whose name matches the pattern and today lives
entirely in service_controller_test.go, the property that makes the counts comparable; and capture
the top-level PASS count from a run filtered by the Service pattern. Print all three side by side
and require they are equal. If the two inventory numbers disagree, a new test was named without
the substring or another file grew a matching test — fix the naming rather than lowering the
expectation.

Finally run the repo-wide gates and confirm the change set is exactly the two operator files with
no dependency movement.
</action>
<verify>
<automated>task test -- -v -run 'Service' ./internal/operator/ 2>&amp;1 | rg -c '^--- PASS'</automated>
<automated>task test</automated>
<automated>task lint</automated>
<automated>task test:coverage:ci</automated>

Compare the first number against both `rg -c '^func Test' internal/operator/service_controller_test.go`
and the summed `rg -c '^func Test.*Service' internal/operator/*_test.go`. All three must be equal
and equal to 20. Coverage must stay at or above 80% (baseline 85.1%) — print the final total line
from the coverage run rather than trusting the task's exit status.

Change-set gate:

- List the files touched by this plan's commits and confirm the set is exactly `internal/operator/service_controller.go` and `internal/operator/service_controller_test.go`
- `git diff --stat -- go.mod go.sum` prints nothing, proving zero new dependencies

</verify>
<done>Both new regression tests are proven to fail against un-fixed code and pass against fixed code; the top-level PASS count equals the 20-test inventory; task test, task lint, and task test:coverage:ci at 80% or above all pass; only the two operator files changed and go.mod and go.sum are untouched.</done>
</task>

</tasks>

<threat_model>

## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Service annotations -> operator | Any namespace user with Service write access controls hostname, aliases, and ip-address; all are untrusted input crossing into the reconcile loop |
| operator -> router-hosts server | gRPC over mTLS; the server re-validates every field and is the bounding control that keeps both findings non-blocking |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-08-14 | Tampering | malformed or oversized alias list in serviceDesiredAliases | medium | mitigate | Task 2 closes the declared-but-absent over-long-list half: one aggregate ValidateAliases call makes validation.go:93 reachable; the task 3 negative control proves the gate fires |
| T-08-22 | Repudiation | invalid ip-address annotation produces no Kubernetes Event (new; recommended by the 08-SECURITY.md WR-02 note) | medium | mitigate | Task 1 adds reasonInvalidConfiguration, distinct from MissingIPAddress, so a present-but-unusable value is attributable in kubectl describe service |
| T-08-23 | Denial of Service | unbounded requeueDelayLong retry against the server for a permanently invalid Service | low | mitigate | Both new branches are terminal per D-14 — no RequeueAfter, no hadError — removing the self-sustaining retry loop |
| T-08-24 | Denial of Service | a new terminal branch tears down a working DNS entry over a cosmetic annotation typo | medium | mitigate | Design decision 2: InvalidConfiguration carries the tracked ID forward into newIDs, so the stale-cleanup pass issues no DeleteHost; asserted in both regression tests |
| T-08-15 | Tampering | nil alias slice silently retains stale server-side aliases | medium | mitigate | Regression guard preserved: serviceAliasCandidates and serviceDesiredAliases both build a non-nil zero-length slice; TestSyncService_AliasesClearedSendsEmptySlice must stay green |

No package-manager installs in this plan — zero new dependencies, so no legitimacy gate applies.

</threat_model>

<verification>

- `task test` green repo-wide; `task lint` clean.
- `task test:coverage:ci` at 80% or above, baseline 85.1%.
- Top-level PASS count for the Service-filtered run equals the 20-test inventory in `internal/operator/service_controller_test.go`.
- Both new regression tests proven by negative control to fail against un-fixed code.
- `git diff --stat` limited to the two operator files; `internal/validation/`, `internal/server/`, `go.mod`, and `go.sum` untouched.
- Locked decisions intact: no tags annotation added (D-22), no default-IP fallback for Services (D-11), dot-less hostnames still warn-but-accept (D-08), aliases still map to the native Aliases field (D-07), Events still carry the operator-visible states (D-12) and stay terminal (D-14).

</verification>

<success_criteria>

- WR-01: an over-cap aliases annotation is caught client-side by one aggregate ValidateAliases call and reported as Warning InvalidConfiguration instead of being retried forever.
- WR-02: an ip-address value that is absent, blank, whitespace-padded, or unparseable is handled distinctly — absent or blank keeps MissingIPAddress, padded is trimmed and accepted, unparseable becomes Warning InvalidConfiguration and is never published.
- Neither new branch requeues, and neither deletes a previously published host entry.
- All 18 pre-existing top-level tests and their subtests still pass without edits to their assertions; the two new regression tests are named for the behavior they guard.

</success_criteria>

<output>
Create `.planning/quick/260728-ude-fix-wr-01-and-wr-02-from-08-review-md-ag/260728-ude-SUMMARY.md` when done.
Commits follow Conventional Commits with scope `operator` and a subject of 50 characters or fewer,
for example `fix(operator): validate ip-address annotation` and
`fix(operator): enforce alias cap client-side`.
</output>
