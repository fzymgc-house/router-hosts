---
phase: 08-kubernetes-service-controller
plan: 05
subsystem: infra
tags: [helm, chart, rbac, ci, documentation, service]

# Dependency graph
requires:
  - phase: 08-kubernetes-service-controller (plan 02)
    provides: services + cluster-scoped events RBAC rules in clusterrole.yaml (D-13, D-24)
provides:
  - "serviceController.enabled Helm values key (deliberately non-conventional per D-23) templating --enable-service in deployment.yaml"
  - "Six content-based task test:chart assertions for the Service controller's opt-in flag and RBAC surface, each proven to fail via a manual negative control"
  - "Chart README Service annotation contract: all four annotations, IP resolution rules, event reasons, cleanup, cache footprint, and both deliberate asymmetries (serviceController key naming, no defaultIngressIP fallback)"
affects: [09-hook-reliability-and-metrics, 10-consumer-rendered-output]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Content-comparison Taskfile assertions (capture render into a shell variable, compare/count, print observed value) replacing the Phase 7 grep -q exit-status idiom — established here as the standing pattern for future chart-surface additions"

key-files:
  created: []
  modified:
    - charts/router-hosts-operator/values.yaml
    - charts/router-hosts-operator/templates/deployment.yaml
    - Taskfile.yml
    - charts/router-hosts-operator/README.md

key-decisions:
  - "D-23 followed exactly as specified: the values key is serviceController.enabled, not service.enabled — verified by an explicit grep asserting the bare service: key is absent from values.yaml, in addition to the positive assertions."
  - "Both required negative controls were executed manually rather than added as permanent Taskfile assertions (per the plan's phrasing 'prove it by running... record both outcomes in the plan summary') — widening services verbs to include delete, and deleting the events rule entirely, each independently made task test:chart exit non-zero with a FAIL: line naming the observed/missing content, then charts/router-hosts-operator/templates/clusterrole.yaml was reverted with git checkout -- and re-verified green."
  - "The blockquote note about D-23 key-naming asymmetry was demoted from a `>` blockquote to a plain paragraph after rumdl's MD028 flagged it as merging with the adjacent tagging blockquote (blank line inside blockquote) — same meaning, different markdown construct, to keep task test:chart's own lint dependency (lefthook's lint-markdown/fmt-markdown) green without touching unrelated content."

patterns-established:
  - "Content-comparison Taskfile assertions: capture helm template output into a shell variable, then compare/count with an explicit `if [ ... ]; then echo FAIL...; exit 1; fi`, printing the observed value — the mandatory pattern for any future task test:chart extension per D-25 and this plan's proof that grep -q went stale in Phase 7."

requirements-completed: [SVC-01, SVC-02]

coverage:
  - id: D1
    description: "serviceController.enabled exists in values.yaml, defaults to false, and the bare service: key remains unclaimed (D-23)"
    requirement: "SVC-01"
    verification:
      - kind: other
        ref: "grep -c '^serviceController:' values.yaml = 1; grep -c '^service:' values.yaml = 0"
        status: pass
    human_judgment: false
  - id: D2
    description: "helm template with default values renders zero --enable-service args; with serviceController.enabled=true it renders exactly one, and --enable-gateway is unaffected in both directions"
    requirement: "SVC-01"
    verification:
      - kind: other
        ref: "helm template charts/router-hosts-operator | grep -c -- '--enable-service' = 0; --set serviceController.enabled=true | grep -c -- '--enable-service' = 1; cross-checked --enable-gateway independence"
        status: pass
    human_judgment: false
  - id: D3
    description: "task test:chart's six new assertions compare rendered content (never grep -q exit status alone) and each is proven to actually fail when the chart is wrong"
    requirement: "SVC-01, SVC-02"
    verification:
      - kind: other
        ref: "task test:chart green (Chart verification passed., zero genuine FAIL: emissions); negative control 1 (services verbs widened with delete) failed the task with FAIL: services verbs line is [...delete...]; negative control 2 (events rule deleted) failed with FAIL: events rule rendered 0 time(s); both reverted via git checkout -- and re-verified green"
        status: pass
    human_judgment: false
  - id: D4
    description: "No ClusterRole renders at all when rbac.create=false, even with serviceController.enabled=true"
    requirement: "SVC-01"
    verification:
      - kind: other
        ref: "helm template --set serviceController.enabled=true --set rbac.create=false | grep -c 'kind: ClusterRole' = 0 (Taskfile.yml assertion)"
        status: pass
    human_judgment: false
  - id: D5
    description: "The chart README documents all four Service annotations, IP-resolution rules, that --default-ingress-ip is not a Service fallback, the serviceController/gateway.enabled asymmetry, and the cluster-wide informer cache footprint"
    requirement: "SVC-01, SVC-02"
    verification:
      - kind: other
        ref: "grep checks for serviceController.enabled (x2+), all four router-hosts.fzymgc.house/* annotation keys, all four event reasons, service-cleanup finalizer, k8s-service: provenance prefix, plus manual read confirming the no-default-fallback and key-asymmetry statements are present"
        status: pass
    human_judgment: true
    rationale: "Grep confirms substring presence; whether the prose actually reads clearly to a Service owner (the plan's own success bar — 'can act on it') was manually read and confirmed during authoring, not machine-verifiable."

# Metrics
duration: ~40min
completed: 2026-07-27
status: complete
---

# Phase 8 Plan 05: Chart Toggle, Chart Verification, and User Documentation Summary

**`serviceController.enabled` Helm toggle (deliberately asymmetric with `gateway.enabled` per D-23) templating `--enable-service`, six content-comparison `task test:chart` assertions proven to fail via two manual negative controls, and a full Service annotation contract in the chart README.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-07-27
- **Tasks:** 3 (chart toggle + template arg; task test:chart content assertions; README documentation)
- **Files modified:** 4

## Accomplishments

- Added `serviceController.enabled` (default `false`) to `values.yaml`, deliberately not named `service.enabled` (D-23) — the comment block states both the naming rationale and the D-04 cluster-wide informer cache footprint, and a values.yaml grep for the bare `service:` key returns 0.
- `templates/deployment.yaml` templates `--enable-service` under a `{{- if .Values.serviceController.enabled }}` block, independent of the existing `gateway.enabled` conditional; cross-verified neither toggle affects the other's flag.
- `task test:chart` gained six new assertions, all content-comparison style per D-25/08-VALIDATION.md's Command Discipline: opt-in default (0), opt-in on (exactly 1), exact `services` verbs string match, `events` rule count + independent `create`/`patch` verb checks, no `services/status` subresource grant, and zero `ClusterRole` under `rbac.create=false`.
- Both required negative controls were run manually and recorded (see below): widening the `services` verb list and deleting the `events` rule each independently made `task test:chart` fail with a `FAIL:` line naming the actual observed/missing content, then both were reverted and the task re-verified green.
- The chart README gained a `serviceController.enabled` values-table row, an extended tagging note covering `k8s-service:` provenance, two new RBAC Permissions bullets (Services, Events), and a full `### Sync Kubernetes Services` section: all four annotations, supported-type table, IP-resolution rules, the explicit no-`defaultIngressIP`-fallback statement, event reasons, cleanup finalizer, cache-footprint tradeoff, and out-of-scope items.
- `rumdl check` and lefthook's `lint-markdown`/`fmt-markdown` hooks both pass clean on the README.
- Zero `go.mod`/`go.sum` changes (no Go files touched by this plan).

## Task Commits

Each task was committed atomically:

1. **Task 1: Add the serviceController toggle and template the --enable-service arg** — `c49f2af` (feat)
2. **Task 2: Extend task test:chart with content-based Service assertions** — `0ea4825` (test)
3. **Task 3: Document the Service annotation contract, RBAC, and the two deliberate asymmetries** — `77b27e5` (docs)

**Plan metadata:** (this commit)

## Files Created/Modified

- `charts/router-hosts-operator/values.yaml` — added `serviceController.enabled: false` block, preceded by a comment covering what enabling it does, the D-23 naming rationale, and the D-04 cache-footprint memory characteristic.
- `charts/router-hosts-operator/templates/deployment.yaml` — added a `{{- if .Values.serviceController.enabled }}` block emitting `--enable-service`, adjacent to and independent of the existing gateway conditional.
- `Taskfile.yml` — extended `test:chart` with a new assertion block (six checks) after the existing Gateway API RBAC block, using captured-and-compared render output throughout, never a bare `grep -q`.
- `charts/router-hosts-operator/README.md` — Key Values table row + naming-asymmetry note, extended tagging note, two new RBAC Permissions bullets, and a new `### Sync Kubernetes Services` usage section.

## Decisions Made

- Followed D-23 exactly: `serviceController.enabled`, not `service.enabled`. The task 1 verify command explicitly asserts the bare `service:` key is absent from `values.yaml` (count 0), which is the guard against the single most likely "correction" an agent could make here.
- Ran both required negative controls manually rather than adding them as permanent `Taskfile.yml` assertions, per the plan's own phrasing ("Prove it by running... then reverting... Record both outcomes in the plan summary"). Both are recorded under Issues Encountered below with the exact observed `FAIL:` output.
- Demoted the new D-23 naming-asymmetry note from a `>` blockquote to a plain paragraph after `rumdl` flagged MD028 (blank line inside blockquote) — two adjacent blockquotes separated by only a blank line get parsed as one blockquote with an interior blank by rumdl's markdown parser. Converting to a plain paragraph preserves the exact same content and meaning without touching the pre-existing tagging blockquote.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed a blockquote-adjacency markdown lint failure introduced by my own edit**

- **Found during:** Task 3, after adding the D-23 naming-asymmetry note as a second blockquote immediately above the pre-existing tagging blockquote.
- **Issue:** `rumdl check` flagged `MD028: Blank line inside blockquote` — two `>`-prefixed blocks separated by a single blank line are parsed as one blockquote with an interior blank, not two distinct blockquotes.
- **Fix:** Converted the new note to a plain paragraph (no `>` prefix), leaving the pre-existing tagging blockquote untouched.
- **Files modified:** `charts/router-hosts-operator/README.md`
- **Verification:** `rumdl check charts/router-hosts-operator/README.md` returns `Success: No issues found`; lefthook's `lint-markdown`/`fmt-markdown` hooks both pass on commit.
- **Committed in:** `77b27e5` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1, self-inflicted markdown lint trip)
**Impact on plan:** No content or behavior change — markdown construct only.

## Issues Encountered

**Grep-based verify command false-positive risk (finding, not fixed — per project rule "fix the criterion, not the source").** The plan's task 2 `<verify>` command is `test "$(grep -c 'FAIL:' /tmp/chart-verify.log)" = "0"`. When run via `task test:chart` (not raw `bash`), `task` echoes the full shell script source it is about to execute — including the 14 literal `echo "FAIL: ..."` strings inside the script's own `if` blocks — before running it. This means `grep -c 'FAIL:'` on the captured log always returns 14, even on a completely clean pass with zero actual failures. Confirmed by running `grep -n 'FAIL:' /tmp/chart-verify.log | grep -v 'echo "FAIL:'`, which returned **zero** matches — i.e., no line matches the pattern a genuine runtime failure would produce (a bare `FAIL: ...` with no `echo "` prefix). The correct pass signal is: `task` exit code 0, the literal string `Chart verification passed.` present, and zero *non-echoed* `FAIL:` lines. This is a property of `task`'s default verbose command-echoing, not a defect in `Taskfile.yml` — no source change was made.

Both negative controls executed exactly as specified in the plan's acceptance criteria:

- **Negative control 1 (widened `services` verbs):** Temporarily appended `"delete"` to the `services` rule's verbs list in `charts/router-hosts-operator/templates/clusterrole.yaml`. `task test:chart` exited non-zero (`task: Failed to run task "test:chart": exit status 1`) with the observed line: `FAIL: services verbs line is [    verbs: ["get", "list", "watch", "update", "patch", "delete"]], want [    verbs: ["get", "list", "watch", "update", "patch"]]`. Reverted with `git checkout -- charts/router-hosts-operator/templates/clusterrole.yaml`; `task test:chart` confirmed green again (`Chart verification passed.`).
- **Negative control 2 (deleted `events` rule):** Temporarily removed the entire `events` RBAC rule block (comment + rule) from `clusterrole.yaml`. `task test:chart` exited non-zero with: `FAIL: events rule rendered 0 time(s), want exactly 1`. Reverted with `git checkout -- charts/router-hosts-operator/templates/clusterrole.yaml`; confirmed green again.

Every other `<verify>` and acceptance-criteria command from the plan was run exactly as written and produced the expected result:

- `helm lint charts/router-hosts-operator` exits 0 (both after task 1 and after task 3)
- `helm template` default: zero `--enable-service`; `--set serviceController.enabled=true`: exactly one; `--enable-gateway` unaffected in both directions; `--set gateway.enabled=true`: `--enable-gateway` still renders exactly once (existing toggle unbroken)
- `grep -c '^serviceController:' values.yaml` = 1; `grep -c '^service:' values.yaml` = 0
- `task test:chart` prints `Chart verification passed.` and exits 0, both before and after the README changes
- `Taskfile.yml` references `--enable-service` at least twice and contains the exact expected verbs string `verbs: ["get", "list", "watch", "update", "patch"]`
- README grep checks: `serviceController.enabled` (≥2), all four `router-hosts.fzymgc.house/*` annotation keys, all four event reason strings, `service-cleanup` finalizer, `k8s-service:` provenance prefix — all present
- `rumdl check charts/router-hosts-operator/README.md` clean after the one auto-fixed lint issue
- `git diff --exit-code -- go.mod go.sum` exits 0 (zero new dependencies; no Go files touched)

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All five plans in Phase 8 are now complete. The chart fully exposes the Service controller: RBAC (plan 02), the enablement toggle and its verified render behavior, standing chart verification coverage, and user-facing documentation (this plan).
- `serviceController.enabled` is the only new user-facing configuration surface this phase adds; a Service owner has everything needed (annotations, IP-resolution rules, event reasons) documented in one place without reading source.
- No blockers. Phase 8 is ready for `/gsd-verify-work 8`.

---

*Phase: 08-kubernetes-service-controller*
*Completed: 2026-07-27*

## Self-Check: PASSED

- FOUND: charts/router-hosts-operator/values.yaml
- FOUND: charts/router-hosts-operator/templates/deployment.yaml
- FOUND: Taskfile.yml
- FOUND: charts/router-hosts-operator/README.md
- FOUND: .planning/phases/08-kubernetes-service-controller/08-05-SUMMARY.md
- FOUND: commit c49f2af in git log
- FOUND: commit 0ea4825 in git log
- FOUND: commit 77b27e5 in git log
