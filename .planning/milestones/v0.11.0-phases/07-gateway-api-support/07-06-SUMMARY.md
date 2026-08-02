---
phase: 07-gateway-api-support
plan: 06
subsystem: infra
tags: [helm, rbac, kubernetes, gateway-api, chart, documentation]

# Dependency graph
requires:
  - phase: 07-gateway-api-support (plan 01)
    provides: "--enable-gateway flag on cmd/operator, SetupGatewayControllers gate"
provides:
  - "ClusterRole rules granting the operator get/list/watch/update/patch on httproutes, grpcroutes, tlsroutes and read-only get/list/watch on gateways"
  - "gateway.enabled chart value (default false) that renders --enable-gateway"
  - "Chart README documentation of the Gateway API CRD cluster prerequisite, the new value, RBAC, usage, and troubleshooting"
affects: [gateway-api-support, operator-deployment]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Hand-maintained ClusterRole rule blocks matching existing Traefik/HostMapping style", "Boolean-gated deployment arg via {{- if }} matching the {{- with }} precedent for --default-ingress-ip"]

key-files:
  created: []
  modified:
    - charts/router-hosts-operator/templates/clusterrole.yaml
    - charts/router-hosts-operator/templates/deployment.yaml
    - charts/router-hosts-operator/values.yaml
    - charts/router-hosts-operator/README.md
    - lefthook.yaml
    - .yamlfmt.yaml

key-decisions:
  - "Write verbs (update, patch) granted only on the three route kinds (finalizer + annotation write-back); gateways stays read-only (get, list, watch) since the operator never writes Gateway status"
  - "No create/delete verbs and no */status subresource rules added — out of scope for this phase per plan"
  - "Fixed a pre-existing lefthook.yaml bug where check-yaml's exclude field used a regex pattern (charts/.*templates/.*) instead of a glob, so it never actually excluded Helm template files from yamlfmt -lint"
  - "Added .yamlfmt.yaml with retain_line_breaks: true — yamlfmt's default formatter was stripping every blank line in values.yaml, which is not this repo's established style"

patterns-established: []

requirements-completed: [GW-03]

coverage:
  - id: D1
    description: "ClusterRole grants get/list/watch/update/patch on httproutes, grpcroutes, tlsroutes and get/list/watch on gateways, nothing more, inside the existing rbac.create guard"
    requirement: "GW-03"
    verification:
      - kind: other
        ref: "helm lint charts/router-hosts-operator && helm template rh charts/router-hosts-operator | rg 'gateway.networking.k8s.io' && helm template rh charts/router-hosts-operator --set rbac.create=false | rg -qv 'gateway.networking.k8s.io'"
        status: pass
    human_judgment: false
  - id: D2
    description: "gateway.enabled defaults to false and gates the --enable-gateway deployment arg"
    requirement: "GW-03"
    verification:
      - kind: other
        ref: "helm template rh charts/router-hosts-operator --set gateway.enabled=true | rg -q -- '--enable-gateway'; helm template rh charts/router-hosts-operator | rg -qv -- '--enable-gateway'"
        status: pass
    human_judgment: false
  - id: D3
    description: "README documents the Gateway API CRD cluster prerequisite, gateway.enabled value, RBAC, entry provenance, IP-resolution rule, and troubleshooting paths"
    requirement: "GW-03"
    verification:
      - kind: other
        ref: "rumdl check charts/router-hosts-operator/README.md"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-26
status: complete
---

# Phase 7 Plan 06: Helm Chart, RBAC, and Documentation Summary

**Opt-in Gateway API support in the Helm chart: least-privilege ClusterRole rules for HTTPRoute/GRPCRoute/TLSRoute/Gateway, a `gateway.enabled` value gating `--enable-gateway`, and README coverage of the CRD prerequisite the chart doesn't bundle.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-26
- **Tasks:** 2
- **Files modified:** 6 (4 planned + 2 deviation fixes)

## Accomplishments

- ClusterRole now grants exactly the permissions the Gateway API controllers need: `get;list;watch;update;patch` on `httproutes`, `grpcroutes`, `tlsroutes` (write verbs for the shared cleanup finalizer and host-ids annotation), and read-only `get;list;watch` on `gateways` (status-only IP resolution) — all inside the existing `rbac.create` guard
- `charts/router-hosts-operator/values.yaml` ships `gateway.enabled: false`, and `deployment.yaml` renders `--enable-gateway` only when it's set
- Chart README updated: Gateway API CRD prerequisite (not bundled), `gateway.enabled` values-table row, RBAC section entries, a "Sync Gateway API Routes" usage section with an HTTPRoute example and IP-resolution/fallback/wildcard behavior, and a troubleshooting entry for the three no-entry causes
- Found and fixed a pre-existing `lefthook.yaml` bug (regex pattern used where a glob was required) that was silently making `yamlfmt -lint` run against Helm template files on every commit — and a missing `.yamlfmt.yaml` config that would have stripped `values.yaml`'s established blank-line formatting

## Task Commits

Each task was committed atomically:

1. **Fix: lefthook yaml exclude glob + yamlfmt config (blocking issue, Rule 3)** - `ddbd4f3` (fix)
2. **Task 1: Add Gateway API RBAC rules and the gateway.enabled chart value** - `f630e90` (feat)
3. **Task 2: Document the Gateway API prerequisite, value, RBAC, and entry provenance in the chart README** - `4b25573` (docs)

## Files Created/Modified

- `charts/router-hosts-operator/templates/clusterrole.yaml` - Two new rule blocks: route kinds (get/list/watch/update/patch) and gateways (get/list/watch)
- `charts/router-hosts-operator/templates/deployment.yaml` - `{{- if .Values.gateway.enabled }}` conditional `--enable-gateway` arg
- `charts/router-hosts-operator/values.yaml` - New `gateway: { enabled: false }` block; widened `defaultIngressIP` comment to mention Gateway API routes
- `charts/router-hosts-operator/README.md` - Prerequisites, values table, RBAC section, new usage section, troubleshooting entry
- `lefthook.yaml` - Fixed `check-yaml` exclude to use valid glob patterns instead of a regex string
- `.yamlfmt.yaml` - New repo-root config with `retain_line_breaks: true` to match the chart's existing formatting style

## Decisions Made

- Write verbs (`update`, `patch`) granted only on the three route kinds, matching the existing Traefik rule's rationale (finalizer + annotation write-back); `gateways` stays strictly read-only
- No `create`/`delete` and no `*/status` subresource rules — explicitly out of scope per the plan
- `routerHosts.defaultIngressIP` reused as-is for the Gateway fallback IP (D-07); no new value added

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed lefthook `check-yaml` exclude regex-vs-glob mismatch**

- **Found during:** Task 1, first commit attempt
- **Issue:** `lefthook.yaml`'s `check-yaml` command excludes files via `exclude: "charts/.*templates/.*|mkdocs\\.yml"`. Lefthook's `exclude` field is glob-only (confirmed via Context7 docs against `evilmartians/lefthook`), so this regex string never matched anything — `yamlfmt -lint` ran against `clusterrole.yaml`/`deployment.yaml`, which fail immediately because Go template syntax (`{{ }}`) isn't valid YAML. This silently blocked any local commit touching chart templates; prior template-touching commits in git history must have bypassed local hooks (e.g. merged via GitHub UI).
- **Fix:** Replaced the regex string with a proper doublestar glob list: `["charts/**/templates/**", "mkdocs.yml"]`.
- **Files modified:** `lefthook.yaml`
- **Verification:** Re-ran `lefthook run pre-commit` — `check-yaml` no longer flags the two template files.
- **Committed in:** `ddbd4f3`

**2. [Rule 3 - Blocking] Added missing `.yamlfmt.yaml` config to preserve values.yaml formatting**

- **Found during:** Task 1, same commit attempt (after fixing the exclude glob, `check-yaml` still failed on `values.yaml`)
- **Issue:** No `.yamlfmt` config file existed in the repo. yamlfmt's default `basic` formatter strips blank lines between top-level keys unless `retain_line_breaks: true` is set — this would have rewritten every blank-line separator in `values.yaml` (a chart config file with an established blank-line-per-section style), a global reformat far outside this task's scope, purely to satisfy a lint gate that was apparently never actually enforced locally before.
- **Fix:** Added repo-root `.yamlfmt.yaml` with `formatter: { type: basic, retain_line_breaks: true, trim_trailing_whitespace: true }`. Also ran `yamlfmt -w` once on `values.yaml`, which fixed one small pre-existing indentation quirk (a comment block under `resources: {}` was indented as if nested, but empty flow mappings de-indent trailing comments to column 0 under this formatter) — a semantically-inert, comment-only change.
- **Files modified:** `.yamlfmt.yaml` (new), `charts/router-hosts-operator/values.yaml` (comment reindent only, verified via `diff` to be the sole change beyond the plan's intended edits)
- **Verification:** `yamlfmt -lint charts/router-hosts-operator/values.yaml` exits 0; `helm lint`/`helm template` verification still passes identically.
- **Committed in:** `ddbd4f3` (config), `f630e90` (the values.yaml reindent, bundled with the plan's intended gateway.enabled addition)

---

**Total deviations:** 2 auto-fixed (both Rule 3 - blocking issues, both CI/tooling config gaps unrelated to Gateway API logic)
**Impact on plan:** Both fixes were prerequisites for committing this plan's own files through the repo's pre-commit hook; neither touches Gateway API behavior. No scope creep beyond what was required to unblock the commit.

## Issues Encountered

None beyond the two deviations above.

## User Setup Required

None - no external service configuration required. Operators who want Gateway API support enabled must separately install the Gateway API CRDs (a cluster prerequisite, now documented) and set `gateway.enabled: true`.

## Next Phase Readiness

- The deployment surface for GW-03 is complete: RBAC, the opt-in value, and documentation all ship together
- No blockers for remaining phase 7 plans; this plan touched only chart/doc files and ran independently of the Go controller work in wave 1

---

*Phase: 07-gateway-api-support*
*Completed: 2026-07-26*

## Self-Check: PASSED

All created/modified files confirmed present on disk; all task commit hashes confirmed in git log.
