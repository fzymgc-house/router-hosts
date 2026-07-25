# Fix PR

<!--
Use this template ONLY for bug fixes.
Open it with: ?template=fix.md appended to the PR compare URL.

GATE: the linked issue MUST already carry the `confirmed-bug` label, so that
maintainer and author agree on the root cause before the fix lands.
-->

Fixes #

## What was broken

<!-- The observable failure, as a user would experience it. -->

## Root cause

<!--
The actual defect, not the symptom. Name the file and the specific logic that
was wrong, and explain why it produced the observed behavior.
-->

## What the fix does

<!-- The change, and why it addresses the root cause rather than masking it. -->

## Verification

<!-- Exact commands run and output observed, before and after. -->

**Before the fix:**

```console

```

**After the fix:**

```console

```

## Regression test

<!--
Every bug fix requires a regression test that fails before the fix and passes
after. If one is genuinely impossible, explain why here.
-->

- [ ] Regression test added, and confirmed failing before the fix
- [ ] Test store uses `t.TempDir()` / a `t.Name()`-scoped DSN (no shared state)
- [ ] `task test` passes with the race detector
- [ ] `task test:coverage:ci` passes (total coverage >= 80%)

## Platforms tested

- [ ] Linux (x86_64)
- [ ] Linux (arm64)
- [ ] macOS (Apple Silicon)

## Deployment targets tested

- [ ] Local binary (`task build`)
- [ ] Container image (`task docker:build`)
- [ ] Kubernetes operator
- [ ] Not applicable

## Checklist

- [ ] Linked issue has the `confirmed-bug` label
- [ ] Commit uses the `fix:` Conventional Commit type so release-please picks it up
- [ ] `task lint` passes (golangci-lint + buf lint)
- [ ] `task fmt` applied (gofumpt + buf format)
- [ ] Errors wrapped with `samber/oops` and contextual messages
- [ ] Fix is minimal — no opportunistic refactoring bundled in
- [ ] No `//nolint` directives added without written justification
- [ ] Hooks were not bypassed (`--no-verify` not used)

## Breaking changes

<!--
Fixes can still break consumers who depended on the buggy behavior. State
explicitly, or write "None" with reasoning.
-->
