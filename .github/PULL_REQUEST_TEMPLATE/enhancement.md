# Enhancement PR

<!--
Use this template ONLY for improvements to existing behavior.
Open it with: ?template=enhancement.md appended to the PR compare URL.

GATE: the linked issue MUST already carry the `approved-enhancement` label.
-->

Closes #

## What this enhancement improves

<!-- Name the specific existing behavior being improved. -->

## Before / after

**Before:**

```console

```

**After:**

```console

```

## Implementation approach

<!-- How was it done, and why this way over the alternatives in the issue? -->

## Verification

<!-- How did you prove the improvement is real? Commands run, output observed. -->

- [ ] Unit tests updated or added
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

## Scope confirmation

- [ ] This PR implements only the linked issue — no drive-by changes
- [ ] No unrelated formatting or reordering appears in the diff

## Checklist

- [ ] Linked issue has the `approved-enhancement` label
- [ ] Conventional Commit type/scope set correctly so release-please classifies it
- [ ] `task lint` passes (golangci-lint + buf lint)
- [ ] `task fmt` applied (gofumpt + buf format)
- [ ] Docs updated under `docs/` if user-facing
- [ ] No `//nolint` directives added without written justification
- [ ] Hooks were not bypassed (`--no-verify` not used)

## Breaking changes

<!--
State explicitly. Machine-readable output (`--format json`/`csv`), config keys,
and proto contracts are the usual risks. Write "None" with reasoning if there
are none.
-->
