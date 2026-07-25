# Feature PR

<!--
Use this template ONLY for new functionality.
Open it with: ?template=feature.md appended to the PR compare URL.

GATE: the linked issue MUST already carry the `approved-feature` label.
PRs without an approved feature issue are closed unmerged.
-->

Closes #

## Feature summary

<!-- What does this add, in two or three sentences? -->

## New files

| File | Purpose |
|------|---------|
|      |         |

## Modified files

| File | Change |
|------|--------|
|      |        |

## Implementation notes

<!--
Why this design? Call out anything a reviewer would otherwise have to
reverse-engineer: concurrency, error paths, event-sourcing implications,
proto field numbering, migration behavior.
-->

## Spec compliance

<!-- Copy each acceptance criterion from the linked issue and check it off. -->

- [ ]
- [ ]

## Test coverage

<!-- Which tests were added and what do they prove? -->

- [ ] Unit tests added
- [ ] Property-based tests added (`pgregory.net/rapid`) or explained as not applicable
- [ ] E2E coverage added (`task test:e2e`) or explained as not applicable
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

- [ ] Linked issue has the `approved-feature` label
- [ ] Conventional Commit type/scope set correctly so release-please classifies it
- [ ] `task lint` passes (golangci-lint + buf lint)
- [ ] `task fmt` applied (gofumpt + buf format)
- [ ] Errors wrapped with `samber/oops` and contextual messages
- [ ] Proto regenerated via `task proto:generate` if `proto/` changed
- [ ] Docs updated under `docs/` if user-facing
- [ ] No `//nolint` directives added without written justification
- [ ] Hooks were not bypassed (`--no-verify` not used)

## Breaking changes

<!--
State explicitly. Cover: CLI flags, config keys, proto field numbers, on-disk
state/snapshot format, generated output files. Write "None" with reasoning if
there are none.
-->
