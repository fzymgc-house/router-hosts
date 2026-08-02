# Stack Research

**Domain:** CI wiring for existing e2e tiers + containerized DNS deployment-verification harness + cursor-paginated event-sourced storage reads (Go 1.26, no CGo, existing shipped app)
**Researched:** 2026-08-02
**Confidence:** HIGH (versions verified against pkg.go.dev/GitHub releases/Alpine package index Aug 2026; CI-runner behavior verified against Namespace docs)

This is a **subsequent-milestone** stack addendum, not a greenfield recommendation. It covers only the three new capabilities in v0.14.0. Everything already in `go.mod` (Go 1.26.5, `zombiezen.com/go/sqlite`, `samber/oops`, Cobra, Bubble Tea, OTel, controller-runtime, lego, `google.golang.org/grpc`) is **out of scope** — do not re-evaluate or propose replacing it.

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `github.com/testcontainers/testcontainers-go` (compose module: `.../modules/compose`) | v0.43.0 (Jun 19 2026) | Programmatic lifecycle for the 3-container DNS-verification harness (unbound resolver + 2 sinks) | The harness needs a private Docker network where 3 containers resolve each other by service name, deterministic readiness waits (unbound listening on 53/tcp+udp, sink processes up), and guaranteed cleanup even when a test panics mid-run. The existing `docker_e2e_test.go` hand-rolls this today with `exec.Command("docker", "run"/"inspect"/"logs"/"rm")` for a *single* container — that pattern does not scale cleanly to 3 containers + a shared network + per-service wait strategies. The `compose` module wraps the `docker compose` CLI (not the full testcontainers container-request API), so the harness topology is declared once as `compose.yaml` and driven from Go via `compose.NewDockerComposeWith` / `Up(ctx, compose.Wait(true))` / `Down(ctx, compose.RemoveOrphans(true))`. Ryuk (its reaper sidecar) removes orphaned containers automatically on interrupted CI runs. |
| Alpine + `unbound` package (own Dockerfile under `e2e/testdata/`) | `alpine:3.22` base, `unbound` **1.23.1-r1** (or `alpine:edge`, `unbound` 1.25.2-r0 for newer feature parity) | Real unbound resolver container for the resolver-reload and two-node-convergence checks | `mvance/unbound` (the most-searched pre-built unbound image) has not been updated in over a year — an unpinned supply-chain dependency for a test-only image is unjustified risk when Alpine ships current, well-audited `unbound` packages directly. Build a small `FROM alpine:3.22` image (`apk add --no-cache unbound`) so the exact unbound version is pinned in the Dockerfile and rebuilt from the current Alpine package index, matching how the production `Dockerfile` already pins `golang:1.26-alpine` by digest. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/testcontainers/testcontainers-go/network` | (submodule of v0.43.0, same go.mod) | Explicit custom Docker network + per-container aliases, if the compose module's auto-network isn't granular enough | Only needed if the harness moves off `compose` to raw container requests (see "Alternatives Considered" — not the primary recommendation). Compose YAML's own `networks:` block already gives service-name DNS between the 3 containers without this package. |
| (none — no new pagination library) | n/a | Cursor-based `HostProjection` reads | See "Cursor pagination: no new dependency" below — this is a SQL query change against the already-vendored `zombiezen.com/go/sqlite`, not a new package. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `docker compose` CLI plugin (v2, bundled with Docker Engine ≥ 20.10) | Backing runtime the `compose` module shells out to | **Verify presence on the `namespace-profile-linux-amd64-*` runners before adopting** — the compose Go module does not vendor a compose implementation, it drives the host's `docker compose` binary. Add a `docker compose version` sanity step to the new CI job as a fast-fail guard; if absent, install via the Docker APT repo's `docker-compose-plugin` package in a setup step. |
| `TESTCONTAINERS_RYUK_DISABLED` env var | Escape hatch, not a default | Namespace runners have a working Docker daemon by default (no privileged flag needed for ordinary `docker run`/`docker compose`), so Ryuk's reaper container should run normally. Only reach for this if Ryuk itself can't reach the Namespace Docker socket — treat as a documented fallback, not a day-1 setting. |
| `govulncheck` (already in CI as `vuln` job) | Covers new deps | `testcontainers-go` and its transitive `docker/docker` client pull in real Docker API bindings — the existing `vuln` job in `ci-go.yml` will scan them for free once added to `go.mod`; no new tool needed. |

## Installation

```bash
# Core — testcontainers-go compose module
go get github.com/testcontainers/testcontainers-go@v0.43.0
go get github.com/testcontainers/testcontainers-go/modules/compose@v0.43.0

# No new packages for cursor pagination — internal/storage/sqlite/projection.go
# gets a new query + interface method, using the already-vendored
# zombiezen.com/go/sqlite / sqlitex.
```

Both new modules must land behind the **same build-tag discipline the codebase already uses** (`e2e`, `docker_e2e`, `proc_e2e`) so they never compile into the shipped `router-hosts`/`operator` binaries or affect `CGO_ENABLED=0` static builds — `testcontainers-go` itself has no CGo dependency, but it is a test-only tool and must stay quarantined behind a build tag (a new one, e.g. `harness_e2e`, or folded into `docker_e2e` — see Roadmap Implications below) the same way `docker_e2e`/`proc_e2e` already are, so `go build ./...` and `task build` never need Docker to succeed.

## Question 1 — Wiring the three e2e tiers into CI

No new library. This is Taskfile/workflow wiring using tasks that already exist (`task test:e2e`, `task test:e2e:docker`, `task test:e2e:proc`).

**Concrete integration points:**

- Add three new jobs to `.github/workflows/ci-go.yml`, mirroring the existing `test` job's checkout/setup-go/cache/install-task steps, each running one of:
  - `task test:e2e` (in-process — no Docker, cheapest, put on the smallest runner profile e.g. `namespace-profile-linux-amd64-2x4`)
  - `task test:e2e:docker` (already `deps: ['docker:build']` in the Taskfile — Namespace runners have Docker by default so this needs no extra runner config, just enough disk/CPU for the image build; keep on `namespace-profile-linux-amd64-4x8`, matching the existing `test` job's profile)
  - `task test:e2e:proc` (already `deps: ['build']` — no Docker needed, but needs real listening ports; keep it off any runner profile that might sandbox raw process/socket use — Namespace's `namespace-profile-linux-amd64-4x8` is already used for `test` and is proven safe for that)
- Add `docker compose version` as the first step of whichever job ends up running the new harness (see Question 2), so a missing compose plugin fails fast with a clear message instead of a confusing testcontainers timeout.
- Add all three new job names to the `ci-go-complete` gate's `needs:` list and its `if` result check, exactly like `lint`/`vuln`/`test`/`build`/`buf-check`/`manifests`/`docs` are wired today — **do not** invent a different aggregation pattern.
- `docker_e2e` and `proc_e2e` both build the binary/image first — mirror the Taskfile's own `deps:` (`docker:build`, `build`) as explicit steps or accept the Taskfile deps running inline; either is fine since `task` already encodes the dependency, but the CI job needs Docker layer caching considered (see Pitfalls) since `test:e2e:docker` does a fresh `docker build` every run today with no BuildKit cache mount configured.

## Question 2 — Containerized deployment-verification harness

### Evaluation: testcontainers-go vs docker compose (CLI) vs raw Docker SDK

| Criterion | testcontainers-go (compose module) | raw `docker compose` CLI via `exec.Command` | raw Docker SDK (`github.com/docker/docker/client`) |
|---|---|---|---|
| Fits the 3-container + shared-network topology (resolver + 2 sinks) | Best — compose YAML declares the network and service DNS aliases once; Go API only drives lifecycle | Workable — same YAML, but you hand-roll `exec.Command("docker","compose",...)`, parse its text output, and hand-roll readiness polling | Worst — you'd hand-build 3 container specs, a network, and readiness logic in raw Go against the Docker Engine API; most code for least benefit |
| Consistent with existing pattern in `docker_e2e_test.go` | Diverges from today's raw single-container `exec.Command("docker", ...)` pattern, but that pattern was never designed for N containers + a network | Same underlying CLI as today, no new dependency, but doesn't remove the boilerplate that already makes `docker_e2e_test.go` the largest/most manual e2e file | Diverges most; introduces a Docker API version-compatibility surface the codebase doesn't otherwise track |
| Cleanup guarantees on test failure/panic | Ryuk reaper cleans orphaned containers automatically | Manual `defer exec.Command("docker","rm","-f",...)` — already the pattern in `docker_e2e_test.go`, already a known maintenance burden | Manual, same burden as CLI approach, more code |
| GitHub Actions / Namespace runner fit | Needs Docker daemon (confirmed present by default on `namespace-profile-linux-amd64-*`) + `docker compose` v2 plugin (verify, don't assume) | Needs Docker + compose plugin, nothing else | Needs Docker daemon only; no compose plugin dependency |
| New `go.mod` dependency surface | Adds `testcontainers-go` + transitive `docker/docker` client, `docker/go-connections`, etc. — real but well-audited, MIT-licensed, CNCF-adjacent | Zero new Go dependencies | Adds `docker/docker` client directly (smaller footprint than testcontainers, but you write the orchestration testcontainers already wrote) |
| Effort to build resolver-reload + two-node-convergence checks | Low — `WaitForService("unbound", wait.ForListeningPort("53/udp"))`-style readiness, then exec `unbound-control` inside the container via `container.Exec(ctx, []string{...})` | Medium — same shape, hand-written polling instead of a wait-strategy library | High — most plumbing to write and maintain |

**Recommendation: `testcontainers-go`'s **compose module**, not its low-level container-request API.** Use a `compose.yaml` under `e2e/testdata/harness/` declaring 3 services (`resolver` = the Alpine+unbound image above, `sink-a`, `sink-b` = the existing `router-hosts watch` sink binary in a minimal image) on one bridge network, driven from a new `harness_e2e`-tagged (or folded into `docker_e2e`) Go test file using `compose.NewDockerComposeWith(compose.WithStackFiles(...))` → `Up(ctx, compose.Wait(true))` → assertions (query `resolver` over DNS from the test process, or `Exec` into it to run `unbound-control status`) → `defer stack.Down(...)`.

**Do NOT add:**
- **The raw Docker SDK (`docker/docker/client`) directly** — testcontainers-go already wraps it correctly (retry/backoff, API-version negotiation, Ryuk); hand-rolling the same thing is pure risk for zero benefit given testcontainers is already the de facto Go standard for this.
- **`testcontainers-go`'s generic `GenericContainer`/`network.New` API as the primary mechanism** — reserve it only as a fallback if the compose module's declarative YAML proves too rigid for a specific wait condition; starting there means re-deriving what compose already gives for free.
- **`dockertest` (`ory/dockertest`)** — an older, less-maintained alternative to testcontainers-go with a smaller feature set (no first-class compose/network module, no Ryuk); no reason to pick it over testcontainers-go for a new harness in 2026.
- **A second physical/VM-based CI runner "to be safe"** — the entire point of this milestone item is retiring that dependency; do not reintroduce it as a CI concern.

### Docker-in-CI concerns specific to `docker_e2e` and the new harness tier

- Namespace's `namespace-profile-linux-amd64-*` runners have Docker available by default, matching GitHub-hosted `ubuntu-latest` behavior — no `privileged: true` / `container.privileged=true` runner-label change needed for ordinary `docker run`/`docker compose` or for Ryuk reaching the socket.
- `docker compose` v2 (the plugin, not the legacy Python `docker-compose` v1 binary) must be present — add the version-check guard mentioned above rather than assuming.
- The existing `test:e2e:docker` task does a full `docker build` on every run with no layer-cache reuse across CI runs; the new harness compose build will add 3 more image builds (resolver + 2 sinks) on top. Use `namespacelabs/nscloud-cache-action` (already used for Go module caching in `ci-go.yml`) with its Docker-layer-cache mode, or accept slower harness jobs and keep them out of the required-checks fast path if build time becomes a problem — a phasing/roadmap concern, not a library choice.

## Question 3 — Cursor-based pagination for `storage.HostProjection`

**No new dependency.** This is a SQL-query and interface change against the already-vendored `zombiezen.com/go/sqlite`. Do not add a pagination helper library (there is no idiomatic one for this pure-Go SQLite binding, and adding an ORM/query-builder to work around it would be a much bigger, unjustified stack change).

**What changes and why it fits the existing shape:**

- Today, `ListAll` (`internal/storage/sqlite/projection.go:19`) calls `getDistinctAggregateIDs` (unbounded `SELECT DISTINCT aggregate_id FROM events`), then for **every** aggregate ID calls `loadEventsForAggregate` (full per-aggregate event replay) before returning a single `[]domain.HostEntry`. `ExportHosts`/`WatchHosts` both currently sit downstream of this — they get a fully-materialized slice before the first gRPC chunk goes out.
- Aggregate IDs in this codebase are ULIDs (`github.com/oklog/ulid/v2`, already a direct dependency) — lexicographically sortable and monotonic by creation time. That property is exactly what keyset/cursor pagination over `aggregate_id` needs: `SELECT DISTINCT aggregate_id FROM events WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?` gives a stable, resumable cursor with no `OFFSET` (which would still be O(n) and unstable under concurrent writes to the single-writer `WriteQueue`).
- The new interface surface (naming is a roadmap/requirements decision, not this document's call) is additive to `HostProjection` — e.g. a `ListPage(ctx, cursor *ulid.ULID, limit int) (entries []domain.HostEntry, nextCursor *ulid.ULID, err error)` — so `ListAll`, `GetAtTime`, `Search`, `FindByIPAndHostname` can either stay as-is (they have no streaming caller today) or be reimplemented in terms of the new paged primitive; that call is for planning, not this stack document.
- `ExportHosts`/`WatchHosts` (`internal/server/service.go:680`, `internal/server/watch_test.go`) then loop pages and stream chunks as they're produced, instead of calling `ListAll` once up front — bounding server-side memory to one page's worth of aggregates' event logs at a time, matching the wire-side bounded-chunk contract TMPL-06 already established for the client.

**What NOT to add:**
- **No ORM** (`gorm`, `sqlc`, `ent`) — the codebase hand-writes SQL via `sqlitex.Execute` throughout `internal/storage/sqlite`; introducing a query builder for one new method breaks that consistency for no benefit.
- **No generic pagination package** (e.g. `github.com/vaughan0/go-pagination`-style helpers) — cursor pagination here is two WHERE/LIMIT clauses over an already-sortable ULID column; a dependency would add more surface than the code it replaces.
- **No CGo SQLite driver or FTS/extension** to "make search faster" as a side-effect of this work — `zombiezen.com/go/sqlite` (modernc pure-Go backend) is locked (`.planning/PROJECT.md` Constraints: "SQLite only ... no CGo toolchain"); any pagination approach that would push toward `mattn/go-sqlite3` or a CGo-linked full-text extension is disqualified outright, regardless of performance claims.

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|--------------------------|
| `testcontainers-go` compose module for the 3-container harness | Hand-rolled `exec.Command("docker","compose",...)` (extending today's `docker_e2e_test.go` pattern) | If the team wants zero new `go.mod` dependencies at any cost and is willing to hand-write readiness polling/cleanup for 3 containers — acceptable, but it's strictly more code to maintain for the same outcome. |
| Alpine + `apk add unbound` custom test image | `mvance/unbound` prebuilt image | Only if a maintained fork/replacement image appears with active updates; as of this research the image is >1 year stale, an avoidable supply-chain risk for a test-only container. |
| Cursor pagination via `aggregate_id > ?` keyset query (no library) | A per-aggregate snapshot table (mentioned in ADR `router-hosts-vl8` as future work) | Only if compaction/snapshot work (currently explicitly out of scope, `router-hosts-vl8` LOCKED) is revisited — that's a storage-architecture change, not a pagination-API change, and shouldn't be conflated with this milestone's scope. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|--------------|
| `ory/dockertest` | Older, smaller-scope Docker test helper; no compose/network module, no Ryuk reaper, materially behind `testcontainers-go`'s current feature set | `testcontainers-go` v0.43.0 |
| `mvance/unbound` Docker image | Unmaintained for 1+ year; unpinned supply-chain risk for a container that needs to prove a real resolver-reload behavior | Own `alpine:3.22` + `apk add unbound` (1.23.1-r1) Dockerfile, version-pinned and rebuildable |
| `mattn/go-sqlite3` or any CGo SQLite driver, for pagination or any other reason | Violates the LOCKED "SQLite only, no CGo toolchain" constraint (`.planning/PROJECT.md` Constraints) — breaks `CGO_ENABLED=0` static builds | `zombiezen.com/go/sqlite` (already the dependency; pagination is a query change, not a driver change) |
| `OFFSET`-based pagination (`LIMIT ? OFFSET ?`) for the new storage method | O(n) per page as offset grows, and unstable under concurrent writes even though writes are serialized through the single `WriteQueue` — a page boundary can still shift between calls as new aggregates are created between two `ListPage` calls | Keyset/cursor pagination on `aggregate_id` (ULID, already sortable) |
| A second physical machine, or a VM-based GitHub Actions runner, for the resolver-reload/two-node-convergence checks | Exactly the dependency this milestone item exists to retire (`.planning/PROJECT.md` Active: "so they stop needing a second physical machine") | The 3-container Docker harness described above, running on the same Namespace-hosted runners the rest of CI already uses |
| A general-purpose ORM or query builder for the new pagination method | No other code in `internal/storage/sqlite` uses one; would fragment the codebase's SQL style for a two-clause WHERE/LIMIT change | Hand-written `sqlitex.Execute` query, matching the existing `getDistinctAggregateIDs`/`loadEventsForAggregate` style in `projection.go` |

## Stack Patterns by Variant

**If the compose plugin turns out to be missing on Namespace runners:**
- Add an explicit `docker compose` plugin install step (APT `docker-compose-plugin` package) before the harness job, rather than falling back to the legacy `docker-compose` (v1, Python, EOL) binary.

**If harness image build time becomes a bottleneck in required CI checks:**
- Split the harness job out of the required `ci-go-complete` gate initially (nightly/manual trigger) while the other two e2e tiers (`e2e`, `docker_e2e` as it exists today) go into the required gate first — a phasing decision for the roadmap, not a stack change.

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|------------------|-------|
| `github.com/testcontainers/testcontainers-go` v0.43.0 | Go 1.26.5 (project's pinned version) | testcontainers-go tracks the two latest stable Go releases per its own support policy; Go 1.26 is well within that window as of Aug 2026. |
| `github.com/testcontainers/testcontainers-go/modules/compose` v0.43.0 | Docker Engine ≥ 20.10 with the `docker compose` v2 CLI plugin | Module shells out to the host `docker compose` binary; it does not vendor a compose implementation. |
| Alpine `unbound` 1.23.1-r1 (3.22) / 1.25.2-r0 (edge) | Any Docker-capable CI runner (this is a test-image concern, not a `go.mod` concern) | Pin the Alpine base tag by digest in the harness Dockerfile, matching how the shipped `Dockerfile` already pins `golang:1.26-alpine` by digest. |
| `zombiezen.com/go/sqlite` v1.4.2 (existing, unchanged) | `modernc.org/sqlite` v1.52.0 (existing indirect dep, pure-Go backend) | No version bump needed for cursor pagination — it's a new query against the existing schema/driver. |

## Sources

- Context7 `/testcontainers/testcontainers-go` — compose module `ComposeStack` interface, `NewDockerComposeWith`, `Up`/`Down` lifecycle, Ryuk `RyukDisabled` config, `network.WithNetwork` for custom-network attachment.
- https://pkg.go.dev/github.com/testcontainers/testcontainers-go?tab=versions — confirmed v0.43.0 is current (Jun 19 2026), version history back to v0.38.0.
- https://github.com/testcontainers/testcontainers-go/releases — v0.43.0 release notes (`PullImageWithOpts`, `ResolveSaveImageOptions`).
- https://golang.testcontainers.org/system_requirements/ — Go-version support policy (tracks two latest major Go releases).
- https://hub.docker.com/r/mvance/unbound — confirmed image last updated 1+ year ago (staleness basis for rejecting it).
- https://pkgs.alpinelinux.org/package/edge/main/x86_64/unbound and /v3.22/main/x86_64/unbound — current `unbound` package versions (1.25.2-r0 edge, 1.23.1-r1 v3.22).
- https://namespace.so/docs/reference/github-actions/runner-configuration and /docker-builds — confirmed Docker daemon available by default on `namespace-profile-linux-amd64-*` runners without a privileged flag; `container.privileged=true` only needed for kernel/namespace-level access, not ordinary `docker run`/`docker compose`.
- Repo inspection (`go.mod`, `Taskfile.yml`, `.github/workflows/ci-go.yml`, `internal/storage/storage.go`, `internal/storage/sqlite/projection.go`, `e2e/docker_e2e_test.go`, `.planning/PROJECT.md`) — confirmed current stack, existing e2e tier build tags, existing raw-`exec.Command`-Docker pattern, `HostProjection` interface shape, and the LOCKED no-CGo SQLite constraint.

---
*Stack research for: router-hosts v0.14.0 — Verification & Lazy Reads*
*Researched: 2026-08-02*
