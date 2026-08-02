# Pitfalls Research

**Domain:** Adding CI-gated e2e tiers, a containerized deployment-verification harness, and cursor-based streaming reads to an existing event-sourced, mTLS Go control plane (router-hosts, v0.13.0 → v0.14.0)
**Researched:** 2026-08-02
**Confidence:** HIGH — grounded directly in this codebase's source (`internal/storage/sqlite/eventstore.go`, `internal/storage/sqlite/projection.go`, `internal/server/service.go`, `internal/server/watch.go`, `e2e/*_test.go`, `.github/workflows/ci-go.yml`, `docs/contributing/testing.md`, `docs/guides/operations.md`) and the project's own documented history (`.planning/PROJECT.md`) rather than generic domain knowledge.

## Critical Pitfalls

### Pitfall 1: Docker-tier CI wiring inherits a built-in soft-skip that reports green while running nothing

**What goes wrong:**
`e2e/docker_e2e_test.go` skips (not fails) when Docker is unavailable: `t.Skip("docker not found, skipping Docker E2E test")` and `t.Skip("docker daemon not running, skipping Docker E2E test")` (lines 139–144). If the `docker_e2e` tier is wired into a CI job whose runner lacks Docker, or where the Docker daemon isn't started before the test step, the job reports **PASS** via a skip — the tier never ran a single assertion, and CI is exactly as blind as before wiring it in.

**Why it happens:** The skip logic was written to keep local `task test:e2e:docker` runs from failing hard on a laptop without Docker running. That reasonable local-dev accommodation becomes a silent CI-gate hole the moment the tier is treated as "wired into CI = enforced" without separately verifying the runner actually has Docker.

**How to avoid:** In the CI job, verify Docker availability as an explicit, failing pre-step (`docker info || exit 1`) BEFORE running `task test:e2e:docker`, so an unavailable daemon fails the job loudly rather than letting the test's own skip absorb it. Additionally, grep the test log for `--- SKIP` and fail the job if any test in the docker_e2e binary skipped — a job that "passed" with zero non-skipped tests is not evidence of anything.

**Warning signs:** CI job is green but its log contains `--- SKIP:` lines; the docker_e2e job never once needed the runner to actually pull/build an image; wiring PR doesn't reference a specific runner image/label known to have Docker preinstalled.

**Phase to address:** CI Gating (e2e tiers into CI, closing #403).

---

### Pitfall 2: `proc_e2e` runs against a stale binary instead of the PR's actual code

**What goes wrong:** `task test:e2e:proc` requires `task build` to have run immediately before it (testing.md: "requires `task build` first"). `procBinaryPath(t)` (`e2e/proc_harness_test.go:47`) resolves `bin/router-hosts` on disk — it fails hard if that path is missing, but it has no way to know whether the binary there is FRESH. If the CI job restores a cached `bin/` directory (e.g., via `actions/cache`) or runs `proc_e2e` as a job parallel to (not dependent on, or after, a fresh) `build` step, the tier will happily execute against yesterday's binary and report green — a new mechanism for the exact class of blind spot that produced G-01-1 (a real defect shipping green because the seam under test was never actually exercised against current code).

**Why it happens:** `procBinaryPath`'s hard-fail-if-missing behavior (explicitly documented as protecting against a G-01-1-style silent skip) is easy to mistake for a freshness guarantee. It guards against "binary absent," not "binary stale."

**How to avoid:** The `proc_e2e` CI job MUST run `task build` (or `go build`) as its own step, immediately before `task test:e2e:proc`, in the SAME job/runner, with no `bin/` restored from cache. Assert freshness in the job log (echo the build timestamp or a checksum of `bin/router-hosts` right after building, before testing).

**Warning signs:** CI workflow has `test:e2e:proc` as a separate job from `build` connected only by artifact download, not a fresh in-job build; `bin/` appears in a cache-key path.

**Phase to address:** CI Gating (e2e tiers into CI).

---

### Pitfall 3: Treating in-process/`e2e` and `docker_e2e` as sufficient closure of #403, leaving the CLI-flag seam ungated

**What goes wrong:** Both the `e2e` and `docker_e2e` tiers drive the CLI client in-process (`commands.NewRootCmd(...).SetArgs(...)` inside the test binary) — testing.md states plainly that BOTH "do NOT prove anything about the CLI's flag parsing or config-file resolution." `proc_e2e` is the only tier that launches the shipped binary via `os/exec` on both sides. If CI wiring work ships `e2e` and `docker_e2e` as required checks first and treats #403 as "mostly done, proc_e2e later," the exact seam that let G-01-1 ship (`--config` silently falling back instead of failing loudly) remains unwatched by CI for however long that gap persists.

**Why it happens:** `e2e` and `docker_e2e` are easier to wire (no binary build step, no freshness concern) and produce a satisfying "3/3 tiers exist" checkbox before all three are actually required and green on every PR.

**How to avoid:** Treat #403 as closed only when `proc_e2e` is a required status check on branch protection for `main`, not merely "present in the workflow file." Write this as the literal acceptance criterion: "PR cannot merge to main without a passing `proc_e2e` job."

**Warning signs:** `proc_e2e` is wired as `continue-on-error: true`, non-required, or added in a follow-up PR after `e2e`/`docker_e2e` already gate merges.

**Phase to address:** CI Gating (e2e tiers into CI).

---

### Pitfall 4: A new CI gate that has never been observed to fail is not proven to be a gate

**What goes wrong:** A CI job added and immediately green — because the code it exercises is already correct — looks identical, from the outside, to a job that is structurally incapable of failing (wrong build tag, wrong working directory, assertions that can't trip, a fixture that always short-circuits). "Green" alone is not evidence the gate can catch the class of regression it exists to catch. This is the project's own stated lesson from G-01-1: 45 UAT items and a full e2e phase were green while the defect shipped.

**Why it happens:** It's natural to consider a CI-wiring task "done" once the workflow file is merged and shows a green checkmark. Proving negative capability (the job CAN fail) is extra work nobody schedules unless required.

**How to avoid — concrete anti-vacuity technique:** For each of the three tiers, before merging the CI-wiring PR, deliberately reintroduce a known regression on a scratch branch and observe the job go red:
- **`proc_e2e`:** revert (on a throwaway branch, never `main`) the fix for gap G-01-1, or stub the `--config` flag binding so it's silently ignored; push; confirm the `TestProcE2E_MissingExplicitConfigFailsLoudly` / `TestProcE2E_ColdStartWatchHonorsConfigFlag` job fails. Link the failing run in the wiring PR description.
- **`docker_e2e`:** temporarily break the Dockerfile's entrypoint or a documented flag; confirm the job fails, not skips.
- **`e2e`:** temporarily break a CRUD or auth assertion; confirm the job fails.

Write this into the acceptance criteria for the CI-wiring phase: *"PR description links to a CI run on a deliberately-broken branch showing each of the three required jobs fail; the branch and commit used to produce that failure are named."* A gate that has never been observed red is, by this project's own definition, not yet trustworthy.

**Warning signs:** CI-wiring PR contains no link to any red run; reviewers approve based solely on the new job being green.

**Phase to address:** CI Gating (e2e tiers into CI) — this is the phase's primary verification gate, not an optional nicety.

---

### Pitfall 5: Real-process and real-container tiers flake under shared CI runners and get quietly disabled within weeks

**What goes wrong:** `proc_e2e` launches real OS processes with real listening sockets; `docker_e2e` builds and runs a real container. Both introduce port-binding races and timing assumptions (`waitForFileContent`/`waitForSidecar` polling deadlines) tuned against a developer's mostly-idle laptop. On shared, noisy CI runners (`namespace-profile-linux-amd64-*` per `ci-go.yml`), the same test can intermittently fail from resource contention alone, not a real regression. Teams that inherit a flaky required check typically mark it `continue-on-error: true` or drop it from required checks within a month once it blocks a few otherwise-fine PRs — silently recreating the pre-#403 gap this whole phase exists to close.

**Why it happens:** Fixed sleeps, fixed ports, and deadlines calibrated for local dev don't survive contended, shared infrastructure; nobody budgets time to re-tune timing constants for CI specifically.

**How to avoid:** Use OS-assigned ephemeral ports (bind to `:0`, read back the assigned port) everywhere a fixed port would otherwise be used; size polling deadlines as an explicit multiple (e.g., 5×) of locally-measured `-race` timing rather than a guessed constant; give `proc_e2e`/`docker_e2e` their own dedicated CI job (not sharing a runner with parallel test binaries) so resource contention between unrelated jobs doesn't leak into timing-sensitive assertions. Treat any observed CI-only flake as a harness bug to fix, never as grounds to un-require the job.

**Warning signs:** A test occasionally fails only in CI, never locally; the fix proposed in review is "increase the timeout" for the third time; someone suggests `continue-on-error`.

**Phase to address:** CI Gating (e2e tiers into CI) — establish the no-fixed-timeout, no-fixed-port convention here since the deployment-verification harness (Pitfall 9) will reuse the same primitives.

---

### Pitfall 6: The harness asserts the config file changed, not that unbound actually reloaded it

**What goes wrong:** router-hosts writes `unbound_conf_path` atomically but explicitly does **not** reload unbound itself — reload is delegated to an external hook (a systemd `.path` unit plus `unbound-reload.service` running `unbound-control reload`, per `docs/guides/operations.md`). A deployment-verification harness that only diffs the conf file on disk after a mutation is asserting the wrong layer: it will pass even if the container's reload hook is missing, misconfigured, or broken, because the file write itself is untouched by that failure.

**Why it happens:** The file write is the part router-hosts directly controls and is easiest to assert on; the reload is an external, container-image-level concern that's easy to treat as "someone else's problem" when writing the test.

**How to avoid:** The convergence assertion must be a live DNS query (`dig`/`unbound-control lookup`) against the running unbound container returning the NEW record — never a file diff alone. The container image under test must run the actual documented reload mechanism (the systemd path-unit + `unbound-control reload` pattern from operations.md), not a test-only shortcut where the harness itself calls `unbound-control reload` directly — that would prove unbound CAN pick up new config, not that router-hosts' hook mechanism DOES trigger it in production.

**Warning signs:** The test's "converged" assertion is `assert file contains newIP`, with no `dig`/resolver query anywhere in the test; the container's reload hook is stubbed or called manually by the test setup instead of by the image's own hook wiring.

**Phase to address:** Deployment-Verification Harness.

---

### Pitfall 7: Negative caching and stale `local-data` masquerade as (or mask) convergence failures

**What goes wrong:** unbound negatively caches NXDOMAIN/SERVFAIL answers for names queried before they exist. If the harness pre-queries a hostname (e.g., as a readiness probe) before adding it, then adds it and queries again too quickly, unbound may still serve the cached negative answer for the negative-cache TTL — a **false failure** that has nothing to do with the feature under test. In the other direction, `static` local-zone directives are authoritative and bypass the general resolver cache for that exact name — so a stale IP served after an UPDATE (not a fresh add) is a genuine router-hosts regeneration bug (e.g., failing to remove/replace an old `local-data` line), and a harness that only checks "new value present" (rather than "old value ABSENT and new value present") can let that regression hide behind an apparent pass.

**Why it happens:** Caching and authoritative-zone semantics are easy to conflate; "just add a retry/sleep" is the default instinct for any resolver flakiness, and it papers over the real-bug case identically to the caching case.

**How to avoid:** Never pre-query a name before creating it (avoids seeding a negative-cache entry). For UPDATE scenarios specifically, assert BOTH that the old IP is gone AND the new IP is present (`dig +short` result must equal the new set exactly, not merely contain the new value) — this is a set-equality check, not a "contains" check, precisely because "contains new value" is satisfied by a bug that leaves the old value behind too.

**Warning signs:** Harness performs a resolver query in a `beforeEach`/setup step before the entry exists; update-scenario assertions use `Contains` rather than exact-set comparison against `dig` output.

**Phase to address:** Deployment-Verification Harness.

---

### Pitfall 8: Vacuous convergence — polling-until-timeout treated as success, or asserting a value that was never made to differ

**What goes wrong:** Two specific vacuous patterns the question calls out by name, both concrete here:
1. **Timeout treated as success:** a poll loop (`for i := 0; i < N; i++ { if converged { break }; sleep }`) followed by an UNCONDITIONAL assertion against the last-observed value, rather than a conditional check of whether the loop actually broke early. If the loop exhausts all N iterations without ever observing convergence, and the assertion re-reads the value one more time and it happens to match by then (or the assertion doesn't distinguish "broke early" from "ran out"), the test passes having proven nothing about *when* convergence happened, or whether it was the harness's own final read (not real propagation) that produced the match.
2. **Never-diverged, not converged:** asserting sink A's rendered artifact equals sink B's when both sinks were seeded identically and the scenario never performs a mutation that would make them differ even momentarily. Two things that started equal and were never forced apart will trivially "converge" without the propagation path under test ever running.

**Why it happens:** Both patterns produce a passing test with less code than the correct version — the timeout-as-success pattern skips tracking a boolean; the never-diverged pattern skips crafting a real state transition.

**How to avoid:**
- The polling helper must return an explicit `(converged bool, lastValue T, lastErr error)`, and the test must `require.True(t, converged, "did not converge within deadline; last observed: %v", lastValue)` — never an unconditional post-loop equality check.
- Before triggering the mutation, assert `oldValue != expectedNewValue` — proves the state was NOT already what's being asserted. After the mutation, require the specific `newValue` (not "any value") to be observed on BOTH sinks within the deadline. This is the concrete mechanism for distinguishing "converged" from "never diverged": capture and assert a real pre/post state difference exists before you can credit the harness with having observed propagation across it.

**Warning signs:** Test helper for polling returns only the final value, no boolean; convergence assertion runs unconditionally after a `for`/`sleep` loop with no early-exit tracking; the mutation scenario uses the SAME value the sinks already had (e.g., re-adding an already-present host) as its "convergence" trigger.

**Phase to address:** Deployment-Verification Harness — write this into the harness's shared polling helper (analogous to `waitForFileContent`/`waitForSidecar` in `proc_e2e`) once, so every convergence assertion in the suite inherits the fix rather than repeating the mistake per-test.

---

### Pitfall 9: Multi-container startup races produce flakiness unrelated to the feature under test

**What goes wrong:** unbound, two sink containers, and the router-hosts server all starting concurrently (e.g., via docker-compose) without explicit readiness gating: a sink's post-write hook can fire `unbound-control reload` before unbound's control socket is listening, or the test can query the resolver before it has bound port 53. Docker's "container is Up" status does not mean the process inside is accepting connections yet — this produces connection-refused-style flakiness that has nothing to do with DNS convergence correctness.

**Why it happens:** `depends_on` without a `condition: service_healthy` only orders container START, not readiness; fixed `sleep N` calibrated locally doesn't generalize.

**How to avoid:** Use docker-compose `depends_on: condition: service_healthy` backed by real healthchecks (`unbound-control status` for unbound; a TCP dial to the gRPC port for router-hosts). Extend the existing filesystem-based polling pattern (`waitForFileContent`/`waitForSidecar`, already proven reusable per testing.md's "Deferred: containerized two-node verification" section) with an equivalent `waitForResolver` that polls a real DNS query with backoff, rather than trusting container "running" state as a readiness signal.

**Warning signs:** docker-compose file has `depends_on` as a bare list (no `condition:`); the harness sleeps a fixed duration after `docker compose up` before running any assertion.

**Phase to address:** Deployment-Verification Harness.

---

### Pitfall 10: Loopback-address assumptions baked into generated config break under bridge networking

**What goes wrong:** testing.md documents that today's `proc_e2e` config generation is deliberately "transport-agnostic ... nothing assumes loopback," specifically so the future containerized harness could reuse it. If the new harness reuses `writeServerConfigFile`/`writeClientConfigFile` but hardcodes `127.0.0.1` instead of passing the docker-compose service's network alias, the test will pass on a machine using host networking and then fail — or worse, silently connect to nothing and hang — the moment it runs under standard bridge networking on a CI runner.

**Why it happens:** Loopback is the path of least resistance during local harness development and is easy to leave in place once "it works on my machine."

**How to avoid:** Config generation already takes the address as a parameter — use it. Pass the docker-compose service DNS name (not an IP), and add one explicit smoke-test step (`dig`/`nc` from inside the compose network) that fails fast and clearly if cross-container name resolution isn't working, before running the real scenario.

**Warning signs:** Any `127.0.0.1` or `localhost` literal in the new harness's compose-file-adjacent config generation code; the harness only works when run with `--network=host`.

**Phase to address:** Deployment-Verification Harness.

---

### Pitfall 11: A cursor keyed to a physical event-table position becomes dangling after compaction

**What goes wrong:** `CompactAggregate` (`internal/storage/sqlite/eventstore.go:255`) atomically **deletes** every existing event row for an aggregate and inserts exactly one new `HostCompacted` seed row inside a single `ImmediateTransaction`, with a freshly minted event ID chosen specifically to sort ABOVE the current `MAX(event_id)` (per the code's own comment and Key Decision D-18/D-20 in PROJECT.md). A cursor design that persists "resume from event row X" — by `event_id`, SQLite `rowid`, or any handle into the physical `events` table — can find that exact row gone on the very next page fetch. This is not a hypothetical: it is precisely what `CompactAggregate` does, unconditionally, whenever an operator invokes `CompactAggregates`, and it's the exact failure mode the question names ("a cursor pointing at an event that no longer exists").

**Why it happens:** Event-sourced systems make "resume from the last event ID I saw" feel like the natural cursor primitive — it's how many CDC/outbox-pattern systems work. This codebase's compaction feature specifically breaks that assumption by design (ADR router-hosts-4w2 and decision v5b: compaction is allowed to destroy pre-compaction history and IS destroying physical rows, atomically, at any time).

**How to avoid:** Define the cursor at aggregate granularity, not event granularity — "next aggregate_id to fold, in ascending ULID order," mirroring the iteration order `getDistinctAggregateIDs` already uses inside `ListAll` (`internal/storage/sqlite/projection.go:19-45`). Each page reconstructs its aggregates' CURRENT fold fresh via the same `loadEventsForAggregate` + `replayEvents` path `GetByID` already uses — never resumes into the middle of one aggregate's event list. A page boundary must always land on an aggregate boundary.

**Warning signs:** The cursor/pagination token type is `event_id`, a SQLite `rowid`, or anything that names a row in the `events` table directly; resume logic issues `SELECT ... FROM events WHERE event_id > ?`.

**Phase to address:** Cursor-Based Lazy Reads.

---

### Pitfall 12: Re-deriving cursor membership per page silently drops entries, and captures the wrong watermark timing

**What goes wrong:** Even with an aggregate-ID keyset cursor (safe against inserts of brand-new aggregates, since ULIDs are time-ordered and new IDs always sort after previously issued ones), a subtler bug appears if the per-page query re-derives "distinct aggregate IDs" fresh on every page call, and filters `Deleted` aggregates in SQL rather than in the fold step: an aggregate compacted-with-delete between two page fetches can vanish from the distinct-ID list entirely with no error — indistinguishable from a legitimate prune. The project already has a locked precedent for exactly this class of timing bug: Key Decision D-21 — "Change ID derived BEFORE `store.ListAll`... makes it a LOWER bound on entries sent. Deriving after would make it an upper bound, which the client-side skip turns into a permanently stale consumer that self-reports converged." A cursor watermark captured AFTER scanning, rather than before, inherits that exact upper-bound failure mode.

**Why it happens:** It's more natural to compute "what changed" by comparing before/after snapshots than to commit to a watermark up front — but D-21 already proved, in this codebase, that the "before" ordering is the only one that fails safe.

**How to avoid:** Apply D-21's pattern to the new cursor unconditionally: capture the change-ID / high-water mark ONCE, before starting aggregate iteration for a page or a full scan, and treat any change whose change-ID is above that watermark as "the client will observe this on its next poll/reconnect," never as "must appear in this response." Never derive the watermark after the scan completes.

**Warning signs:** The implementation computes a "latest change ID" by taking a MAX after building the response rather than before starting to build it; code review can't point to one specific line where the watermark is captured relative to the iteration loop.

**Phase to address:** Cursor-Based Lazy Reads.

---

### Pitfall 13: "Cursor API added" is asserted as "memory is bounded" without measurement — repeating the TMPL-06 overreach

**What goes wrong:** TMPL-06 originally claimed O(1) memory from chunked sends and had to be amended mid-milestone once cross-AI review established that chunking the OUTBOUND wire message (`sendExportChunks`, `internal/server/service.go:657-676`, 64 KiB windows) does nothing for server-side memory if the SOURCE data still folds everything into memory first. That is still true today: `ExportHosts` calls `s.store.ListAll(ctx)` at `service.go:687`, `WatchHosts`'s snapshot path calls it at `watch.go:97`, and the hosts-file/dnsmasq/unbound generators all call it too (`hostsfile.go:31`, `dnsmasqconf.go:46`, `unboundconf.go:55`) — every one materializes a full `[]domain.HostEntry` (and, for export, a fully-serialized `[]byte`) BEFORE the first byte goes out. A cursor implementation that only adds a page-token field to the gRPC request/response, while the storage layer underneath is still `ListAll`-shaped (fetch everything, THEN paginate in application code), delivers a cursor **contract** with zero actual memory benefit — the exact class of overreach this project has already had to publicly walk back once.

**Why it happens:** Adding a cursor parameter to an RPC is a small, visible change; changing the storage-layer iteration strategy underneath it is the actual hard part and is easy to defer or skip while still describing the work as "done."

**How to avoid:** Any memory claim in a PR or commit message must be backed by a MEASURED number: a benchmark using `testing.AllocsPerRun` or a `runtime.ReadMemStats` before/after snapshot against a synthetic fixture of N aggregates (N large enough to matter — e.g. 10k+), asserting peak/allocated bytes either stays within a stated bound independent of N, or states precisely how it scales (e.g. "O(page size) resident aggregates," not "O(1)" or "bounded" used loosely). State the claim precisely and have that specific wording reviewed — this is literally the corrective the TMPL-06 amendment already established as this project's bar, and it should be treated as a standing acceptance-criterion, not relearned.

**Warning signs:** PR description uses "O(1)" or "bounded" with no accompanying number; the new storage method still internally calls `ListAll`/`getDistinctAggregateIDs` as one full unfiltered list before slicing in application code; no benchmark test exists in the diff.

**Phase to address:** Cursor-Based Lazy Reads.

---

### Pitfall 14: The fix accidentally manufactures the materialized read model that the earlier "confirmed bug" wrongly assumed already existed

**What goes wrong:** The earlier bug report "read-model lag causes permanent optimistic-concurrency version conflicts" was confirmed as a symptom, but its named mechanism doesn't exist in this codebase — `GetByID` replays the event log live; there is no materialized read model to lag. A NEW cursor/streaming implementation is, structurally, the FIRST thing in this codebase that could hold read-side state across multiple round trips (a server-held cursor position, or — worse — a server-side cache of "which aggregates have already been sent this stream," or a background-refreshed snapshot used to make pagination fast). If implemented that way, the team would be building, for the first time, the exact mechanism the earlier report incorrectly assumed already existed — and inheriting its exact plausible failure mode: a client's cursor referencing a version the cache hasn't caught up to yet, which looks like a permanent conflict from the outside.

**Why it happens:** Cursor pagination against a live-replay store is slower per page than pagination against a cached/indexed read model, and "just cache it" is the natural optimization reflex once pagination performance becomes a concern.

**How to avoid:** Keep the cursor server-side-stateless. Each page/RPC call re-derives its data by replaying live from SQLite — the same pattern `GetByID`/`ListAll` already use — using only a client-supplied OPAQUE cursor token (last aggregate ID + watermark) to bound the query. Do not introduce a server-held cache, background refresher, or periodic snapshot rebuild as an incidental side effect of "adding cursor support." If a genuine performance need later argues for a materialized read model, that decision belongs in its own ADR (this project locks such decisions explicitly — see ADRs router-hosts-4w2, -bzg, -v5b, -vl8), not as an implementation detail nobody reviewed as an architecture change.

**Warning signs:** Design doc or PR introduces any struct/table that holds "already-sent" or "last-known" state server-side, keyed by client/session, that persists across RPC calls independent of the SQLite event log; a new background goroutine appears that refreshes something on a timer.

**Phase to address:** Cursor-Based Lazy Reads — this is a design-time decision point (resolve before writing code), not something to catch in code review after the fact.

---

### Pitfall 15: A long-lived cursor stream holding a read transaction can collide with the WriteQueue in exactly the way that produced the earlier confirmed-bug's real symptom

**What goes wrong:** Lesson (b)'s real root cause was "almost certainly a separate commit-on-timeout defect," not read-model lag. Compaction (and every other mutation) is routed through a single-goroutine `WriteQueue` with per-aggregate optimistic concurrency (PROJECT.md constraint: "All writes serialized through a single-goroutine WriteQueue... New write paths MUST be retry-safe/idempotent"). `WatchHosts` is already a long-lived bidi-streaming RPC. A cursor-based read that holds a single SQLite read connection/transaction open across an entire streamed response (rather than one short transaction per page, as `ListAll` already scopes internally within `withConn`) risks the same class of ambiguity that produced the earlier symptom: a long-held read racing a queued write with a timeout can make a commit appear to fail from the writer's side while having actually landed, or vice versa.

**Why it happens:** It's tempting to open one transaction/snapshot at the start of a cursor stream "for consistency" and hold it for the stream's lifetime — this reads as more correct (a stable point-in-time view) but trades that for exactly the write-path contention this project has already been burned by once, under a different name.

**How to avoid:** Each cursor page must use its own short-lived read connection/transaction, opened and released per page — never held open across a network round-trip or a gRPC `Send` call — mirroring how `ListAll` already scopes its transaction inside a single `withConn` call rather than exposing a live handle to callers. If a genuinely stable point-in-time cursor view is required, it must be achieved via the watermark comparison already established for D-21 and Pitfall 12 (compare change-IDs, not by holding a database transaction open).

**Warning signs:** Cursor implementation opens a SQLite connection/transaction before the streaming loop begins and closes it only when the stream ends; any `defer` closing a transaction sits outside the per-page loop.

**Phase to address:** Cursor-Based Lazy Reads.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|-----------------|------------------|
| Add a cursor/page-token field to the gRPC proto without changing the storage-layer iteration (still calls `ListAll` underneath) | Ships a visible API surface quickly; unblocks client work | Repeats the TMPL-06 "chunking ≠ bounded memory" mistake; the Active-item goal (`store.ListAll` no longer folding full history) stays unmet even though the proto looks done | Never as a final state — acceptable ONLY as an explicitly-labeled intermediate commit within the same phase, with a follow-up commit in the same PR/phase that fixes the storage layer before merge |
| Wire `e2e`/`docker_e2e` into CI first and defer `proc_e2e` | Faster visible progress on #403 | Leaves the CLI-flag seam — the exact G-01-1 mechanism — ungated for the deferral period | Never acceptable as the phase's final state; may be an interim commit order within the same phase if `proc_e2e` lands before the phase is marked complete |
| Harness-triggers `unbound-control reload` directly instead of relying on the documented hook mechanism | Simpler test setup, avoids debugging container init/hook wiring | Proves unbound CAN reload, not that router-hosts' hook mechanism DOES trigger it — the actual thing in scope | Acceptable only as a scratch/smoke-test step to validate the unbound container image itself, never as the final convergence assertion |
| Fixed `sleep N` instead of readiness polling in the containerized harness | Fast to write, works reliably on the author's machine | Flaky under CI resource contention; becomes the reason the gate gets disabled within weeks (Pitfall 5) | Never acceptable in a merged harness; fine only transiently while debugging locally |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|-----------------|-------------------|
| unbound container reload path | Asserting on the written conf file instead of a live resolver query | Query the running unbound container (`dig`/`unbound-control lookup`) after the documented reload hook fires |
| unbound negative caching | Pre-querying a hostname before it's created, seeding a negative-cache entry that then looks like a convergence failure | Never query a name before creating it; if testing negative-cache behavior specifically, do so as its own isolated scenario |
| docker-compose service startup | Relying on `depends_on` (bare) or a fixed sleep for readiness | Use `depends_on: condition: service_healthy` with real healthchecks (`unbound-control status`, TCP dial) |
| Docker daemon availability in CI | Trusting the test's own `t.Skip` as the availability check | Add an explicit `docker info \|\| exit 1` CI pre-step so unavailability fails the job instead of skipping it |
| `proc_e2e` binary freshness | Assuming `procBinaryPath`'s hard-fail-on-missing also proves the binary is current | Run `task build` as a dedicated, no-cache CI step immediately before `task test:e2e:proc` in the same job |
| SQLite `WriteQueue` vs. long-lived streaming reads | Holding one SQLite read transaction open for an entire cursor stream's lifetime | Scope one short-lived read transaction per page, mirroring `ListAll`'s existing `withConn` scoping |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|-----------------|
| Cursor API layered over an unchanged `ListAll`-based storage layer | Server RSS/allocated bytes during ExportHosts/WatchHosts still scales linearly with total aggregate count, unchanged from pre-cursor behavior | Push the query-level LIMIT/keyset WHERE clause into the storage layer itself; measure with a benchmark against a 10k+-aggregate fixture, not by inspection | Breaks (becomes visible) once the router's hosts inventory grows past whatever size previously prompted #400/#401 in the first place |
| Re-deriving `getDistinctAggregateIDs` as one unbounded list per cursor page | Memory/time per page grows with TOTAL aggregate count, not page size, even though the RPC contract looks paginated | Push aggregate-ID bounding (`WHERE id > cursor LIMIT pageSize`) into SQL, not application-code slicing of a full list | Same threshold as above — silent until inventory size crosses whatever prompted this milestone |
| Long-held SQLite transaction across a streamed cursor response | WriteQueue-routed writes (including compaction) begin blocking or timing out during active cursor streams | One short transaction per page (Pitfall 15) | Breaks under concurrent read-heavy + write-heavy load, which is exactly what a "resolver convergence" scenario in the deployment harness (concurrent watch + compact) would exercise |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Containerized deployment harness generates PKI material with a single shared CN across "two sink containers" | Sink health (keyed by CN per the existing `proc_e2e` design) becomes indistinguishable between the two sinks, masking which sink actually converged and which didn't | Mint a distinct client certificate CN per sink container, exactly as `issueClientCert`'s CN parameter already supports (testing.md: "PKI is N-party from the start") |
| `hermeticEnv`-style isolation not carried into the containerized harness | A container accidentally picking up host-level config/certs would pass for the wrong reason, mirroring the exact false-positive risk `hermeticEnv` was built to prevent in `proc_e2e` | Mount only test-generated config/cert directories into each container; never bind-mount a developer's or CI runner's real config paths |
| CI-wiring PR adds `--insecure-skip-verify`-style shortcuts to make containerized mTLS tests "just work" faster | Violates the project's locked mTLS-only trust boundary constraint (PROJECT.md: "TLS/CA verification MUST NOT be skipped; no InsecureSkipVerify") | Generate and mount real per-test PKI material into containers, exactly as `proc_e2e` already does for real processes |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|--------------|-------------------|
| Cursor-based `WatchHosts`/`ExportHosts` silently changes ordering or omits an in-flight aggregate during a page boundary race with a write | A consumer following the stream sees an inconsistent or seemingly-incomplete snapshot with no error, and no way to tell "I'm missing something" from "there was nothing more" | Apply the D-21 watermark-before-scan pattern (Pitfall 12) so any race is captured as "observe on next poll," never as silent omission; document the exact consistency guarantee (e.g., "each page reflects the store as of read time; changes racing a page are guaranteed visible on the next page or reconnect") |
| Deployment-verification harness reports "converged" based on a coincidental final-poll match rather than genuine propagation | False confidence that the feature works when a mutation was never actually propagated correctly | Require explicit pre/post state divergence before crediting convergence (Pitfall 8) |

## "Looks Done But Isn't" Checklist

- [ ] **CI gate for a tier:** Job is green — but has it EVER been observed red against a deliberately broken commit? Verify a link to a red run exists in the wiring PR (Pitfall 4).
- [ ] **`proc_e2e` in CI:** Job passes — but was the binary it tested built fresh in this job, or restored from cache/a previous run? Verify the `task build` step precedes it with no `bin/` cache restore (Pitfall 2).
- [ ] **Deployment harness "resolver reload" assertion:** Test passes — but does it query the live resolver, or only diff a config file on disk? Verify a `dig`/`unbound-control lookup` call exists in the assertion path (Pitfall 6).
- [ ] **Deployment harness "convergence" assertion:** Test passes — but did the scenario ever make the two sinks differ before asserting they're equal? Verify an explicit pre-mutation divergence check exists (Pitfall 8).
- [ ] **Cursor-based streaming "bounded memory" claim:** PR claims O(1)/bounded memory — but is there a benchmark number in the diff, or only a description of the API shape? Verify a `testing.AllocsPerRun`/memstats benchmark exists against a large synthetic fixture (Pitfall 13).
- [ ] **Cursor pagination across compaction:** Feature "handles compaction correctly" — but is the cursor token an aggregate-ID watermark, or does it reference a physical event row/rowid? Verify by reading the cursor token's type definition, not by running the happy path (Pitfall 11).

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|-----------------|-------------------|
| A CI tier merged as required but turns out to be vacuous (soft-skip, stale binary) | LOW | Add the missing hard-fail pre-check (Docker availability, fresh build step) and re-verify with a deliberately-broken-branch red run before re-enabling as required |
| Cursor implementation shipped as `ListAll`-shaped underneath a paginated API (Pitfall 13) | MEDIUM | Amend the requirement's wording (as TMPL-06 already was), descope the unproven memory claim, and schedule the actual storage-layer query change as its own follow-up work — do not let the amended wording quietly become the permanent state without a tracked follow-up |
| Cursor token found to reference physical event rows after compaction breaks it in production/staging | HIGH | Requires a wire-format/API change (cursor token shape), likely a breaking change to any client already depending on the old token; redesign the token as an aggregate-ID + watermark pair and version the change |
| Containerized harness discovered to be asserting "converged" vacuously after already being relied on for a release decision | MEDIUM | Re-run the specific UAT item (#42) manually against real hardware once more as a stopgap while the harness's convergence assertion is fixed per Pitfall 8; do not mark the deferred verification item closed until the harness itself is proven capable of failing |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|-------------------|----------------|
| 1. Docker-tier soft-skip reports green | CI Gating (e2e tiers) | CI log has zero `--- SKIP` lines for docker_e2e; a `docker info` pre-check gates the job |
| 2. `proc_e2e` runs against stale binary | CI Gating (e2e tiers) | Job log shows `task build` immediately preceding `task test:e2e:proc` in the same job, no cache restore of `bin/` |
| 3. `e2e`/`docker_e2e` treated as sufficient closure of #403 | CI Gating (e2e tiers) | Branch protection lists `proc_e2e` as a required check |
| 4. Gate never observed red | CI Gating (e2e tiers) | PR description links a CI run on a deliberately-broken branch showing each tier fail |
| 5. Flaky tiers get quietly disabled | CI Gating (e2e tiers) | No `continue-on-error` on any of the three tiers; ephemeral ports used throughout |
| 6. Reload asserted via file diff, not live query | Deployment-Verification Harness | Assertion code path includes a `dig`/`unbound-control lookup` call |
| 7. Negative caching / stale-record masking | Deployment-Verification Harness | Update scenarios assert exact-set equality (old value ABSENT, new value present), not `Contains` |
| 8. Vacuous convergence (timeout-as-success, never-diverged) | Deployment-Verification Harness | Shared polling helper returns explicit `converged bool`; every scenario asserts pre/post divergence before the poll |
| 9. Multi-container startup races | Deployment-Verification Harness | docker-compose uses `condition: service_healthy`, not bare `depends_on` or fixed sleeps |
| 10. Loopback assumptions under bridge networking | Deployment-Verification Harness | No `127.0.0.1`/`localhost` literals in harness config generation; a network smoke-test step exists |
| 11. Cursor dangling on physical event rows post-compaction | Cursor-Based Lazy Reads | Cursor token type is aggregate-ID-based; a test compacts an aggregate mid-stream and asserts the stream still completes correctly |
| 12. Watermark captured after scan (upper-bound bug) | Cursor-Based Lazy Reads | Code review confirms watermark capture precedes iteration start, per D-21's pattern |
| 13. Unproven "bounded memory" claim | Cursor-Based Lazy Reads | PR includes a benchmark (`AllocsPerRun`/memstats) against a 10k+-aggregate fixture with a stated, precise bound |
| 14. Accidental materialized read model reintroduces the earlier bug's mechanism | Cursor-Based Lazy Reads | Design review confirms no server-held cross-call cache/snapshot was introduced; each page replays live from SQLite |
| 15. Long-held read transaction collides with WriteQueue | Cursor-Based Lazy Reads | Code review confirms one transaction per page, scoped like `ListAll`'s existing `withConn` usage, never held across a `Send` call |

## Sources

- `internal/storage/sqlite/eventstore.go` (`CompactAggregate`, lines 253–330+) — compaction's atomic delete-and-reseed mechanics, freshly-minted event ID above `MAX(event_id)`
- `internal/storage/sqlite/projection.go` (`ListAll`, `GetByID`, lines 1–100) — current full-materialization read path and live-replay-per-call pattern
- `internal/server/service.go` (`sendExportChunks`, `ExportHosts`, lines 642–700+) — wire-level chunking that does not bound server-side memory
- `internal/server/watch.go` — `WatchHosts` snapshot/follow-mode structure, `sendSnapshot` calling `ListAll`
- `internal/server/unboundconf.go`, `docs/guides/operations.md` — unbound reload delegated to an external hook, not triggered by router-hosts directly
- `e2e/docker_e2e_test.go` (lines 139–144) — the documented `t.Skip` on missing/unstarted Docker
- `e2e/proc_harness_test.go` (`procBinaryPath`, lines 41–62) — hard-fail-on-missing binary, explicitly citing G-01-1 as the failure class it guards against
- `docs/contributing/testing.md` — three-tier e2e design, each tier's proven/not-proven boundary, the "Deferred: containerized two-node verification" section describing the intended extension points for this milestone
- `.github/workflows/ci-go.yml` — current CI jobs; confirms none of the three e2e tiers run today
- `.planning/PROJECT.md` — Key Decisions table (D-21, D-18/D-20, D-12a, `proc_e2e` rationale), locked ADRs (router-hosts-4w2, -v5b, -vl8, -bzg), and the two named historical lessons (G-01-1; the read-model-lag misdiagnosis) that framed this research

---
*Pitfalls research for: router-hosts v0.14.0 — Verification & Lazy Reads*
*Researched: 2026-08-02*
