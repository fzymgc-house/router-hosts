---
phase: 1
slug: consumer-rendered-output-templates-sink
reviewed: 2026-07-31
reviewers: [codex, pi]
selection: explicit flags (--codex --pi)
plans_reviewed: 8
risk_codex: HIGH
risk_pi: MEDIUM
---

# Phase 1 — Cross-AI Plan Reviews

Both lanes were **explicitly named**, both produced real source-grounded reviews (no
stubs, no dropped lane). Each was given all 8 plans in full — neither lane declared a
prompt budget, so nothing was trimmed.

---

## Consensus Summary

### Both reviewers independently flagged the same top issue

**Plan 06's bidirectional stream teardown is unsafe.** Two reviewers, two different
failure paths, one root cause: the handler does `cancel()` then `wg.Wait()` before
returning, but `stream.Send` does not respect a *derived* context.

- **Codex (HIGH):** if `Send` fails while the client is silent, the sender exits but the
  handler stays blocked in `Recv`, so the stream never tears down.
- **pi (MEDIUM):** if the sender is blocked inside `Send` on flow control (a healthy but
  stalled client), `wg.Wait()` never returns. Keepalive bounds this only when the
  *network* is dead, not when a client is merely slow.

Both propose the same shape of fix: return from the handler on first error and let the
RPC teardown error the blocked `Send`, rather than joining the sender first.

This is the strongest signal in the review — independent convergence on the one piece of
genuinely novel concurrency, which RESEARCH.md had already flagged `[ASSUMED]` with no
in-repo precedent.

### Where the reviewers directly contradict each other

**TMPL-06 scope.** A real disagreement, not a nuance:

- **pi lists it as a STRENGTH** — "honest TMPL-06 scoping", noting the limitation is
  stated in three separate places rather than hidden.
- **Codex rates it HIGH** — the requirement and the roadmap success criterion both say
  O(1) memory and "neither side can be driven out of memory". Chunking the final buffer
  into 64 KiB sends bounds *message size*, not *server memory*. Codex's position:
  *"Calling the limitation 'honest' does not make the requirement satisfied."*

Both are right about different things. pi is judging plan **transparency**; Codex is
judging requirement **satisfaction**. The plans are honest AND the requirement is unmet.
Resolving this needs a decision, not a plan edit — see Decisions Required below.

**Coalescing.** Partially contradictory, and worth disentangling:

- **pi traced the subscribe-before-send ordering and confirmed it is correct** — a
  `Notify()` landing mid-send closes the held generation channel, so no update is lost.
- **Codex does not dispute correctness** but challenges the stronger *burst* promise and
  the test: closing a generation channel coalesces only while a watcher is busy or has
  not resubscribed, so `TestService_WatchHosts_FollowCoalescesBurst` asserting *strictly
  fewer* snapshots than mutations is scheduler-dependent and will flake.

Reconciled: the ordering is correct (pi verified it), but the coalescing *guarantee* as
written is weaker than the plan claims and the test encodes a race.

---

## Findings by severity

### HIGH

| # | Finding | Source | Plan |
|---|---|---|---|
| H1 | Stream teardown deadlock / goroutine leak — `wg.Wait()` before handler return | **both** | 06 |
| H2 | TMPL-06 does not meet its literal O(1)-memory requirement; chunking bounds message size, not server memory | codex | 04, 06 |
| H3 | Post-hook failure guarantee is impossible as written — the artifact is already replaced when the hook runs, so "hook errors leave the artifact untouched" cannot be true | codex | 07 |
| H4 | Unspecified data race — the status ticker goroutine reads last-success/failure state while the receive goroutine writes it; no ownership model given, and the suite runs under `-race` | codex | 07 |

### MEDIUM

| # | Finding | Source | Plan |
|---|---|---|---|
| M1 | Shipped `hosts.tmpl` embeds raw `.Comment`/`.Tags`, reopening the GH #349 newline/directive-injection class at every consumer that copies it. `sanitizeCommentField` exists (`hostsfile.go:119-129`) but templates get no FuncMap | **pi only** | 02 |
| M2 | Coalescing guarantee overstated; burst test is scheduler-dependent and will flake | codex | 06 |
| M3 | e2e harness never wires `SinkHealth` (`e2e/helpers_test.go:103`), so the CN-keying claim is asserted but not validated | codex | 08 |
| M4 | "Connection interruption" e2e only cancels one RPC on a live `ClientConn` — tests stream restart, not TCP/TLS interruption, keepalive detection, or the reconnect supervisor | codex | 08 |
| M5 | `router_hosts_sink_render_failures_total` is created but never incremented by any plan | codex | 05, 06 |
| M6 | Cardinality ceiling incomplete — evicting from a 1000-entry registry bounds the live map, not distinct label values already observed by the backend; the failure counter bypasses the registry entirely | codex | 05 |

### LOW

| # | Finding | Source | Plan |
|---|---|---|---|
| L1 | Entry cap is not a byte bound — comments/tags appear unbounded, so a server can OOM a client with fewer than 50k fat entries | codex | 03 |
| L2 | Existing `ExportHosts` tests read only the first response (`service_test.go:492,514,552`), so they do not establish byte identity after chunking | codex | 04 |
| L3 | Status payload on the *opening* Watch message is unspecified — recorded or ignored? | pi | 01, 06 |
| L4 | Status ticker sends `follow`-unset messages on a follow stream; works by design but is an implicit contract needing a proto comment | pi | 07 |
| L5 | Plan 02 Task 3 says the unbound example must match output "exactly" but only asserts declaration counts | pi | 02 |
| L6 | Plan 03's per-test small-limit seam is left open ("a setter, a package variable, or a seam") — the only unpinned test-critical mechanism in the set | pi | 03 |
| L7 | `SnapshotComplete.count` is `int32` while the cap is 50,000 — no overflow, but two units-of-truth | pi | 01, 03 |
| L8 | `render` is exposed to unbounded collection from wave 1 until Plan 03 lands in wave 3 | pi | 01, 03 |

---

## Decisions Required Before Execution

1. **TMPL-06 (H2)** — either implement cursor-based projection streaming (a new
   `storage.HostProjection` method, larger phase), or amend TMPL-06 and the roadmap
   success criterion to say "bounded wire messages and client backpressure, storage
   materialization explicitly deferred". The current plans satisfy neither the literal
   requirement nor an amended one.
2. **Post-hook failure semantics (H3)** — the artifact cannot be both replaced and
   untouched. Codex recommends three distinct outcomes: render/write failure (artifact
   unchanged), artifact updated + hook failed (artifact retained, reload health marked
   failed), connection failure (artifact unchanged and stale).
3. **Template escaping (M1)** — ship a sanitizing FuncMap as part of contract v1, or make
   the examples avoid raw comment/tag embedding. pi's argument for deciding *now*: adding
   functions later is a compatible change, but doing it after examples ship means two
   generations of consumer templates.

---

## Reviewer Verdicts

| Reviewer | Risk | Position |
|---|---|---|
| Codex | **HIGH** | Directionally strong, but two correctness blockers (stream teardown, post-hook semantics) plus one requirements gap. Fixing them reduces the phase to medium without a redesign. |
| pi | **MEDIUM** | Unusually well-grounded; nearly every load-bearing claim verified true against the repo. Not LOW because the two genuinely novel pieces — bidi teardown and the template injection surface — both have concrete unresolved weaknesses. |

Neither reviewer rated the phase LOW. Both agree the issues are fixable within the
existing plan structure without re-planning from scratch.

---

## Codex Review

### Codex — Summary

The plans are unusually thorough and mostly align with the existing architecture, but they are not ready to execute unchanged. The largest issues are a likely goroutine leak in the bidirectional stream teardown, coalescing guarantees stronger than the proposed notifier can provide, failure semantics that become impossible once a post-write hook runs, and TMPL-06 still not meeting its literal O(1)-memory requirement. The real-mTLS plan also does not currently wire or assert the sink-health state it claims to validate.

### Codex — Strengths

- The central notification integration point is correctly identified. `regenerateOutputs` is reached by add, update, delete, import, rollback, and startup at [service.go:108](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:108), [service.go:211](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:211), [service.go:285](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:285), [service.go:314](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:314), [service.go:594](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:594), and [service.go:850](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:850). One notifier call there is the right topology.

- Plan 06 correctly requires notification before the current early return. Deployments without generators or hooks presently return at [service.go:150](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:150), so placing `Notify` below it would miss changes.

- The atomic-writer relocation is well grounded. The existing helper already performs same-directory temporary creation, write, file sync, close, and rename at [hostsfile.go:131](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/hostsfile.go:131). Moving it into a shared package is preferable to duplicating it client-side.

- The template data contract is appropriately separated from the internal domain model. The current domain object exposes additional fields and uses a pointer for comments at [host.go:10](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/domain/host.go:10); a dedicated five-field template struct prevents accidental contract expansion.

- Undefined struct fields will fail loudly under `text/template`. `missingkey=error` remains useful for defense in depth, but the plan correctly relies on a typed struct rather than a `map[string]any`.

- The keepalive values are internally compatible: the proposed client interval is 20 seconds and the server minimum is 15 seconds. The current client has no keepalive option at [client.go:31](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/client/client.go:31), while server options are assembled centrally at [server.go:83](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/server.go:83), so the proposed integration locations are sound.

- The plans accurately identify `ImportHosts` as a false concurrency precedent. It drains `Recv` first at [service.go:448](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:448) and only later sends progress, rather than operating full-duplex.

### Codex — Concerns

- **HIGH — Plan 06 can deadlock when the sender fails.** The proposed handler keeps `stream.Recv()` on the handler goroutine and waits for it to finish before joining the sender. Cancelling a child context created from `stream.Context()` does not itself cancel the transport operation backing a currently blocked `stream.Recv()`. If `sendSnapshot` or `stream.Send` fails while the client remains silent, the sender can exit while the handler stays blocked in `Recv`, so it never returns and never releases the stream. Use two worker goroutines—one Send owner and one Recv owner—with the handler selecting on their error channel and returning promptly, or otherwise provide a mechanism that demonstrably unblocks Recv.

- **HIGH — TMPL-06 is not actually achieved as specified.** `ListAll` constructs a complete `[]domain.HostEntry` by enumerating every aggregate and replaying all its events at [projection.go:19](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/sqlite/projection.go:19). `ExportHosts` then holds that slice and builds another complete formatted buffer at [service.go:609](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:609) and [service.go:614](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:614); JSON additionally allocates another full slice at [service.go:634](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:634). Breaking the final buffer into 64 KiB sends bounds message size, not server memory. Because the requirement and success criterion explicitly say O(1) memory and that neither side can be driven out of memory, this needs either a storage/projection streaming design or an explicit requirements amendment. Calling the limitation “honest” does not make the requirement satisfied.

- **HIGH — Plan 07’s post-hook failure guarantee is impossible as written.** The prescribed sequence is render → atomic artifact replacement → sidecar update → post-write hook. If the hook then fails, the new artifact already exists. The plan nevertheless says hook errors follow the same path as render/write errors and leave the artifact untouched. Those cannot both be true. Define hook failure as “artifact successfully updated, resolver reload failed,” retain the new artifact, and reflect that distinct state in the sidecar and metrics. Rolling the artifact back after an external command has run would introduce worse ambiguity.

- **HIGH — The proposed client concurrency has an unspecified data race.** Plan 07’s ticker goroutine reads last-success and failure state while the receive goroutine updates it. No mutex, atomic snapshot, or channel-owned state model is specified. The repository’s established shared-state code uses explicit locking, and the full suite runs under `-race`; the plan should define ownership before implementation.

- **MEDIUM — The notifier does not guarantee “one snapshot per rapid burst.”** Closing a generation channel coalesces notifications only while a watcher is already busy or has not resubscribed. If mutations and snapshot sends interleave favorably, every mutation may legitimately produce a snapshot. Therefore `TestService_WatchHosts_FollowCoalescesBurst` requiring strictly fewer snapshots than mutations is scheduler-dependent and flaky. More importantly, the promise that a watcher “never renders an intermediate state” is not supported: after mutation A commits, a snapshot may be sent before mutation B begins. If true debounce/burst settlement is required, add a bounded debounce or dirty-generation loop with precise semantics.

- **MEDIUM — Plan 08 does not validate the sink identity claim.** The e2e harness constructs the service without `WithSinkHealth` at [helpers_test.go:103](/Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:103). Although the client certificate has CN `e2e-test-client` at [helpers_test.go:222](/Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:222), merely sending a status message proves neither that this CN was extracted nor that state was keyed by it. The harness must inject a `SinkHealth` registry and expose it to the test, then assert the exact CN entry.

- **MEDIUM — The “real connection interruption” e2e test only cancels one RPC.** Reopening a stream on the same `grpc.ClientConn` does not test TCP/TLS interruption, keepalive detection, redial behavior, or the CLI reconnect supervisor. It validates stream restart, not connection recovery or artifact preservation. The stated phase criterion needs a server stop/restart or forced connection closure while the real `watch` command is running.

- **MEDIUM — The render-failure counter appears unwired.** Plan 05 creates `RecordSinkRenderFailure`, but Plan 06 records only the status snapshot and no later plan invokes the counter. A client-reported failure count is a gauge-like state, not a counter event. As written, `router_hosts_sink_render_failures_total` will remain zero.

- **MEDIUM — The claimed metric-cardinality ceiling is incomplete.** Evicting the oldest entry from a 1,000-item registry bounds the current map, but not the number of distinct label values an OTel backend has observed over time. The render-failure counter bypasses that registry ceiling entirely. CN-only labels are safer than caller names, but “bounded by construction” is too strong unless allowed CNs are statically bounded or unknown identities are aggregated.

- **LOW — The client entry-count cap is not a byte bound.** Hostnames and aliases are constrained—hostnames to 253 bytes and aliases to 50 at [validation.go:32](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/validation/validation.go:32) and [validation.go:82](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/validation/validation.go:82)—but comments and tags do not appear to have equivalent limits. A malicious server can therefore send fewer than 50,000 entries with very large repeated/string fields. A byte-budget or both an entry and byte limit would match the OOM threat more closely.

- **LOW — Existing ExportHosts tests are weaker than the plan suggests.** They consume only the first response at [service_test.go:492](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service_test.go:492), [service_test.go:514](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service_test.go:514), and [service_test.go:552](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service_test.go:552). They will pass for small payloads, but they do not independently establish concatenated byte identity after chunking. Add explicit all-format multi-chunk reconstruction tests.

### Codex — Suggestions

- Redesign Watch teardown around two stream-owner goroutines and a handler-level `select`. Add tests where Send fails while Recv has no pending message, and vice versa.

- Replace the vague burst claim with one of two precise contracts:

  - generation coalescing: changes occurring while a snapshot is in flight produce at most one additional snapshot; or
  - time-window debounce: changes within a configured short window produce one snapshot.

- Split sink cycle results into at least:

  - render/write failure: artifact unchanged;
  - artifact updated, hook failed: artifact retained but reload health marked failed;
  - connection failure: artifact unchanged and stale.

- Move watch health state behind a mutex or make one goroutine own it and serve immutable snapshots to the status sender through a channel.

- Either implement true paginated/projection streaming for TMPL-06 or change TMPL-06 and the roadmap success criterion before execution to say “bounded wire messages and client backpressure, with storage materialization explicitly deferred.”

- Extend the e2e environment to retain `SinkHealth`, assert `e2e-test-client`, and run the actual CLI watcher through a server shutdown/restart.

- Remove the render-failure counter unless a protocol event and invocation point are designed. Otherwise add a monotonic failure sequence or explicit failure event; deriving counter increments from repeated status reports risks double-counting.

- Add a byte-budget alongside `max_stream_entries`, accounting for strings, aliases, tags, and comments before retaining each message.

### Codex — Risk Assessment

**HIGH.** The architecture is directionally strong, but the current plan set contains two correctness blockers—the server stream teardown and contradictory post-hook failure semantics—and one requirements gap where TMPL-06 remains unmet. The coalescing and e2e claims also exceed what the proposed tests and wiring establish. Addressing these before execution should reduce the phase to medium risk without requiring a wholesale redesign.

---

## pi Review

I've verified the plans against the actual code (service.go, hostsfile.go, server.go, client.go, serve_wiring.go, config/client.go, testhelper_test.go, hosts.proto, metrics.go). Here is my review.

### pi — Summary

This is an unusually well-grounded plan set. Nearly every load-bearing claim I checked against the repo is accurate: `atomicWriteFile` at `internal/server/hostsfile.go:133-164` matches the plan's description verbatim including the five `oops.Wrapf` message strings; the `regenerateOutputs` early return the Plan 06 notify-placement constraint targets exists exactly as described (`internal/server/service.go:150`); `ImportHosts` is indeed drain-then-send (`service.go:441-599`), confirming the "false friend" warning; `NewServer` builds `grpcOpts := append([]grpc.ServerOption{grpc.Creds(creds)}, s.grpcOptions...)` (`server.go:84`), so Plan 04's "insert keepalive before `s.grpcOptions`" override story works; and `NewClientFromConn` (`internal/client/client.go:51-58`) really does leave the struct mostly zero-valued, so Plan 03's zero-value fallback to `DefaultMaxStreamEntries` is sound. The wave/dependency graph is coherent, the TMPL-06 scope limitation is stated honestly in three places, and the acceptance criteria are mostly mechanical and fail-able. The main technical risk is the Plan 06 stream-teardown design, which has a bounded-but-real goroutine-leak path the plans don't discuss.

### pi — Strengths

- **Honest TMPL-06 scoping.** `store.ListAll` is in fact a full fold with no cursor API, and the plan set says so in Plan 04's `must_haves.known_limitations`, the docs task in Plan 02, and the phase audit — rather than claiming "O(1) memory". The chunked-send change is surgical: `ExportHosts` currently does exactly one `stream.Send(&hostsv1.ExportHostsResponse{Chunk: data})` (`service.go:678`), and the client receive loop in `importexport.go:194-215` already concatenates chunks, so multi-chunk responses need no client change. Verified.
- **Keepalive numbers are internally consistent and checked against grpc-go semantics.** Client `Time: 20s` ≥ server enforcement `MinTime: 15s`, so a compliant client won't get GOAWAY'd; `PermitWithoutStream: true` on both sides matches the idle-sink use case; and the plan adds a *test* (`TestKeepalive_ClientIntervalRespectsServerMinTime`) for the invariant rather than just documenting it. The absence of keepalive anywhere in the repo is real (`grep` confirms zero hits).
- **The subscribe-before-read ordering in Plan 06 is correct.** I traced it: watcher holds generation channel *ch*, sends snapshot, then selects on `<-ch`; a `Notify()` landing mid-send closes that *ch*, so the watcher wakes immediately after the send and re-reads — no lost update. The plan also correctly identifies that this comment is the kind of invariant a phrase-grep acceptance gate can't reliably check, and uses two independent token greps instead.
- **Notify placement is right and verified.** Putting `changes.Notify()` after the generator blocks but before the `if s.hooks == nil || !ran` early return (`service.go:150`) is required, and the plan calls it out with a dedicated test (`TestService_RegenerateOutputs_NotifiesWithoutGenerators`).
- **D-10/D-13 are implemented structurally, not by convention.** Identity comes only from `peer.FromContext` → `TLSInfo.VerifiedChains[0][0].Subject.CommonName`, and `server.go:207` really does set `tls.RequireAndVerifyClientCert`, making the nil-guards genuinely defensive. Plan 05's acceptance criterion "no `req.`/request-body reads in peercn.go" enforces it mechanically.
- **Real gaps are closed in the right place.** The bufconn harness uses `insecure.NewCredentials()` (`testhelper_test.go:48`), so CN extraction genuinely never runs against a verified chain until Plan 08's e2e — and the e2e harness (`e2e/helpers_test.go`, real CA/certs, build tag intact) supports the planned tests without new machinery.
- **Tracer discipline.** Plan 01 wires one path through all five layers with `follow=true` explicitly returning `Unimplemented` until Plan 06, and Plan 01 Task 1 forces an explicit human sign-off on the two one-way decisions before any code.

### pi — Concerns

- **MEDIUM — Plan 06 stream teardown can leak the sender goroutine for the life of a connection.** The handler derives `ctx, cancel := context.WithCancel(stream.Context())`, but gRPC's `stream.Send` does not respect a *derived* context — it unblocks only when the handler returns, the connection dies, or flow control opens. Sequence: client calls `CloseSend` → receiver gets `io.EOF` → `cancel()` → `wg.Wait()` → but if the sender is blocked inside `stream.Send` on flow control (slow/stalled client, healthy connection), `wg.Wait()` never returns and the handler never returns, so the stream never tears down. Plan 04's keepalive (30s/10s) bounds this to ~tens of seconds only when the *network* is dead; a healthy-but-stalled client defeats it. The standard fix is to return from the handler without joining the sender (letting the RPC return tear down the stream and error the blocked `Send`), or to route sends through a select on a done channel with an internal queue. At minimum the plan should name this trade-off; the current "cancel, wg.Wait, drain errCh" skeleton deadlocks in that window.
- **MEDIUM — Plan 02's shipped `hosts.tmpl` example embeds `.Comment`/`.Tags` raw, which is exactly the injection vector Plan 02's own T-1-06 documents.** `text/template` provides no escaping, and the plan adds no template helper functions, so the copy-paste-ready example cannot reproduce what `sanitizeCommentField` (`hostsfile.go:119-129`) does. A consumer copying `hosts.tmpl` verbatim re-opens GH #349's newline/directive-injection class at their site. Either ship a `sanitize`-style func in the template FuncMap (cheap: the replacer already exists) or make the examples avoid embedding raw comment/tags and say why in the header comment.
- **LOW — Plan 06's health-status path is only half-specified for the opening message.** `WatchHostsRequest` carries `optional SinkStatus status = 2` (Plan 01), and the follow-mode handler reads the first request only for `follow`; the plan never says whether a status payload on the *opening* message is recorded or ignored. Minor, but it's a contract ambiguity consumers will hit.
- **LOW — Plan 07's status ticker sends full `WatchHostsRequest` messages with `follow` unset on a follow stream.** Works by design (server only reads `follow` from the first message), but this is an implicit protocol contract that deserves a proto comment, or a future reader will "fix" it.
- **LOW — Plan 02 Task 3 action text says the unbound example must reproduce `unboundconf.go` output "exactly", but the acceptance criteria only assert zone-declaration count and the absence of `transparent`.** The rendered-fixture test should assert full expected text against the same two-entry fixture the existing `unboundconf_test.go` uses, or the "exactly" claim is unenforced.
- **LOW — Plan 03's per-test small-limit seam is hand-waved.** "Add an exported-for-test setter, a package variable, or a seam" is the only place in the whole plan set where a test-critical mechanism is left open; since `setupCmdTest` (`testhelper_test.go:18-68`) builds through `NewClientFromConn` with no config, the natural seam is a `WithMaxStreamEntries` option on the client or a harness-settable field — worth pinning now to avoid a per-executor improvisation.
- **LOW — Plan 01's `SnapshotComplete.count` is `int32` while Plan 03's cap is 50,000 entries.** No overflow risk, but the terminator count and the client cap live in different units-of-truth; a one-line comment in the proto that count is bounded by the client's configured ceiling would prevent confusion.
- **LOW — `render` in Plan 01 is exposed to the unbounded-collection threat until Plan 03 lands (acknowledged in T-1-05 as "no worse than today's `host list`").** Accurate, but since Plan 03 is wave 3 and Plan 01 is wave 1, the exposure window spans two waves of merges; consider making `render`'s drain loop bounded-with-a-constant in Plan 01 and upgraded to configurable in Plan 03.

### pi — Suggestions

1. Plan 06: change the teardown contract — handler returns on first error and lets the RPC framework error the blocked `Send`, instead of `wg.Wait()` before return; or add a comment + test explicitly covering "blocked Send during client CloseSend".
2. Plan 02: add a minimal FuncMap with a newline-collapsing function (reuse `commentLineBreakReplacer` via a small exported helper) and use it in `hosts.tmpl`/`unbound.tmpl`; document it as part of contract v1 *now*, because adding functions later is a compatible change but adding them after examples ship means two example generations.
3. Plan 06: write a proto comment on `WatchHostsRequest.status` stating it is meaningful on every message after the first and that `follow` is read only from the first.
4. Plan 02 Task 3: assert full rendered-text equality for `unbound.tmpl` against the fixture used by `TestService_UnboundConf`-style tests, not just declaration counts.
5. Plan 03: pin the test seam — e.g. `client.WithMaxStreamEntries(n)` option used by the harness — in the plan text.
6. Plan 08 Task 3: in the "server restart" step, also assert the sidecar's `consecutive_failures` resets to zero after reconnect, closing the loop with Plan 07's status semantics.

### pi — Risk Assessment

**MEDIUM.** The plan set is thorough, evidence-backed, and honest about scope — architectural decisions are correctly flagged one-way and gated, the wave ordering is sound, and most mechanism claims check out against the code. It is not LOW because the two genuinely novel pieces — the concurrent bidi stream teardown (goroutine-leak window) and the consumer-template injection surface (shipped examples embedding raw fields) — both have concrete unresolved weaknesses, and the highest-novelty concurrency code rests on a primitive with no in-repo precedent (the plan itself flags it `[ASSUMED]`). Both are fixable within the existing plan structure without re-planning.
