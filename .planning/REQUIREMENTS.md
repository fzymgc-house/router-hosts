# Requirements: router-hosts

**Defined:** 2026-07-07
**Core Value:** Cluster and CLI actors declare a hostname once, and the router's authoritative DNS output stays correct, leak-free, and hands-off.

> Provenance: no PRDs exist. Validated requirements are reconstructed from 10 SPEC design docs and the mapped Go codebase (shipped at v0.10.13). Active requirements are the open forward gaps, gated by four locked ADRs.

### v1 Requirements

#### Core — Event-Sourced Host Management (v0.10.13 Phase 1, shipped)

- [x] **CORE-01**: User can add, update, and remove DNS host entries (IP + hostname) via the CLI
- [x] **CORE-02**: Every mutation is recorded as an immutable domain event in an event-sourced SQLite store with per-aggregate optimistic concurrency
- [x] **CORE-03**: Server regenerates the `hosts(5)` file from the projected read model on every successful write
- [x] **CORE-04**: Client and server communicate over gRPC secured by mutual TLS
- [x] **CORE-05**: User can browse/edit entries via an interactive TUI and import/export in table, JSON, and CSV formats
- [x] **ALIAS-01**: User can assign multiple hostname aliases to a single canonical host entry

#### Certificates & ACME (v0.10.13 Phase 2, shipped)

- [x] **CERT-01**: Server reloads TLS certificates and config on SIGHUP without dropping in-flight connections (supports Vault Agent rotation)
- [x] **ACME-01**: Server automatically obtains and renews TLS certificates via ACME with a renewal loop
- [x] **ACME-02**: Server completes ACME DNS-01 challenges through Cloudflare using env-expanded credentials

#### Kubernetes Operator — Core Controllers (v0.10.13 Phase 3, shipped)

- [x] **OPER-01**: Operator reconciles HostMapping custom resources into router DNS entries over mTLS
- [x] **OPER-02**: Operator syncs IngressRoute hostnames to router DNS entries with configurable IP resolution
- [x] **OPER-03**: Operator removes DNS entries when their source resource is deleted (deletion scheduling)

#### Observability (v0.10.13 Phase 4, shipped)

- [x] **OBS-01**: Server exposes OpenTelemetry metrics for host operations and storage health
- [x] **OBS-02**: Trace context propagates from client through server to storage operations

#### Split-Horizon DNS Output (v0.10.13 Phase 5, shipped)

- [x] **DNSOUT-01**: Server generates dnsmasq-format output alongside `hosts(5)`
- [x] **DNSOUT-02**: Server generates unbound-format output using per-name `static` zones that leak neither ECH nor AAAA

#### Aggregate Compaction (v0.10.13 Phase 6, shipped)

- [x] **COMP-01**: Operator can compact aggregates on demand via a CompactAggregates RPC
- [x] **COMP-02**: Compaction progress and outcome are observable through metrics gauges

#### Gateway API Support (v0.11.0 Phase 7, shipped)

- [x] **GW-01**: Operator reconciles HTTPRoute/GRPCRoute/TLSRoute hostnames into router DNS
- [x] **GW-02**: IPs resolve from the parent Gateway's `status.addresses`
- [x] **GW-03**: Gateway API support is opt-in via `--enable-gateway`

#### Kubernetes Service Controller (v0.11.0 Phase 8, shipped)

- [x] **SVC-01**: Annotated LoadBalancer/NodePort Services register their hostnames in router DNS
- [x] **SVC-02**: IPs resolve from `status.loadBalancer.ingress[]` or the `ip-address` annotation, opt-in via `--enable-service`

#### Hook Reliability & Metrics (v0.12.0 Phase 9, shipped)

- [x] **HOOK-01**: Post-edit hooks emit execution metrics (count, duration, outcome)
- [x] **HOOK-02**: Hooks run detached from the write path with per-hook configurable timeouts, bounded concurrency, coalescing, and a bounded-drain shutdown

#### Consumer-Rendered Output (v0.13.0 Phase 1, shipped)

- [x] **TMPL-01**: A caller supplies a template and receives host data rendered through it, without a code change to this project
- [x] **TMPL-02**: The field set a template may reference is documented and versioned as an explicit compatibility surface (at minimum `ip_address`, `hostname`, `aliases`, `tags`, `comment` per entry, plus `.Count`, `.GeneratedAt`, `.ContractVersion` and `.ChangeID` metadata) rather than being whatever the internal struct happens to expose. The contract also publishes a **sanitizing template function** so a consumer template can emit comment/tag text without reopening the newline-injection class closed in #349 (`internal/server/hostsfile.go:123`)
- [x] **TMPL-03**: A template referencing an undefined key fails loudly; a render failure never emits a partial or empty artifact and leaves any previous artifact byte-identical
- [x] **TMPL-04**: Writes to a path are atomic (write-and-rename), so a consumer watching the file never observes a partial write
- [x] **TMPL-05**: Sink mode holds the rendered artifact current as host data changes without polling, and recovers after a connection interruption without emitting a truncated artifact
- [x] **TMPL-06**: `ExportHosts` and sink streaming emit **bounded wire messages with client backpressure** — the client is never handed an unbounded single response and can apply backpressure. **Storage-layer laziness was explicitly deferred** and is now carried by LAZY-01…04 in v0.14.0. Amended 2026-07-31 after cross-AI review (`01-REVIEWS.md` H2) — the original wording said "O(1) memory", which chunked sends do not deliver
- [x] **TMPL-07**: Client-side stream collection is bounded and fails with a clear error past the limit, so a malicious or buggy server cannot exhaust client memory (absorbs #38)
- [x] **TMPL-08**: Each snapshot carries a **change ID** identifying the server state it represents — the ULID of the newest event in the log (`MAX(event_id)`), so it is durable across restarts and monotonic. The same state yields the same ID for every consumer, making cross-consumer convergence observable. A client records the last change ID it rendered and may skip a redundant render, but the **server never uses a client-reported change ID to decide what to send** — that would make it a resume token and violate D-08's stateless-server constraint

#### CI Gating — e2e Tiers (v0.14.0, active)

Closes #403. The three tiers already exist from v0.13.0 Phase 1; this is wiring, not new test code.

- [x] **CI-01**: All three e2e tiers (`e2e`, `docker_e2e`, `proc_e2e`) run as CI jobs, and a single aggregated required check fails if any tier fails — so a merge cannot land on a tier nobody made required
- [x] **CI-02**: The fast tier gates every PR; the container and process tiers gate merge to `main`. `proc_e2e` is required before merge because it is the only tier that observes the CLI-flag→config seam (the blind spot G-01-1 shipped through)
- [x] **CI-03**: Each new gate is demonstrated **red** against a deliberately reintroduced regression before it is accepted — "never observed to fail" and "cannot fail" are indistinguishable from outside
- [x] **CI-04**: The container tiers hard-fail when Docker is unavailable instead of skipping (`e2e/docker_e2e_test.go` currently `t.Skip`s), and `proc_e2e` builds the binary fresh in-job rather than restoring a cached `bin/`, so neither tier can pass while testing nothing

#### Deployment Verification Harness (v0.14.0, active)

Replaces the second-physical-machine dependency. The bar is green-not-built.

- [ ] **VRFY-01**: Operator can run the deployment-verification suite locally and in CI with no second physical machine — a real unbound container plus two independent sink containers on a shared Docker network
- [ ] **VRFY-02**: The resolver-reload check asserts a **real DNS answer** from the running unbound container after zone regeneration, including that an unmanaged sibling name still resolves normally (no zone-wide NXDOMAIN leak, per ADR router-hosts-bzg) — asserting only "file changed" or "container healthy" does not satisfy this
- [ ] **VRFY-03**: The two-node convergence check asserts **state equality** via the monotonic change ID (TMPL-08) both sinks report, and distinguishes "converged" from "never diverged" by forcing a pre/post state difference. A timeout is recorded as failure, never as success
- [ ] **VRFY-04**: UAT test 42 (resolver reload plus two-node convergence) and the four manual deployment checks from plan 01-08 execute and pass in the harness, so v0.13.0 Phase 1 no longer reports `uat-passed: false`
- [x] **VRFY-05**: Readiness is established by wait-strategy polling with a bounded timeout — no fixed sleeps — through a shared helper reused by `docker_e2e`, `proc_e2e`, and the harness, so anti-flake rules live in one place rather than being reinvented per test file

#### Lazy Storage Reads (v0.14.0, active)

Closes #400, #401, #23. Completes the half of TMPL-06 deferred at v0.13.0.

- [ ] **LAZY-01**: `storage.HostProjection` exposes a cursor-based read keyed on aggregate ID (keyset, not `OFFSET`), so a caller pages through entries without the store replaying every aggregate's full event log into memory. This is an interface change, not an internal optimization
- [ ] **LAZY-02**: `ExportHosts` and `WatchHosts` consume the cursor, and their peak memory no longer scales with total event-log size — proven by a **measured** benchmark (`AllocsPerRun`/memstats) against a 10k+ entry fixture, never by API-shape inspection
- [ ] **LAZY-03**: When a cursor sits inside an aggregate's pre-compaction history and that aggregate is compacted mid-stream, the reader jumps to the `HostCompacted` seed event at the preserved OCC version. This behavior is documented and covered by a test rather than left implicit
- [ ] **LAZY-04**: Rendered output is byte-identical before and after the change for every format, so no consumer template or pinned fixture breaks

### v2 Requirements

Acknowledged but deferred; not in the current roadmap.

#### Storage / History

- **HIST-01**: Per-aggregate snapshot tables + snapshot-accelerated rehydration (would restore GetAtTime across compaction; deferred per ADR router-hosts-vl8/-4w2)
- **HIST-02**: Automatic / threshold-triggered compaction (deferred as YAGNI per ADR router-hosts-vl8)

#### Maintainability

- **DEBT-01**: Remove in-tree Rust-era `legacy_migration.go` once all deployments are known-migrated

### Out of Scope

| Feature | Reason |
|---------|--------|
| Auto-compaction / snapshot tables / retention windows | YAGNI; root causes already fixed (ADR router-hosts-vl8) |
| GetAtTime replay across compacted aggregates | No production caller; deliberately sacrificed (ADR router-hosts-4w2) |
| unbound `typetransparent` / zone-wide `local-zone` | Re-leaks ECH/AAAA or NXDOMAINs siblings (ADR router-hosts-bzg) |
| Rust / Cargo / kube-rs / instant-acme stack | Superseded by 2026-02-22 Go migration |
| DuckDB / alternate storage backends | SQLite-only, pure-Go, no CGo by design |
| Materialized/indexed read model for sorted pagination | Would manufacture the very mechanism whose absence disproved #323, and contradicts the deliberate read/write merge in `internal/storage/storage.go:143-146`. The residual O(N entries) held for the `hosts`/`json` IP-then-hostname sort is not "full event history" and is out of scope for v0.14.0 |
| Generic multi-writer gap-detection subsystem | The single-goroutine `WriteQueue` makes the concurrent out-of-order-commit race impossible by construction |
| Exactly-once delivery guarantees for streaming reads | Out of scope for a storage layer; the sink already handles at-least-once correctly via idempotent change-ID application |
| Nightly-scheduled e2e cadence | Two gating events only (PR, merge to `main`) — a fourth cadence is CI machinery this milestone was not asked to build |
| Flake-quarantine convention | More machinery than a homelab-scale suite needs; revisit only if the container tiers prove flaky in practice |

### Traceability

Phase numbering restarted at v0.13.0 and again at v0.14.0, so the Milestone
column is required to read the Phase column unambiguously — v0.10.13 Phase 1
(Event-Sourced Host Core), v0.13.0 Phase 1 (Consumer-Rendered Output), and
v0.14.0 Phase 1 are different phases.

| Requirement | Milestone | Phase | Status |
|-------------|-----------|-------|--------|
| CORE-01 | v0.10.13 | Phase 1 | Complete |
| CORE-02 | v0.10.13 | Phase 1 | Complete |
| CORE-03 | v0.10.13 | Phase 1 | Complete |
| CORE-04 | v0.10.13 | Phase 1 | Complete |
| CORE-05 | v0.10.13 | Phase 1 | Complete |
| ALIAS-01 | v0.10.13 | Phase 1 | Complete |
| CERT-01 | v0.10.13 | Phase 2 | Complete |
| ACME-01 | v0.10.13 | Phase 2 | Complete |
| ACME-02 | v0.10.13 | Phase 2 | Complete |
| OPER-01 | v0.10.13 | Phase 3 | Complete |
| OPER-02 | v0.10.13 | Phase 3 | Complete |
| OPER-03 | v0.10.13 | Phase 3 | Complete |
| OBS-01 | v0.10.13 | Phase 4 | Complete |
| OBS-02 | v0.10.13 | Phase 4 | Complete |
| DNSOUT-01 | v0.10.13 | Phase 5 | Complete |
| DNSOUT-02 | v0.10.13 | Phase 5 | Complete |
| COMP-01 | v0.10.13 | Phase 6 | Complete |
| COMP-02 | v0.10.13 | Phase 6 | Complete |
| GW-01 | v0.11.0 | Phase 7 | Complete |
| GW-02 | v0.11.0 | Phase 7 | Complete |
| GW-03 | v0.11.0 | Phase 7 | Complete |
| SVC-01 | v0.11.0 | Phase 8 | Complete |
| SVC-02 | v0.11.0 | Phase 8 | Complete |
| HOOK-01 | v0.12.0 | Phase 9 | Complete |
| HOOK-02 | v0.12.0 | Phase 9 | Complete |
| TMPL-01 | v0.13.0 | Phase 1 | Complete |
| TMPL-02 | v0.13.0 | Phase 1 | Complete |
| TMPL-03 | v0.13.0 | Phase 1 | Complete |
| TMPL-04 | v0.13.0 | Phase 1 | Complete |
| TMPL-05 | v0.13.0 | Phase 1 | Complete |
| TMPL-06 | v0.13.0 | Phase 1 | Complete |
| TMPL-07 | v0.13.0 | Phase 1 | Complete |
| TMPL-08 | v0.13.0 | Phase 1 | Complete |
| CI-01 | **v0.14.0** | Phase 1 | Pending |
| CI-02 | **v0.14.0** | Phase 1 | Pending |
| CI-03 | **v0.14.0** | Phase 1 | Pending |
| CI-04 | **v0.14.0** | Phase 1 | Pending |
| VRFY-01 | **v0.14.0** | Phase 3 | Pending |
| VRFY-02 | **v0.14.0** | Phase 3 | Pending |
| VRFY-03 | **v0.14.0** | Phase 3 | Pending |
| VRFY-04 | **v0.14.0** | Phase 3 | Pending |
| VRFY-05 | **v0.14.0** | Phase 1 | Pending |
| LAZY-01 | **v0.14.0** | Phase 2 | Pending |
| LAZY-02 | **v0.14.0** | Phase 2 | Pending |
| LAZY-03 | **v0.14.0** | Phase 2 | Pending |
| LAZY-04 | **v0.14.0** | Phase 2 | Pending |

**Coverage:**

- v1 requirements: 46 total (33 shipped / Complete, 13 active / Pending)
- Mapped to phases: 46 — v0.14.0's 13 mapped 2026-08-02 (Phase 1 x5, Phase 2 x4, Phase 3 x4)
- Unmapped: 0

---

*Requirements defined: 2026-07-07*
*Last updated: 2026-08-02 mapping v0.14.0's 13 requirements to phases 1-3 (roadmap created)*
