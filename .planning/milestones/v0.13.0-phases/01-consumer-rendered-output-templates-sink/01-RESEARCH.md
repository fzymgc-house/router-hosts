# Phase 1: Consumer-Rendered Output (templates + sink) - Research

**Researched:** 2026-07-31
**Domain:** Client-side text/template rendering, gRPC bidirectional streaming, OTel observable gauges, atomic file writes
**Confidence:** HIGH (all 8 research questions answered against in-repo code or tool-verified library behavior; two open items flagged LOW where the fix requires a judgment call, not a fact-check)

## Summary

This phase moves output rendering from server to CLI. The server already has every
building block needed except three: (1) a per-consumer change-notification/coalescing
primitive that fans out to N concurrent watchers instead of the single hookRunner's
one global pending slot, (2) a way to extract the mTLS CN from a stream (no
production code path does this today — only test fixtures set `CommonName`), and (3)
gRPC keepalive configuration, which is **not currently set anywhere** in this codebase
and defaults to a 2-hour server-side ping interval — far too coarse to make D-09/D-10's
"last-seen" metric meaningful for detecting a dead sink.

The `ImportHosts` bidi RPC (`internal/server/service.go:441`) is cited in CONTEXT.md as
"the existing bidi precedent," but it is **not** a concurrent full-duplex pattern — it
fully drains `stream.Recv()` in a loop, then processes and calls `stream.Send()`
afterward. It proves the `grpc.BidiStreamingServer[Req,Resp]` API shape works in this
codebase, but the Watch RPC needed for D-06/D-07 requires genuine concurrent send/recv
(server pushes snapshots asynchronously on write while the client reports status at
its own cadence) — a goroutine pair per stream must be built fresh, following the
grpc-go concurrency contract (safe: one goroutine Send, another goroutine Recv,
simultaneously; not safe: two goroutines both calling Send, or both calling Recv).

`text/template`'s `missingkey=error` option does **not** cover D-03's fail-loud
requirement for struct field typos — verified by running it locally. A typo'd field on
a struct (`{{.Hostnaem}}`) already fails unconditionally via Go's reflection layer,
with or without the option; `missingkey` only affects **map** key lookups. Because
D-03 mandates a struct (not a map) as the template's top-level value, "fail loudly on
an undefined key" is achieved for free by the data-shape decision itself — set
`Option("missingkey=error")` anyway as defense-in-depth for any incidental map value,
but it is not the mechanism doing the real work.

A template can declare its target contract version using a `{{define "contract_version"}}N{{end}}`
named block, looked up via `Template.Lookup()` and executed independently of the main
body — verified working locally. This is cleaner than scanning raw source text for a
comment directive and needs no new dependency.

`ExportHosts` (`internal/server/service.go:602-678`) has a real, structural blocker for
"true" O(1)-memory laziness: `store.ListAll()` is not a SQL cursor read — it is an
event-sourced fold (`internal/storage/sqlite/projection.go:19-45`) that loads every
distinct aggregate ID, replays each aggregate's full event log, and returns one
in-memory `[]domain.HostEntry`. There is no cursor/keyset-paginated read path in
`storage.HostProjection` today. TMPL-06's practical target is therefore the **transport
and serialization** layer (stream one `HostEntry` per `stream.Send`, as `ListHosts`
already does at `service.go:319-330`, instead of building one giant `[]byte` blob and
sending it in a single `Send` as `ExportHosts` does today) — this bounds *wire* memory
and gives the client backpressure via gRPC flow control, but does not make the
server-side `ListAll()` read itself lazy. That is a pre-existing architectural property
of the event-sourced core, out of this phase's blast radius, and should be called out
to the user as a scope clarification, not silently narrowed.

`atomicWriteFile` (`internal/server/hostsfile.go:133-164`) has no external dependency —
plain `os.CreateTemp` → `WriteString` → `Sync` → `Close` → `Rename`. It can move
verbatim to a new shared package importable by both `internal/server` and
`internal/client` (neither currently imports the other). No existing shared
non-domain, non-config package exists for this; recommend a new `internal/atomicfile`
package.

No new external packages are required anywhere in this phase — `text/template`,
`google.golang.org/grpc/peer`, `google.golang.org/grpc/credentials`, and
`google.golang.org/grpc/keepalive` are all stdlib or already-vendored transitive
dependencies of the pinned `google.golang.org/grpc v1.83.0`. The Package Legitimacy
Audit is therefore trivial (see below).

**Primary recommendation:** Build the Watch RPC as a genuinely concurrent bidi stream
(separate goroutines for send/recv, `sync.WaitGroup` + error channel to coordinate
shutdown); drive per-stream coalescing off a lightweight shared "generation" broadcast
channel (not a copy of `hookRunner`, which is a process-wide singleton, not a per-stream
primitive); extract the mTLS CN via `peer.FromContext` → `credentials.TLSInfo` →
`State.VerifiedChains[0][0].Subject.CommonName`; configure explicit gRPC keepalive on
both client and server before relying on last-seen timestamps for anything operationally
meaningful; and treat `ExportHosts`'s laziness as a wire-format change, not a
storage-layer one.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Template rendering (text/template execution) | Client (CLI) | — | D-01: server never executes caller-supplied template text |
| Contract-version declaration + enforcement | Client (CLI) | — | D-05: CLI parses/refuses before rendering; server has no opinion on template content |
| Snapshot assembly (`.Entries`/`.Count`/`.GeneratedAt`) | API / Backend (gRPC service) | Database (event-sourced fold via `ListAll`) | Server owns authoritative state; must serialize it into the wire contract |
| Change coalescing / fan-out notification | API / Backend | — | Server is the only party that knows when a write commits; must notify all active watchers |
| Sink health / last-seen | API / Backend (OTel gauge) | Client (sidecar status file) | D-09/D-11 split: server-side metric for "server up + reachable" case, client-side file for "server down" case |
| Atomic artifact write | Client (CLI) | — | D-01 relocates rendering client-side; atomic write must follow it |
| Post-write hook exec | Client (CLI) | — | D-16: server-side hook system (Phase 9) does not fire for a client-only write |
| mTLS CN extraction | API / Backend (gRPC interceptor/handler) | — | CN is a property of the transport-layer peer certificate, only visible server-side |
| Bounded stream collection cap | Client (CLI) | — | D-14: protects client memory from a malicious/buggy server; a server-side cap would not address the actual threat model |
| Lazy `ExportHosts` streaming | API / Backend (wire serialization) | Database (already fully materialized by `ListAll`) | See Summary — genuine laziness would require a storage-layer cursor that does not exist; in-phase scope is the transport layer only |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `text/template` | stdlib (go1.26.5) | Client-side template rendering | No dependency, exact semantics already relied upon by D-15's `{{range}}` reasoning; confirmed via local execution (see Code Examples) |
| `google.golang.org/grpc` | v1.83.0 (pinned, `go.mod:22`) | Bidi Watch RPC, keepalive, peer/CN extraction | Already the only RPC transport in this codebase |
| `google.golang.org/grpc/peer` | bundled with grpc v1.83.0 | Extract `peer.Peer` from stream context | `[VERIFIED: go doc google.golang.org/grpc/peer]` |
| `google.golang.org/grpc/credentials` | bundled with grpc v1.83.0 | `TLSInfo.State.VerifiedChains` for CN | `[VERIFIED: go doc google.golang.org/grpc/credentials TLSInfo]` |
| `google.golang.org/grpc/keepalive` | bundled with grpc v1.83.0 | Bound dead-connection detection latency | `[VERIFIED: go doc google.golang.org/grpc/keepalive]` — not currently used anywhere in this repo (`rg` for `keepalive|KeepaliveParams` in `internal/server` and `internal/client` returns nothing) |
| `go.opentelemetry.io/otel/metric` (`Int64ObservableGauge`) | v1.44.0 (pinned) | Per-CN last-seen / last-success gauges | Already used identically for `router_hosts_aggregate_events_max` at `internal/server/metrics.go:307-348` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `os/exec` (`exec.CommandContext`) | stdlib | D-16 post-write exec hook | Mirrors the existing server-side hook pattern at `internal/server/hooks.go:197` (`exec.CommandContext(hookCtx, "sh", "-c", hook.Command)`) |
| `samber/oops` | v1.23.0 (pinned) | Structured errors for cap-exceeded, contract-version-mismatch, render-failure | Repo-wide convention; CLAUDE.md mandates it |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `text/template` | `html/template` | Rejected — `html/template` auto-escapes for HTML context, which is wrong for `dnsmasq`/`unbound`/arbitrary consumer config syntax; would corrupt output. Not evaluated further per CONTEXT.md's working assumption. |
| Named-block version declaration (`{{define "contract_version"}}N{{end}}`) | Raw-text regex scan for a magic comment (`{{/* contract-version: 1 */}}`) | Comments are stripped by the parser and are not independently executable/queryable after `Parse()` — the named-block approach is a first-class `Template.Lookup()` call with no string-matching fragility. Verified: comments cannot be extracted post-parse; named blocks can. |
| Per-stream `hookRunner`-style struct (one instance per watcher) | Shared broadcast/"generation" channel, one per server, watchers select on it | A `hookRunner` clone per watcher works but re-implements mutex+pending+channel bookkeeping N times. A single `sync.Mutex`-guarded "current generation channel" (closed and replaced on each write, à la `sync.Cond` broadcast) lets any number of watcher goroutines wake concurrently with zero per-watcher state beyond "which channel am I currently holding" — see Pattern section. |

**Installation:** No new packages. All required imports already exist as direct or transitive dependencies of `go.mod`.

**Version verification:**

```text
$ grep -A1 'google.golang.org/grpc ' go.mod
	google.golang.org/grpc v1.83.0
$ grep -A1 'go.opentelemetry.io/otel/metric ' go.mod
	go.opentelemetry.io/otel/metric v1.44.0
```

`go doc` against the vendored module tree confirms `peer`, `credentials.TLSInfo`, and `keepalive` all resolve inside this exact pinned version (see Sources).

## Package Legitimacy Audit

No external packages are being newly introduced by this phase — every library referenced above is already present in `go.mod` (direct) or resolves as a transitive dependency of `google.golang.org/grpc`/`go.opentelemetry.io/otel` already pinned there. The gate does not apply.

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| — | — | — | — | — | — | No new packages required |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```text
                    ┌─────────────────────────── Server process ───────────────────────────┐
                    │                                                                        │
 AddHost/UpdateHost/│   ┌──────────────┐      ┌───────────────────┐      ┌────────────────┐ │
 DeleteHost/Import  │──▶│ CommandHandler│─────▶│ regenerateOutputs │─────▶│ changeNotifier  │ │
 RollbackToSnapshot │   │ (write path)  │      │ (service.go:122)  │      │ (NEW — closes   │ │
                    │   └──────────────┘      └───────────────────┘      │ + replaces a    │ │
                    │                                                     │ broadcast chan) │ │
                    │                                                     └────────┬────────┘ │
                    │                                                              │          │
                    │                          ┌───────────────────────────────────┘          │
                    │                          ▼ (fan-out: N watcher goroutines wake)          │
                    │                 ┌──────────────────┐     ┌─────────────────────────┐    │
                    │                 │ store.ListAll()   │────▶│ per-entry domainToProto │    │
                    │                 │ (event-sourced     │     │ (existing helper)       │    │
                    │                 │  fold — NOT lazy)  │     └───────────┬─────────────┘    │
                    │                 └──────────────────┘                  │                  │
                    │                                          stream.Send  ▼ (one HostEntry    │
                    │                                          per message, gRPC flow-controlled)│
                    │  ┌──────────────────────────────────────────────────────────────────┐    │
                    │  │ Watch RPC (bidi) — one goroutine sends snapshots, another Recv's  │    │
                    │  │ client status reports; peer.FromContext → TLSInfo → CN            │    │
                    │  └──────────────────────────────────┬───────────────────────────────┘    │
                    │                                      │ last-seen / last-success            │
                    │                          ┌───────────▼────────────┐                       │
                    │                          │ in-memory map[CN]time   │──▶ Int64ObservableGauge│
                    │                          │ (survives stream close,│    (pull-based, keyed  │
                    │                          │  lost on restart, D-10)│    by CN, D-13)        │
                    │                          └─────────────────────────┘                       │
                    └────────────────────────────────────────┬───────────────────────────────────┘
                                                              │ mTLS gRPC stream
                                                              ▼
                    ┌─────────────────────────── CLI (consumer) process ────────────────────────┐
                    │  Recv loop (bounded, TMPL-07 cap) → accumulate []HostEntry                 │
                    │        │                                                                    │
                    │        ▼                                                                    │
                    │  Build template.Data{Entries, Count, GeneratedAt, ContractVersion}          │
                    │        │                                                                    │
                    │        ▼                                                                    │
                    │  tmpl.Lookup("contract_version") → compare to Data.ContractVersion (D-05)   │
                    │        │ (mismatch → refuse to run, exit nonzero)                            │
                    │        ▼                                                                    │
                    │  tmpl.Execute(&buf, data)  — render to buffer, NEVER stream to file (D-12)   │
                    │        │ (render error → discard buf, previous artifact untouched)           │
                    │        ▼                                                                    │
                    │  atomicfile.Write(path, buf.Bytes())  — CreateTemp→Write→Sync→Close→Rename   │
                    │        │                                                                    │
                    │        ├─▶ sidecar status file (<artifact>.status) written atomically (D-11)│
                    │        └─▶ post-write exec hook (D-16), sh -c, mirrors server hook pattern   │
                    └────────────────────────────────────────────────────────────────────────────┘
```

### Recommended Project Structure

```text
internal/
├── atomicfile/              # NEW — relocated atomicWriteFile + its 4 tests
│   └── atomicfile.go
├── server/
│   ├── service.go            # add Watch RPC handler; ExportHosts becomes per-entry stream.Send
│   ├── changenotify.go       # NEW — broadcast/generation-channel primitive, wired into regenerateOutputs
│   ├── sinkmetrics.go        # NEW (or extend metrics.go) — per-CN last-seen/last-success gauges + map
│   └── peercn.go             # NEW — peer.FromContext → CN extraction helper
├── client/
│   ├── template/             # NEW — template.Data struct, contract-version parsing, Option("missingkey=error")
│   │   └── template.go
│   └── commands/
│       ├── template.go       # NEW — `export --template` (one-shot) Cobra command
│       └── watch.go          # NEW — `watch --template --out --exec` (sink) Cobra command
proto/router_hosts/v1/
└── hosts.proto                # additive: new Watch RPC + request/response messages
```

### Pattern 1: Genuinely concurrent bidi stream (Watch RPC)

**What:** Server handler spawns a dedicated goroutine for `stream.Send` (snapshot pushes,
triggered by the change notifier) while the RPC goroutine itself owns `stream.Recv`
(client status reports). Coordinated shutdown via `sync.WaitGroup` + a single error
channel; the first error from either side cancels a per-stream `context.Context` that
both goroutines select on.
**When to use:** Any RPC where client and server must both send independently and
concurrently, unlike `ImportHosts`'s drain-then-respond shape.
**Example:**

```go
// Source: grpc-go concurrency contract — CITED:
// https://github.com/grpc/grpc-go/blob/master/Documentation/concurrency.md
// "it's safe to have a goroutine calling SendMsg and another goroutine calling
//  RecvMsg on the same stream at the same time... it is not safe to call SendMsg
//  on the same stream in different goroutines, or to call RecvMsg ... in different
//  goroutines."
func (s *HostsServiceImpl) Watch(stream grpc.BidiStreamingServer[hostsv1.WatchRequest, hostsv1.WatchResponse]) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	cn := commonNameFromContext(ctx) // see Pattern 4
	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { // sender: wakes on change notifications, sends coalesced snapshots
		defer wg.Done()
		ch := s.changes.Subscribe()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-ch:
				ch = s.changes.Subscribe() // re-subscribe to the *new* generation channel
				entries, err := s.store.ListAll(ctx)
				if err != nil {
					errCh <- err
					return
				}
				for i := range entries {
					if err := stream.Send(&hostsv1.WatchResponse{Entry: domainToProto(&entries[i])}); err != nil {
						errCh <- err
						return
					}
				}
			}
		}
	}()

	// receiver: runs on this goroutine, reports client status upstream
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cancel()
			break
		}
		s.sinkHealth.RecordStatus(cn, req) // updates in-memory map[CN]time.Time — D-09/D-10
	}
	cancel()
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
```

### Pattern 2: Broadcast/"generation channel" coalescing (NOT the hookRunner shape)

**What:** A tiny primitive that lets N independent watcher goroutines each "wait for
the next change" without a per-watcher queue. `hookRunner` (`internal/server/hookrunner.go`)
is a **process-wide singleton** with a single pending slot — reusing it as-is for N
concurrent Watch streams would require either one `hookRunner` instance per stream
(re-implementing its mutex/pending/trigger bookkeeping N times) or funneling all
watchers through one shared instance (which breaks per-stream independence — a slow
watcher would block others' pending updates from being distinguished). The broadcast
channel is simpler and is the idiomatic Go substitute for `sync.Cond.Broadcast()`:
**When to use:** Fan-out notification to an unknown, changing set of subscribers, where
each subscriber independently reads current state after waking (as opposed to
`hookRunner`'s single consumer that needs to know exactly what data was superseded).
**Example:**

```go
// changeNotifier is safe for concurrent use. Notify() is called from
// regenerateOutputs (service.go:122) after every mutation. Subscribe() returns
// a channel that closes exactly once, the next time Notify() runs — closing a
// channel is a broadcast primitive in Go: every goroutine selecting on it wakes
// simultaneously, whether there are 0 or 1000 subscribers.
type changeNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func newChangeNotifier() *changeNotifier {
	return &changeNotifier{ch: make(chan struct{})}
}

func (n *changeNotifier) Subscribe() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ch
}

func (n *changeNotifier) Notify() {
	n.mu.Lock()
	defer n.mu.Unlock()
	close(n.ch)
	n.ch = make(chan struct{})
}
```

This naturally coalesces bursts exactly like D-06 requires: if `Notify()` fires 5 times
while a watcher is mid-`ListAll()`+send, the watcher's next `Subscribe()` call returns
the *current* (post-burst) channel — it never queues 5 separate wakeups, and it always
renders the latest state, never an intermediate one.
**`[ASSUMED]`** — this specific primitive is not implemented anywhere in this repo
today; it is a standard Go idiom (channel-close-as-broadcast) but has not been verified
against this codebase's exact concurrency requirements under test. Flag for
`checkpoint:human-verify` on the race-detector run (`task test` already runs `-race`).

### Pattern 3: Contract-version declaration via named template block

**What:** Require every consumer template to include a `{{define "contract_version"}}N{{end}}`
block. The CLI parses the whole template, looks up that named sub-template, executes
it standalone (no data needed) to get the declared version string, and compares it to
the server's advertised `ContractVersion` (D-05) *before* executing the main template
body.
**When to use:** Any time template metadata must be extracted without executing the
main render (which may depend on data not yet available, or which you want to fail
before, not during).
**Example — verified working via local execution:**

```go
// Source: local verification (go1.26.5, text/template stdlib) — see Sources
const src = `{{define "contract_version"}}1{{end}}{{range .Entries}}{{.Hostname}}
{{end}}`

tmpl, err := template.New("main").Option("missingkey=error").Parse(src)
if err != nil { /* parse error: malformed template, fail loudly */ }

verTmpl := tmpl.Lookup("contract_version")
if verTmpl == nil {
	return fmt.Errorf("template does not declare a contract_version block")
}
var buf bytes.Buffer
if err := verTmpl.Execute(&buf, nil); err != nil { /* ... */ }
declared := strings.TrimSpace(buf.String())
if declared != currentContractVersion {
	return fmt.Errorf("template targets contract version %q, server serves %q", declared, currentContractVersion)
}
// only now: tmpl.Execute(&mainBuf, data)
```

Verified output: `declared version: 1`, then `rendered main: a.local` — both the
version-block lookup and the main-body render work independently against the same
parsed `*template.Template`.

### Pattern 4: mTLS CN extraction from a gRPC stream context

**What:** `peer.FromContext(ctx)` → `p.AuthInfo.(credentials.TLSInfo)` →
`tlsInfo.State.VerifiedChains[0][0].Subject.CommonName`.
**When to use:** Any server-side RPC handler that needs to key state by the calling
consumer's identity (D-09/D-13's cardinality-safety requirement: label by verified CN,
never by anything the caller supplies in the request body).
**Example:**

```go
// Source: [VERIFIED: go doc google.golang.org/grpc/peer, go doc
// google.golang.org/grpc/credentials TLSInfo] — both resolved against the
// exact pinned google.golang.org/grpc v1.83.0 in this repo's module cache.
func commonNameFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", oops.Errorf("no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", oops.Errorf("connection is not TLS-authenticated")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", oops.Errorf("no verified client certificate chain")
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, nil
}
```

This is safe because the server's TLS config already sets
`ClientAuth: tls.RequireAndVerifyClientCert` (`internal/server/server.go:207`,
`[VERIFIED: internal/server/server.go:207]` — quoted: `ClientAuth:     tls.RequireAndVerifyClientCert,`)
— a connection cannot reach the RPC handler at all without a CA-verified client cert,
so `VerifiedChains` is guaranteed non-empty for any request that gets this far; the nil
checks above are defensive, not load-bearing.

### Anti-Patterns to Avoid

- **Streaming template output directly to the artifact file:** D-12 requires the
  previously written artifact to be left byte-identical on *any* failure, including a
  mid-render template error. `Execute` writing straight to an `os.File` opened for the
  final path would leave a truncated/partial file on error. Always `Execute` into a
  `bytes.Buffer` (or an in-memory writer) first; only call the atomic-write helper once
  rendering has fully succeeded.
- **Relying on `missingkey=error` as the sole fail-loud mechanism:** it only guards map
  lookups. If a future contract revision represents `.Entries[].Tags` or metadata as a
  `map[string]any` instead of a typed struct field, this option becomes load-bearing;
  today, with D-03/D-04's struct-based contract, it is a secondary guard, not primary.
- **Copying `hookRunner`'s single-pending-slot shape per watcher:** see Pattern 2 — it
  works but is unnecessary bookkeeping; prefer the broadcast-channel primitive.
- **Treating `ExportHosts` laziness as a storage-layer change:** `store.ListAll()`
  cannot become a true streaming cursor without adding a new `HostProjection` method
  backed by a materialized SQL table — that is out of this phase's scope (see Summary).
  Do not let a plan quietly expand into a storage-layer rewrite to satisfy TMPL-06;
  satisfy it at the transport/serialization layer instead, and flag the deeper
  limitation to the user explicitly.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Atomic file write | A new write-and-rename implementation client-side | Relocate the existing `atomicWriteFile` (`internal/server/hostsfile.go:133-164`) to a shared package | Already has 4 passing tests (`hostsfile_test.go:181-227`) covering new-file, overwrite, temp-cleanup, invalid-path; zero external deps |
| Broadcast/fan-out notification | A pub-sub library or message broker | The channel-close-as-broadcast idiom (Pattern 2) | Standard library primitive; no new dependency; matches the in-process, single-binary deployment model |
| Contract-version metadata extraction | Regex scanning of raw template source | `Template.Lookup("contract_version")` + independent `Execute` | Uses the parser's own named-template mechanism; regex-over-source is fragile against comment/whitespace variance and duplicates work the stdlib already does |
| Per-consumer health state | A new time-series store or external cache | `Int64ObservableGauge` + `RegisterCallback`, exactly as `RegisterAggregateEventGauges` already does (`internal/server/metrics.go:301-349`) | Existing precedent in this exact codebase for pull-based, source-of-truth-backed gauges; avoids re-solving cardinality safety from scratch |
| CLI post-write hook execution | A new subprocess-management abstraction | `exec.CommandContext(ctx, "sh", "-c", cmd)`, mirroring `internal/server/hooks.go:197` | Identical shape already reviewed and tested server-side; reuse the pattern (timeout via context, not a new mechanism) |

**Key insight:** Every piece of new machinery this phase needs has a structurally
identical precedent already living in this codebase (coalescing → hookRunner's
mutex+pending pattern generalizes to a broadcast channel; observable per-key gauges →
`RegisterAggregateEventGauges`; atomic writes → `atomicWriteFile`; subprocess hooks →
`HookExecutor.executeHook`). The risk in this phase is not "we don't know how to build
this," it's "don't reinvent a shape that already exists two files away, and don't
reuse a shape (`hookRunner`) whose singleton design doesn't fit the new N-consumer
fan-out requirement."

## Common Pitfalls

### Pitfall 1: `missingkey=error` gives false confidence about fail-loud rendering

**What goes wrong:** A planner or reviewer assumes `Option("missingkey=error")` is
what makes TMPL-03 ("a template referencing an undefined key fails loudly") work, sets
it, and stops there — while the real protection (struct-typed `Entries`) is a separate
decision (D-03/D-04) that must independently hold.
**Why it happens:** The option's name strongly suggests it covers "any undefined key,"
but its documented and verified scope is map indexing only.
**How to avoid:** Keep the template data model 100% struct-typed (no `map[string]any`
anywhere in `template.Data` or its nested types); set the option anyway for defense in
depth; add a unit test asserting a struct-field typo produces a Go error from
`Execute`, not silent empty output.
**Warning signs:** Any future field added to the contract as a `map[string]string`
instead of a named struct field.

### Pitfall 2: Sink health metrics look "live" but keepalive is unconfigured

**What goes wrong:** D-09/D-10's last-seen timestamp is designed to "convert stream
absence into a measurable age," but with no keepalive configured, gRPC's default
server-side ping interval is **2 hours** (`ServerParameters.Time` default,
`[VERIFIED: go doc google.golang.org/grpc/keepalive]`) — a dead TCP connection with no
in-flight application data can go undetected for a very long time, especially over a
NAT/firewall that silently drops idle connections without an RST. A watcher whose
network died would appear "alive" (no error surfaced on either side) for far longer
than an operator would expect from a metric called `last_seen`.
**Why it happens:** This repo has never configured `grpc.KeepaliveParams`/
`grpc.KeepaliveEnforcementPolicy` server-side or `grpc.WithKeepaliveParams`
client-side — confirmed via `rg` returning zero hits for `keepalive` across
`internal/server` and `internal/client`.
**How to avoid:** Configure explicit keepalive on both sides for the Watch RPC's
connection (e.g., server `Time: 30s, Timeout: 10s`; client `Time: 20s, Timeout: 10s,
PermitWithoutStream: true` so pings continue even with no host mutations in flight).
Additionally, have the client send an application-level status message on its own
fixed interval (independent of host data changes) so `RecordStatus` updates
`last-seen` predictably even during long quiet periods — this is arguably the primary
mechanism per D-07/D-09 ("the sink reports status upstream"), with keepalive as a
secondary, transport-level backstop for true network partition detection.
**Warning signs:** `router_hosts_sink_last_seen_timestamp_seconds` staying fresh for a
consumer that has actually lost network connectivity.

### Pitfall 3: The unbound/dnsmasq injection class re-opens at the consumer-template layer

**What goes wrong:** `sanitizeCommentField` (`internal/server/hostsfile.go:119-129`)
exists specifically because a `Comment` or `Tag` containing a newline could break out
of a single-line `#` comment and inject active directives into the *server-generated*
hosts/dnsmasq/unbound files (GH #349 finding router-hosts-00b.2). Once rendering moves
client-side (D-01), the template contract hands `Comment`/`Tags` to the **consumer's**
template as raw field values — the server-side sanitizer does not run on this new
path. If a consumer's template embeds `.Comment` directly into an `unbound.conf`
directive without escaping, the exact same injection class re-opens, just at the
consumer's template author's responsibility instead of router-hosts's.
**Why it happens:** `text/template`'s documented security model explicitly assumes
"template authors are trusted" and does **not** auto-escape output
(`[CITED: text/template package doc, "Package template"]` — quoted: "The security
model used by this package assumes that template authors are trusted. The package
does not auto-escape output..."). That's correct for D-01's threat model (the
consumer authors their own template), but the *data* (`Comment`/`Tags`) can still
contain attacker-influenced content if any router-hosts caller with write access is
less trusted than the template author.
**How to avoid:** Document explicitly in the TMPL-02 contract spec that `Comment` and
`Tags` are delivered **raw/unsanitized** and that consumer templates embedding them
into a config-file syntax are responsible for their own escaping — this is a
compatibility-surface decision, not an implementation bug, and belongs in the same
document that defines the field set (D-04).
**Warning signs:** A future security review flags newline/directive injection in a
consumer-authored unbound/dnsmasq template as if it were a router-hosts bug, when the
threat model has explicitly moved that responsibility client-side.

### Pitfall 4: `ImportHosts` is not a template for the Watch RPC's concurrency

**What goes wrong:** Assuming "we already have a bidi RPC, just copy its shape" leads
to a sequential recv-then-send implementation that cannot satisfy D-06/D-07 (server
must push snapshots *while* the client is free to send status reports at any time,
not only after the server has finished draining an initial batch).
**Why it happens:** `ImportHosts` (`internal/server/service.go:441-599`) is a
client-streaming-with-progress-updates RPC that happens to use the same
`grpc.BidiStreamingServer[Req,Resp]` Go type as a true full-duplex RPC would — the
type signature looks identical, but the usage pattern (drain all `Recv()` first, then
loop `Send()`) is fundamentally sequential, not concurrent.
**How to avoid:** Build Watch with two goroutines from the start (Pattern 1); do not
attempt to adapt `ImportHosts`'s loop shape.
**Warning signs:** A Watch implementation where `stream.Recv()` calls never interleave
with unprompted `stream.Send()` calls — i.e., the server only sends in direct response
to something it just received, rather than asynchronously on a write elsewhere in the
system.

## Code Examples

Verified patterns from official sources and local execution:

### Confirming struct-field typos already fail loudly (no `missingkey` needed)

```text
$ go run tmpltest.go
struct typo err: template: t:1:20: executing "t" at <.Hostnaem>: can't evaluate field Hostnaem in type main.Entry
map missing key err: template: t2:1:2: executing "t2" at <.Foo>: map has no entry for key "Foo"
map missing key (default) err: <nil>
```

`[VERIFIED: local execution, go1.26.5 text/template]`

### `missingkey` option semantics, verbatim from `go doc`

```text
missingkey: Control the behavior during execution if a map is indexed with a
key that is not present in the map.

    "missingkey=default" or "missingkey=invalid"
    	The default behavior: Do nothing and continue execution.
    	If printed, the result of the index operation is the string
    	"<no value>".
    "missingkey=zero"
    	The operation returns the zero value for the map type's element.
    "missingkey=error"
    	Execution stops immediately with an error.
```

`[VERIFIED: go doc text/template Option, go1.26.5]`

### Concurrent stream Send/Recv contract, verbatim

```text
it's safe to have a goroutine calling SendMsg and another goroutine calling
RecvMsg on the same stream at the same time.
it is not safe to call SendMsg on the same stream in different goroutines, or
to call RecvMsg on the same stream in different goroutines.
```

`[CITED: https://github.com/grpc/grpc-go/blob/master/Documentation/concurrency.md]`

### Existing per-entry streaming precedent (reuse this shape for the new Watch RPC and for lazy `ExportHosts`)

```go
// Source: internal/server/service.go:319-330 (existing, unmodified)
func (s *HostsServiceImpl) ListHosts(req *hostsv1.ListHostsRequest, stream grpc.ServerStreamingServer[hostsv1.ListHostsResponse]) error {
	entries, err := s.handler.ListHosts(stream.Context())
	if err != nil {
		return mapError(err)
	}
	for i := range entries {
		if err := stream.Send(&hostsv1.ListHostsResponse{
			Entry: domainToProto(&entries[i]),
		}); err != nil {
			return err
		}
	}
	return nil
}
```

### Existing observable-gauge precedent (reuse this shape for per-CN last-seen)

```go
// Source: internal/server/metrics.go:301-348 (existing, unmodified)
func (m *Metrics) RegisterAggregateEventGauges(store storage.EventStore, warnThreshold int64) error {
	if m.meterProvider == nil || store == nil {
		return nil
	}
	meter := m.meterProvider.Meter("router-hosts")
	maxGauge, err := meter.Int64ObservableGauge("router_hosts_aggregate_events_max", /* ... */)
	// ...
	_, err = meter.RegisterCallback(
		func(ctx context.Context, o otelmetric.Observer) error {
			// pull current state from the source of truth at scrape time
			// ...
			o.ObserveInt64(maxGauge, maxCount)
			return nil
		},
		maxGauge, overGauge,
	)
	return err
}
```

The new per-CN last-seen gauge should follow this exact shape: an
`Int64ObservableGauge` whose `RegisterCallback` iterates the in-memory
`map[string]time.Time` (keyed by CN) at scrape time, rather than a synchronous
`.Record()` call from inside the RPC handler — this is what makes D-10's "state
survives the stream closing" requirement compatible with OTel's pull model: the map
is the durable (in-process) source of truth, the gauge just projects it.

### Existing bounded-size precedent (reuse this error shape for TMPL-07's client-side cap)

```go
// Source: internal/server/service.go:438,458-460 (existing, unmodified — server-side
// precedent for "fail loudly with a clear limit, never truncate silently")
const maxImportBytes = 64 * 1024 * 1024 // 64 MiB
// ...
if buf.Len() > maxImportBytes {
	return status.Errorf(codes.ResourceExhausted, "import payload exceeds maximum size (%d bytes)", maxImportBytes)
}
```

The client-side TMPL-07 cap needs the same shape (clear message naming the limit and
how to raise it, per D-14) but returns a plain `oops`-wrapped Go error rather than a
gRPC status code, since the client is refusing to *accumulate* a response it already
received, not rejecting an inbound RPC.

### Existing subprocess-hook precedent (reuse for D-16's client post-write exec hook)

```go
// Source: internal/server/hooks.go:197 (existing, unmodified)
cmd := exec.CommandContext(hookCtx, "sh", "-c", hook.Command)
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Server renders all output formats (`hosts`, `dnsmasq`, `unbound`) in-process | Consumer supplies and runs its own template client-side | This phase (v0.13.0 Phase 1) | New resolver formats no longer require an upstream code change (#364) |
| `ExportHosts` sends the entire formatted payload in one `stream.Send` | Per-entry streaming (matching `ListHosts`'s existing shape) | This phase (TMPL-06) | Bounds wire memory per message; enables client backpressure via gRPC flow control — does not change the `ListAll()` read itself |
| Client streams (`collectHostStream`, `collectSnapshotStream`, etc.) `append` without limit | Bounded accumulation with a configurable, fail-loud cap | This phase (TMPL-07) | Prevents a malicious/buggy server from exhausting client memory |

**Deprecated/outdated:** None — this phase adds a new client-rendering path
alongside the existing `ExportHosts` `hosts`/`json`/`csv` formats, which explicitly
keep their current behavior (CONTEXT.md "Not in scope").

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | A shared "generation/broadcast channel" primitive (Pattern 2) is the right coalescing shape for N concurrent watchers, in preference to a `hookRunner`-per-stream clone | Architecture Patterns, Pattern 2 | If wrong, the planner should fall back to a per-stream `hookRunner` clone — functionally equivalent, just more bookkeeping. Low risk; both are correct, this is a design-quality judgment, not a correctness question. |
| A2 | Recommended keepalive values (server `Time: 30s, Timeout: 10s`; client `Time: 20s, Timeout: 10s, PermitWithoutStream: true`) are reasonable starting defaults for this deployment's scale | Common Pitfalls, Pitfall 2 | If too aggressive, could add unnecessary network chatter on constrained/battery-powered consumer devices; if too lax, last-seen staleness detection is slower than desired. These are tunable config values, not structural risks — should be exposed as config, not hardcoded. |
| A3 | A new `internal/atomicfile` package (rather than e.g. folding it into `internal/domain` or `internal/config`) is the right relocation target for `atomicWriteFile` | Recommended Project Structure, Don't Hand-Roll | CONTEXT.md explicitly leaves this as "Claude's Discretion" — the planner may choose a different package name/location; the constraint that matters (importable by both `internal/server` and `internal/client` without a new cross-import) is verified, the specific name is not. |
| A4 | The client-side TMPL-07 cap should be entry-count based by default (mirroring `maxImportBytes`'s byte-based precedent, but Count is already a first-class contract field per D-03) rather than byte-budget based | Code Examples | CONTEXT.md explicitly leaves the cap's unit as "Claude's Discretion." If the planner picks byte-budget instead, the error-message shape (Code Examples) still applies; only the comparison value changes. |

## Open Questions

1. **Where does `ExportHosts`'s existing behavior draw the TMPL-06 scope line?**
   - What we know: `store.ListAll()` is a full event-sourced fold with no cursor API;
     changing that would be a storage-layer project, not scoped by CONTEXT.md or
     REQUIREMENTS.md's TMPL-06 wording ("ExportHosts and sink streaming yield lazily
     (O(1) memory, client backpressure)").
   - What's unclear: whether "O(1) memory" is meant literally (impossible without a
     storage-layer cursor) or whether it's shorthand for "don't buffer the whole
     serialized response in one `[]byte` before sending" (achievable at the transport
     layer, per Pattern/Code Examples above).
   - Recommendation: the plan should state explicitly which of these two it is
     delivering, and record the storage-layer limitation as a known, accepted gap
     (potentially a `HIST`-style v2 backlog item) rather than silently narrowing scope
     without saying so.

2. **Should the Watch RPC reuse `ExportHosts`'s request shape (format string:
   `hosts`/`json`/`csv`) or introduce a new, template-only response message?**
   - What we know: CONTEXT.md leaves "concrete RPC and message names, and whether
     one-shot export reuses the watch RPC or gets its own" as Claude's discretion.
   - What's unclear: whether one-shot `export --template` should call `ExportHosts`
     (which currently only supports the three fixed formats) or a dedicated new RPC
     that always returns the structured `HostEntry` stream (letting the CLI apply
     *any* template, one-shot or watch, through the same data path).
   - Recommendation: a single new RPC (e.g. `WatchHosts` used in both one-shot and
     streaming CLI modes, client just closes after the first snapshot for one-shot)
     avoids duplicating the entry-streaming logic between `ExportHosts` and a new
     Watch RPC, and keeps `ExportHosts`'s three fixed formats completely untouched per
     the explicit out-of-scope note.

## Environment Availability

Skipped — this phase has no new external tool/service dependencies. `text/template`,
`os/exec`, and the gRPC/OTel packages are all either stdlib or already-vendored
dependencies confirmed present in `go.mod` and the local module cache (`go doc`
resolved every referenced package against the pinned versions with no network access
required beyond the existing module cache).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `stretchr/testify` (assert/require) + `pgregory.net/rapid` (property-based, already a direct dependency) |
| Config file | none — plain `go test`, invoked via Taskfile |
| Quick run command | `task test -- -run TestX ./internal/server/` (or `./internal/client/...`) |
| Full suite command | `task test` (== `go test -race -count=1 ./...`, `Taskfile.yml:21-26`) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TMPL-01 | Template renders host data with no code change | unit | `task test -- -run TestTemplate_Render ./internal/client/template/` | ❌ Wave 0 |
| TMPL-02 | Documented/versioned field set (`.Entries[].IPAddress/Hostname/Aliases/Tags/Comment`) | unit | `task test -- -run TestTemplateData_FieldSet ./internal/client/template/` | ❌ Wave 0 |
| TMPL-03 | Undefined key fails loudly; failure leaves prior artifact byte-identical | unit | `task test -- -run TestTemplate_UndefinedKeyFails ./internal/client/template/`; `task test -- -run TestRender_FailurePreservesArtifact ./internal/client/commands/` | ❌ Wave 0 |
| TMPL-04 | Atomic write-and-rename; no partial-write observable | unit (already exists for the source impl) | `task test -- -run TestAtomicWrite ./internal/atomicfile/` (relocated from `internal/server/hostsfile_test.go:181-227`) | ⚠️ exists in old location, moves in this phase |
| TMPL-05 | Sink holds artifact current without polling; recovers after connection interruption without truncation | integration (in-process bidi stream, bufconn) | `task test -- -run TestWatch_ReconnectNoTruncation ./internal/server/` and a CLI-side equivalent in `./internal/client/commands/` | ❌ Wave 0 |
| TMPL-06 | `ExportHosts`/Watch stream yields lazily; client applies backpressure | integration | `task test -- -run TestExportHosts_StreamsPerEntry ./internal/server/`; existing `ExportHosts` format tests must still pass unmodified (regression gate) | ❌ Wave 0 (new); ✅ existing format tests already present in `internal/server/service_test.go` |
| TMPL-07 | Bounded client collection; clear error past cap, never silent truncation | unit | `task test -- -run TestCollectHostStream_CapExceeded ./internal/client/commands/` | ❌ Wave 0 |
| (regression) | `unbound_conf_path` and `ExportHosts` format strings unchanged | unit | `task test -- -run TestExportHosts ./internal/server/` (existing) | ✅ exists |

### Sampling Rate

- **Per task commit:** targeted `task test -- -run <TestName> <package>`
- **Per wave merge:** `task test` (full suite, `-race`)
- **Phase gate:** `task test:coverage:ci` (80% threshold) green, plus `task test:e2e` (build tag `e2e`, real mTLS, in-process) extended with at least one Watch-RPC round-trip before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `internal/atomicfile/atomicfile_test.go` — relocated from `internal/server/hostsfile_test.go:181-227`; covers TMPL-04
- [ ] `internal/client/template/template_test.go` — new; covers TMPL-01/02/03 (struct field typo failure, contract-version mismatch refusal, `.Count`/`.GeneratedAt` presence)
- [ ] `internal/server/watch_test.go` (or extend `service_test.go`) — new bufconn-based bidi test harness for TMPL-05/06 (reconnect-without-truncation, per-entry streaming)
- [ ] `internal/client/commands/watch_test.go` — new; covers TMPL-07 (bounded collection cap error path) and the D-12 byte-identical-on-failure guarantee at the CLI layer
- [ ] e2e: extend `e2e/e2e_test.go` with a `TestE2E_WatchSinkReconnect`-style real-mTLS scenario (build tag `e2e`) once the Watch RPC exists

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | mTLS client certificate (`tls.RequireAndVerifyClientCert`, `internal/server/server.go:207`) — unchanged by this phase; the new Watch RPC rides the same authenticated channel |
| V3 Session Management | no | No session/cookie concept; gRPC connection + per-RPC mTLS identity is the only "session" |
| V4 Access Control | no | This repo has no per-consumer authorization model beyond "possesses a CA-signed client cert" — unchanged by this phase; every authenticated client can Watch/Export |
| V5 Input Validation | yes | Template files are local, operator-supplied input (trusted per D-01's threat model); the *data* fed into them (`Comment`/`Tags`) is not sanitized for the consumer's target syntax — see Common Pitfalls, Pitfall 3. Contract-version string must be validated (exact match, not prefix/semver-range) before rendering. |
| V6 Cryptography | no (unchanged) | Existing mTLS/TLS 1.3 config governs the channel; this phase adds no new cryptographic operations |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Config-directive injection via `Comment`/`Tags` embedded raw in a consumer template targeting `unbound.conf`/`dnsmasq.conf`-like syntax | Tampering | Document (do not silently fix) that the contract delivers raw field values; consumer template authors are responsible for escaping into their target syntax, mirroring the trust model `text/template`'s own docs describe (`[CITED: text/template package doc]`) |
| Malicious/buggy server driving client OOM via an unbounded stream | Denial of Service | D-14's configurable, fail-loud client-side cap (TMPL-07); never silently truncate |
| Dead/partitioned sink connection reported as "healthy" due to unconfigured keepalive | (availability blind spot, not classic STRIDE) | Explicit `keepalive.ClientParameters`/`keepalive.ServerParameters` + `EnforcementPolicy` (Common Pitfalls, Pitfall 2) |
| Cardinality-unsafe metric labels (labeling by consumer-supplied string instead of verified identity) | Denial of Service (metrics-storage exhaustion) | D-13: label exclusively by the mTLS-verified CN (Pattern 4), never by any request-body field, mirroring ADR `router-hosts-vl8`'s existing cardinality-safety precedent |
| Partial/truncated artifact observed by a concurrent reader (e.g. a resolver reloading mid-write) | Tampering / availability | Atomic write-and-rename (TMPL-04) via relocated `atomicWriteFile`; render to buffer first, never stream to the final path (D-12) |

## Sources

### Primary (HIGH confidence)

- `internal/server/service.go:1-679` — `ExportHosts`, `ListHosts`, `SearchHosts`, `ImportHosts`, `regenerateOutputs`, `domainToProto` (read this session)
- `internal/server/hostsfile.go:1-165` — `atomicWriteFile`, `sanitizeCommentField`, `HostsFileGenerator.Regenerate` (read this session)
- `internal/server/hookrunner.go:1-169` — `hookRunner` coalescing shape (read this session)
- `internal/server/metrics.go:1-466` — all 8 existing OTel instruments, `RegisterAggregateEventGauges` pull-based gauge pattern, `StreamMetricsInterceptor` (read this session)
- `internal/server/hooks.go` (lines 40-207 inspected) — `HookExecutor.executeHook`'s `exec.CommandContext(hookCtx, "sh", "-c", hook.Command)` (read this session)
- `internal/storage/storage.go:51-140` — `EventStore`, `HostProjection`, `Storage` interfaces; confirms no cursor/paginated read method exists (read this session)
- `internal/storage/sqlite/projection.go:1-80` — `ListAll`'s event-sourced fold implementation, confirming the TMPL-06 storage-layer blocker (read this session)
- `internal/domain/host.go:10-26` — `HostEntry` struct fields (`IP`, `Hostname`, `Aliases`, `Comment`, `Tags`) (read this session)
- `internal/config/client.go:1-212` — `ClientConfig` shape, precedent for where a new collection-cap config field would live (read this session)
- `internal/server/server.go` (lines 180-215 inspected) — `buildTLSConfig`, confirms `ClientAuth: tls.RequireAndVerifyClientCert` (read this session)
- `internal/client/client.go:1-109` — confirms no keepalive configured client-side today (read this session)
- `proto/router_hosts/v1/hosts.proto:1-533` — existing RPC definitions, `ImportHosts`/`ExportHosts` signatures (read this session)
- `go doc google.golang.org/grpc/peer` (against pinned grpc v1.83.0 in local module cache) — `peer.FromContext`, `Peer.AuthInfo`
- `go doc google.golang.org/grpc/credentials TLSInfo` (against pinned grpc v1.83.0) — `TLSInfo.State`
- `go doc google.golang.org/grpc/keepalive` (against pinned grpc v1.83.0) — `ClientParameters`, `ServerParameters`, `EnforcementPolicy`, default 2h server ping interval
- `go doc text/template Option` and local execution of `tmpltest.go`/`tmplver.go` (go1.26.5) — `missingkey` semantics; struct-field-typo failure behavior; named-block contract-version lookup

### Secondary (MEDIUM confidence)

- https://github.com/grpc/grpc-go/blob/master/Documentation/concurrency.md — concurrent Send/Recv contract, fetched and quoted directly this session
- `text/template` package doc ("Package template") — "template authors are trusted... does not auto-escape output" — stdlib doc, standard knowledge, cited for the security-model framing in Pitfall 3

### Tertiary (LOW confidence)

- General WebSearch results on OTel observable-gauge cardinality/memory-growth behavior — confirms the general shape (`RegisterCallback`/`Registration.Unregister` for cleanup, cardinality limits exist) but did not surface a citable authoritative source for the exact per-key memory-retention behavior after a label's underlying entity disappears; the in-repo `RegisterAggregateEventGauges` precedent (HIGH confidence, read directly) is the actual basis for the recommended pattern, not this search.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new dependencies; every referenced package version-confirmed via `go doc` against the pinned module cache
- Architecture: HIGH for patterns directly precedented in this codebase (coalescing shape, observable gauges, atomic write, subprocess hooks); MEDIUM for the broadcast-channel primitive itself (idiomatic Go, but not yet implemented/tested in this repo — flagged A1)
- Pitfalls: HIGH — all four are either verified via direct code reading (keepalive absence, `ImportHosts`'s sequential shape, sanitizer scope) or verified via local execution (`missingkey` scope)

**Research date:** 2026-07-31
**Valid until:** 30 days (stable stdlib/grpc/OTel APIs; re-verify if `google.golang.org/grpc` or `go.opentelemetry.io/otel/*` are bumped to a new minor version before planning starts)
