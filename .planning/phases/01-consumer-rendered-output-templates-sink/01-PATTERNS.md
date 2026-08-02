# Phase 1: Consumer-Rendered Output (templates + sink) - Pattern Map

**Mapped:** 2026-07-31
**Files analyzed:** 12 new + 3 modified
**Analogs found:** 9 / 12 (3 genuinely novel — flagged below)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/atomicfile/atomicfile.go` | utility | file-I/O | `internal/server/hostsfile.go:133-164` (`atomicWriteFile`) | exact (verbatim relocation) |
| `internal/atomicfile/atomicfile_test.go` | test | file-I/O | `internal/server/hostsfile_test.go:181-227` | exact (verbatim relocation) |
| `internal/client/template/template.go` | service/transform | transform | `internal/server/hostsfile.go` (`FormatHostsFile` + `Regenerate`) | role-match (formatting logic), NO direct render-engine analog |
| `internal/client/template/template_test.go` | test | transform | `internal/server/hostsfile_test.go` (table tests) | role-match |
| `internal/server/watch.go` (or extend `service.go`) — `Watch` RPC handler | controller | streaming/event-driven | `internal/server/service.go:441` (`ImportHosts`, structural only) + `:319` (`ListHosts`, send idiom) | partial — structural shape only, concurrency is NOVEL |
| `internal/server/changenotify.go` | service | event-driven/pub-sub | `internal/server/hookrunner.go` (coalescing shape, NOT reusable as-is) | NO ANALOG — new primitive |
| `internal/server/peercn.go` | middleware/utility | request-response | none | NO ANALOG — new primitive |
| `internal/server/sinkmetrics.go` (or extend `metrics.go`) | service | event-driven | `internal/server/metrics.go:301-349` (`RegisterAggregateEventGauges`) | exact (observable-gauge shape) |
| `internal/client/commands/template.go` (`export --template`) | route/controller (Cobra) | request-response | `internal/client/commands/host.go:30-89` (`newHostAddCmd`) + `importexport.go` export cmd | role-match |
| `internal/client/commands/watch.go` (`watch` sink command) | route/controller (Cobra), long-lived | streaming | `internal/client/commands/serve.go` (long-lived loop, signal handling via `srv.Run(ctx)`) + `importexport.go:61-90` (client stream send/recv loop) | role-match |
| `proto/router_hosts/v1/hosts.proto` (new `Watch` RPC + messages) | config/schema | streaming | `hosts.proto:475-532` (`ImportHosts`/`ExportHosts` RPC decls) | exact (proto convention) |
| `internal/server/service.go` `ExportHosts` (modified, lazy per-entry) | controller | streaming (modified) | `internal/server/service.go:319-332` (`ListHosts`) | exact — this IS the target shape |
| `internal/server/watch_test.go` | test | streaming | `internal/server/service_test.go:33-77` (`newServiceTestEnv`, bufconn harness) | exact |
| `internal/client/commands/watch_test.go` | test | streaming | `internal/client/commands/testhelper_test.go` (bufconn-backed client test harness) | exact |

## Pattern Assignments

### `internal/atomicfile/atomicfile.go` (utility, file-I/O)

**Analog:** `internal/server/hostsfile.go:131-164` — move verbatim, only the package name and (optionally) an exported name change.

**Current implementation to relocate:**

```go
// atomicWriteFile writes content to a temp file in the target directory,
// fsyncs, then renames into place. Shared by all output-file generators.
func atomicWriteFile(path, content string) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return oops.Wrapf(err, "create temp file")
	}
	tmpPath := f.Name()

	_, writeErr := f.WriteString(content)
	if writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return oops.Wrapf(writeErr, "write file")
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "fsync file")
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "close file")
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "rename file")
	}

	return nil
}
```

Error style: every branch wraps with `oops.Wrapf(err, "<verb phrase>")` — no bare `fmt.Errorf`. Keep that exact convention in the new package.

**All call sites that must be updated after relocation (still in package `server`):**

- `internal/server/hostsfile.go:37` — `HostsFileGenerator.Regenerate`
- `internal/server/unboundconf.go` and `internal/server/dnsmasqconf.go` — same call pattern (`atomicWriteFile(g.path, content)`), confirm exact line via `rg` in that file at task time
- New client-side callers in `internal/client/template` / `internal/client/commands/watch.go` will call `atomicfile.Write(path, buf.Bytes())` (or whatever the exported name becomes — CONTEXT.md leaves the package name to discretion, but two-package-import compatibility from both `internal/server` and `internal/client` is the hard constraint)

**Tests to relocate verbatim** (rename package, keep bodies unchanged): `TestAtomicWrite_NewFile`, `TestAtomicWrite_OverwritesExisting`, `TestAtomicWrite_CleansUpTmp`, `TestAtomicWrite_InvalidPath` — `internal/server/hostsfile_test.go:181-227`. Each uses `t.TempDir()` (never real filesystem paths), `require.NoError`/`assert.Equal` from testify — keep this convention.

---

### `internal/client/template/template.go` (service/transform, transform)

**Analog:** `internal/server/hostsfile.go` `HostsFileGenerator` shape (constructor + format function), but the actual `text/template` execution machinery is genuinely new — RESEARCH.md's verified `Code Examples` section is the primary source, not an in-repo analog.

**Shape to follow from the generator pattern** (constructor holds config, one method does the work, atomic write at the end):

```go
// internal/server/hostsfile.go:18-41 — the generator shape to mirror
type HostsFileGenerator struct {
	path string
}

func NewHostsFileGenerator(path string) *HostsFileGenerator {
	return &HostsFileGenerator{path: path}
}

func (g *HostsFileGenerator) Regenerate(ctx context.Context, store storage.Storage) (int, error) {
	entries, err := store.ListAll(ctx)
	if err != nil {
		return 0, oops.Wrapf(err, "list hosts for regeneration")
	}
	content := g.FormatHostsFile(entries)
	if err := atomicWriteFile(g.path, content); err != nil {
		return 0, err
	}
	return len(entries), nil
}
```

**Contract-version + render pattern — copy from RESEARCH.md verbatim (verified locally, not yet in-repo):**

```go
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

**Critical constraint (D-12):** `Execute` MUST write into a `bytes.Buffer`, never directly to the destination file. Only call `atomicfile.Write` after `Execute` succeeds fully — this is the anti-pattern flagged explicitly in RESEARCH.md's "Anti-Patterns to Avoid".

**Error wrapping:** use `oops.Wrapf`/`oops.Errorf` (repo convention), not bare `fmt.Errorf` as shown in the research snippet — adapt during implementation.

**NO ANALOG** for: the `template.Data{Entries, Count, GeneratedAt, ContractVersion}` struct itself (D-03) and the missingkey/contract-version enforcement — this is new domain logic for this phase.

---

### `internal/server/watch.go` — `Watch` RPC handler (controller, streaming/event-driven)

**Analog (structural shape only — NOT concurrency template):** `internal/server/service.go:319-332` (`ListHosts`, the `stream.Send` + `mapError` idiom) and `:441-599` (`ImportHosts`, proves `grpc.BidiStreamingServer[Req,Resp]` compiles/wires in this codebase).

**`stream.Send` + `mapError` idiom to copy** (from `ListHosts`):

```go
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

**`mapError` — reuse directly, do not reimplement:**

```go
// internal/server/service.go:175-187
func mapError(err error) error {
	if oopsErr, ok := oops.AsOops(err); ok {
		code, _ := oopsErr.Code().(string)
		grpcCode := domain.GRPCCode(code)
		if grpcCode == codes.Internal {
			slog.Error("internal server error", "error", oopsErr)
			return status.Error(codes.Internal, "internal server error")
		}
		return status.Error(grpcCode, oopsErr.Error())
	}
	slog.Error("internal server error", "error", err)
	return status.Error(codes.Internal, "internal server error")
}
```

**Explicitly NOT a template — do not copy `ImportHosts`'s sequential drain-then-send loop.** RESEARCH.md Pitfall 4 flags this directly: `ImportHosts` (`service.go:441-599`) fully drains `stream.Recv()` before ever calling `stream.Send()`. The Watch RPC needs concurrent goroutines (one Send, one Recv) per the grpc-go concurrency contract. Use RESEARCH.md's Pattern 1 code block verbatim as the starting skeleton (goroutine pair, `sync.WaitGroup`, `errCh`, per-stream `context.WithCancel`).

**NO ANALOG in this repo** for the genuinely concurrent bidi shape — flag this as the highest-novelty file in the phase.

---

### `internal/server/changenotify.go` (service, event-driven/pub-sub)

**NO ANALOG.** `internal/server/hookrunner.go` has the nearest *conceptual* shape (coalescing a burst into one run) but is explicitly disqualified as a copy-source: it's a process-wide singleton with one pending slot, not a fan-out primitive for N independent watchers. RESEARCH.md Pattern 2 supplies the full recommended implementation (channel-close-as-broadcast) — use it directly since no in-repo precedent exists:

```go
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

Wire `Notify()` into `regenerateOutputs` (`internal/server/service.go:122-170`) alongside the existing generator/hook calls — same call site, one more line.

---

### `internal/server/peercn.go` (middleware/utility, request-response)

**NO ANALOG.** No production code path in this repo extracts the mTLS CN today (RESEARCH.md confirms only test fixtures set `CommonName`). Use RESEARCH.md's verified Pattern 4 directly:

```go
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

Note it already uses `oops.Errorf`, matching repo convention. Safe because `server.go:207` sets `ClientAuth: tls.RequireAndVerifyClientCert` — nil checks are defensive, not load-bearing.

---

### `internal/server/sinkmetrics.go` (or extend `metrics.go`) (service, event-driven)

**Analog:** `internal/server/metrics.go:301-349` (`RegisterAggregateEventGauges`) — exact shape match, this is the cardinality-safe pull-based-gauge precedent CONTEXT.md's D-13 cites directly.

```go
// internal/server/metrics.go:301-349
func (m *Metrics) RegisterAggregateEventGauges(store storage.EventStore, warnThreshold int64) error {
	if m.meterProvider == nil || store == nil {
		return nil
	}
	meter := m.meterProvider.Meter("router-hosts")

	maxGauge, err := meter.Int64ObservableGauge("router_hosts_aggregate_events_max",
		otelmetric.WithDescription("Maximum event count across all aggregates"),
	)
	if err != nil {
		return oops.Wrapf(err, "create aggregate_events_max gauge")
	}
	// ... second gauge ...

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o otelmetric.Observer) error {
			// pull current state from the source of truth at scrape time
			o.ObserveInt64(maxGauge, maxCount)
			o.ObserveInt64(overGauge, over)
			return nil
		},
		maxGauge, overGauge,
	)
	if err != nil {
		return oops.Wrapf(err, "register aggregate-event gauge callback")
	}
	return nil
}
```

**New per-CN gauge follows the exact same shape:** `Int64ObservableGauge` + `RegisterCallback` iterating an in-memory `map[string]time.Time` keyed by CN (never by caller-supplied strings, per D-13). The map is the durable source of truth; the gauge only projects it at scrape time — this is what makes D-10 ("state survives stream closing") compatible with OTel's pull model.

**Instrument registration convention** — every instrument construction in this file follows: `meter.<Kind>(<name>, otelmetric.WithDescription(...))` then `if err != nil { return oops.Wrapf(err, "create <name> <kind>") }`. Keep exact naming style: `router_hosts_sink_last_seen_timestamp_seconds`, etc. (illustrative names from CONTEXT.md, not locked).

**`DisabledMetrics()` must also be extended** (`metrics.go:206-229`) — every real instrument has a matching no-op instrument constructed via `noop.Meter{}` so metrics-disabled builds keep working; add the new gauges there too.

---

### `internal/client/commands/template.go` (`export --template`) (route/controller — Cobra, request-response)

**Analog:** `internal/client/commands/host.go:30-89` (`newHostAddCmd`) for command construction/flag registration, and `internal/client/commands/importexport.go` export command for the client-stream receive pattern.

**Cobra construction pattern to copy:**

```go
// internal/client/commands/host.go:30-89
func newHostAddCmd() *cobra.Command {
	var (
		ip       string
		hostname string
		// ...
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new host entry",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if err := c.Close(); err != nil {
					slog.Warn("closing client connection", "error", err)
				}
			}()
			ctx, cancel := commandContext()
			defer cancel()
			// ... RPC call, oops.Wrapf on error ...
		},
	}
	cmd.Flags().StringVar(&ip, "ip", "", "IP address (required)")
	_ = cmd.MarkFlagRequired("ip")
	return cmd
}
```

Note `commandContext()` (`host.go:330-333`) gives a fixed 30s timeout for one-shot RPCs — reuse for the one-shot export path, but the long-lived `watch` command (below) must NOT use this fixed-timeout helper.

**Bounded-collection error shape (TMPL-07) — copy exact structure, not exact code:**

```go
// internal/server/service.go:438,458-460 — server-side precedent for
// "fail loudly with a clear limit, never truncate silently"
const maxImportBytes = 64 * 1024 * 1024 // 64 MiB
if buf.Len() > maxImportBytes {
	return status.Errorf(codes.ResourceExhausted, "import payload exceeds maximum size (%d bytes)", maxImportBytes)
}
```

Client-side cap uses the same shape but returns a plain `oops`-wrapped error (not a gRPC status), since the client is refusing to accumulate a response it already received. Existing unbounded `append` loops to replace/bound:

```go
// internal/client/commands/host.go:343-359 (collectHostStream) — CURRENT, unbounded
func collectHostStream(stream hostsv1.HostsService_ListHostsClient) ([]*hostsv1.HostEntry, error) {
	var entries []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, oops.Wrapf(err, "receiving host entry")
		}
		if resp.GetEntry() != nil {
			entries = append(entries, resp.GetEntry())
		}
	}
	return entries, nil
}
```

Same unbounded shape also at `internal/client/commands/host.go:361-377` (`collectSearchStream`) and `internal/client/commands/snapshot.go:219`.

---

### `internal/client/commands/watch.go` (`watch` sink command) (route/controller, long-lived, streaming)

**Analog for long-lived process structure:** `internal/client/commands/serve.go` — the whole file is the shape (`RunE` builds dependencies, calls a `run*` function that blocks on `srv.Run(ctx)` until context cancellation/signal). No explicit signal-handling code exists in `serve.go` itself — it delegates to `srv.Run(ctx)`; if the watch command needs its own signal handling, note that as a genuinely new addition, not a copy.

**Analog for the client-side stream send/recv loop:** `internal/client/commands/importexport.go:61-90` (import command opens a client stream, then loops `stream.Send`):

```go
stream, err := c.Hosts.ImportHosts(ctx)
if err != nil {
	return oops.Wrapf(err, "starting import stream")
}
buf := make([]byte, importChunkSize)
firstChunk := true
for {
	n, readErr := file.Read(buf)
	if n > 0 {
		isLast := readErr == io.EOF
		req := &hostsv1.ImportHostsRequest{Chunk: buf[:n], LastChunk: isLast}
		// ...
		if sendErr := stream.Send(req); sendErr != nil {
			return oops.Wrapf(sendErr, "sending import chunk")
		}
	}
	// ...
}
```

Adapt this shape for the bidi Watch client: one goroutine `stream.Recv()`s snapshots (renders + atomic-writes on each), another (or the main goroutine) periodically `stream.Send()`s status reports — mirrors the server's genuinely concurrent Pattern 1, just from the other side of the wire.

**Cobra construction:** same `newClientFromFlags()` / `defer c.Close()` idiom as `host.go`, but `RunE` must NOT use `commandContext()`'s fixed 30s timeout — it needs a context tied to signal handling (`os/signal.NotifyContext` or similar), which has **no existing analog in this codebase** (`serve.go` relies on `cmd.Context()` from Cobra's root, populated upstream — check `root.go`/`main.go` for how that's wired before assuming it needs reinventing).

**D-16 post-write exec hook — reuse exact shape from server-side hook execution:**

```go
// internal/server/hooks.go:197
cmd := exec.CommandContext(hookCtx, "sh", "-c", hook.Command)
```

Mirror the timeout-via-context idiom (`hooks.go:187-190`) and the `hookCtx.Err()`-before-`err`classification for timeout-vs-failure (`hooks.go:206-220`) if the CLI hook needs the same distinction.

---

### `proto/router_hosts/v1/hosts.proto` (new `Watch` RPC) (config/schema, streaming)

**Analog:** existing RPC declarations, `hosts.proto:475-532`.

```proto
// Import/Export operations

// Import hosts from a file format via client streaming with server progress updates
rpc ImportHosts(stream ImportHostsRequest) returns (stream ImportHostsResponse);

// Export all hosts in a specified format via server streaming
rpc ExportHosts(ExportHostsRequest) returns (stream ExportHostsResponse);
```

Comment style: one-line `//` doc comment immediately above each RPC, imperative/descriptive, no period requirement seen consistently. Message field comments (see `AcmeHealth`/`HooksHealth` at `hosts.proto:455-473`) are similarly terse `//` lines per field.

**New RPC declaration convention to follow (additive; do not renumber existing fields/methods):**

```proto
rpc Watch(stream WatchRequest) returns (stream WatchResponse);
```

placed under a new `// Sink streaming` section, following the existing grouped-by-concern layout (`// Host management`, `// Import/Export operations`, `// Snapshots`, `// Health checks`).

**Regeneration:** run `task proto:generate` after editing — do not hand-edit `api/v1` generated stubs.

---

### `internal/server/service.go` `ExportHosts` (modified for TMPL-06 laziness)

**Analog — this IS the target shape to converge toward:** `internal/server/service.go:319-332` (`ListHosts`, per-entry `stream.Send`).

**Current `ExportHosts` (to be changed for the `hosts`-adjacent template/watch path, NOT for the existing `hosts`/`json`/`csv` formats — those stay byte-for-byte unchanged per CONTEXT.md's explicit out-of-scope note):**

```go
// internal/server/service.go:602-679 — current: builds one []byte blob, one Send
func (s *HostsServiceImpl) ExportHosts(req *hostsv1.ExportHostsRequest, stream grpc.ServerStreamingServer[hostsv1.ExportHostsResponse]) error {
	// ... builds `data []byte` for hosts/json/csv ...
	return stream.Send(&hostsv1.ExportHostsResponse{Chunk: data})
}
```

**Do not literally rewrite this function.** Per RESEARCH.md, TMPL-06's practical scope is the *new* Watch RPC / template data path streaming one `HostEntry` per `stream.Send` (matching `ListHosts`'s existing per-entry shape), not a rewrite of the three fixed `hosts`/`json`/`csv` formats which must keep their current single-`Send` behavior and passing tests (`internal/server/service_test.go:478-565`).

---

### Test harness files

**Analog:** `internal/server/service_test.go:33-77` (`newServiceTestEnv`) — the canonical bufconn-based in-process gRPC test harness in this repo.

```go
lis := bufconn.Listen(1024 * 1024)
srv := grpc.NewServer()
hostsv1.RegisterHostsServiceServer(srv, svc)
go func() { _ = srv.Serve(lis) }()
t.Cleanup(func() { srv.Stop() })

conn, err := grpc.NewClient(
	"passthrough:///bufconn",
	grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}),
	grpc.WithTransportCredentials(insecure.NewCredentials()),
)
```

Also present at `internal/client/commands/testhelper_test.go:20-61` (client-side variant, swaps `newClientFromFlags` for a bufconn-backed client) and `internal/operator/grpc_hostclient_test.go:23-44`. Reuse `newServiceTestEnv`-style setup for `internal/server/watch_test.go`; reuse `testhelper_test.go`'s `setupCmdTest` shape for `internal/client/commands/watch_test.go`.

**Test naming convention:** `TestService_<RPC>_<Scenario>` server-side (`TestService_ImportHosts_HostsFormat`, `TestService_ExportHosts_CSVFormat`), `Test<Feature>_<Scenario>` client-side. Uses `testify` `assert`/`require`, never writes to real filesystem (`t.TempDir()` throughout `hostsfile_test.go`), `sqlite.New("file::memory:?mode=memory&cache=shared", ...)` for an in-memory store in server tests.

## Shared Patterns

### Error wrapping (`samber/oops`)

**Source:** every file read this session (`hostsfile.go`, `service.go`, `metrics.go`, `hooks.go`)
**Apply to:** all new Go files in this phase, no exceptions

```go
return oops.Wrapf(err, "create temp file")     // wrap with context, lowercase, no trailing period
return oops.Errorf("no peer info in context")  // construct a new error with a code-free message
```

Server RPC handlers additionally convert `oops`-coded errors to gRPC status via the existing `mapError` (`service.go:175-187`) — reuse it directly for the Watch RPC rather than reimplementing.

### Logging (`log/slog`)

**Source:** `service.go:130-168`, `hooks.go` throughout
**Apply to:** server-side new files (`watch.go`, `changenotify.go`, `sinkmetrics.go`)

```go
slog.Error("hosts file regeneration failed", "op", op, "error", err)
slog.Warn("import completed with failures", "processed", stats.Processed, "failed", stats.Failed, "created", stats.Created)
```

Structured key-value pairs, not `fmt.Sprintf`-formatted messages. `internal/client/commands/serve.go` constructs its own JSON handler logger (`slog.NewJSONHandler(os.Stdout, ...)`) at the CLI entry point — the `watch` command should follow the same construction if it needs its own logger instance rather than a global.

### Observable gauge registration (OTel)

**Source:** `internal/server/metrics.go:301-349`
**Apply to:** `sinkmetrics.go`'s new per-CN last-seen/last-success gauges — see full excerpt in Pattern Assignments above. Also extend `DisabledMetrics()` (`metrics.go:206-229`) with matching no-op instruments for every new real one.

### Cardinality safety (D-13)

**Source:** ADR `router-hosts-vl8` (PROJECT.md) + `RegisterAggregateEventGauges`'s existing precedent of labeling by verified state (aggregate ID from storage), never caller-supplied strings.
**Apply to:** any new metric label — MUST be the verified mTLS CN (via `commonNameFromContext`), never a request-body field.

### Bounded, fail-loud collection (D-14/TMPL-07)

**Source:** `internal/server/service.go:438,458-460` (`maxImportBytes` + `codes.ResourceExhausted` error)
**Apply to:** `collectHostStream`/`collectSearchStream`-style client accumulation loops and any new Watch-client accumulation loop — clear message naming the limit + how to raise it, never silent truncation.

### `task lint` / `task fmt`

Per CLAUDE.md: run `golangci-lint run ./...` (via `task lint`) before committing; `task fmt` runs `gofumpt` + `buf format`. After editing `hosts.proto`, run `task proto:generate` before `task lint`/`task test` since generated stubs must be in sync. No `//nolint` directives without explicit justification and user approval.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `internal/server/watch.go` (concurrent bidi Send/Recv goroutine pair) | controller | streaming | `ImportHosts` looks identical in type signature but is structurally sequential (drain-then-send); genuine concurrent full-duplex has zero precedent in this repo — build from RESEARCH.md's verified Pattern 1 skeleton and the grpc-go concurrency contract, not from in-repo code |
| `internal/server/changenotify.go` (broadcast/generation-channel primitive) | service | event-driven/pub-sub | `hookRunner` is a process-wide singleton with one pending slot, explicitly disqualified as a copy-source per RESEARCH.md; this is a new, currently-unimplemented-in-repo idiom (channel-close-as-broadcast) — flagged `[ASSUMED]` by RESEARCH.md itself, recommend `checkpoint:human-verify` on the race-detector run |
| `internal/server/peercn.go` (mTLS CN extraction from stream context) | middleware | request-response | No production code path in this repo extracts CN today; only test fixtures set `CommonName`. Use RESEARCH.md's verified `go doc`-sourced pattern directly |

## Metadata

**Analog search scope:** `internal/server/*.go` (hostsfile.go, unboundconf.go, dnsmasqconf.go, service.go, metrics.go, hooks.go, hookrunner.go, server.go, service_test.go, hostsfile_test.go), `internal/client/commands/*.go` (host.go, importexport.go, serve.go, testhelper_test.go, connect.go), `internal/client/client.go`, `proto/router_hosts/v1/hosts.proto`, `internal/operator/grpc_hostclient_test.go`
**Files scanned:** ~16 read directly this session (all cited above with line numbers); broader directory listing via `rg`/`Glob` covered the remainder
**Pattern extraction date:** 2026-07-31
