# Template Data Contract

This page — not any Go struct — defines what a `router-hosts render` (or
sink) template may reference. The contract is versioned independently of
both the gRPC proto contract and the router-hosts release version: a proto
change can ship without moving this number, and this number can move without
a proto change.

## Contract version 1

The template's top-level value is a struct. Templates iterate with
`{{range .Entries}}` — never treat `.` at the top level as the entry list
itself.

### Top-level fields

| Field | Go type | Meaning |
|-------|---------|---------|
| `.Entries` | `[]Entry` | The host entries in this snapshot. See per-entry fields below. |
| `.Count` | `int` | The number of entries in `.Entries`. |
| `.GeneratedAt` | `time.Time` (UTC) | When the server produced this snapshot. |
| `.ContractVersion` | `string` | The contract version this server served this snapshot under. |
| `.ChangeID` | `string` | A ULID identifying the server state this snapshot represents. See below — its guarantee is narrower than it looks. |

`.GeneratedAt` is a UTC `time.Time` carrying the nanosecond precision of the
protobuf `Timestamp` it came from. Go's default rendering of a `time.Time`
(what `{{.GeneratedAt}}` prints unformatted) includes that nanosecond
component and a monotonic-clock-reading suffix that most consumers do not
want in a generated config file. Format it explicitly instead, for example
`{{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}`, rather than relying on
the default `String()` output.

### Per-entry fields

| Field | Go type | Meaning |
|-------|---------|---------|
| `.IPAddress` | `string` | The entry's IP address (IPv4 or IPv6 literal). |
| `.Hostname` | `string` | The entry's primary hostname. |
| `.Aliases` | `[]string` | Additional names for the same address. |
| `.Tags` | `[]string` | Free-form operator-supplied labels. |
| `.Comment` | `string` | Free-form operator-supplied text. |

`.Comment` never distinguishes an absent comment from an empty one — the
wire carries both identically, so `GetComment()` returns `""` in either
case. `{{if .Comment}}` is the only meaningful test a template can perform;
contract v1 does not promise a nil-versus-empty distinction, so a future
contract version is not accidentally bound by a promise the wire never
carried.

Entry order in `.Entries` is whatever order the server streamed. That order
is **not** part of the contract — it is not guaranteed to be stable across
snapshots or across the entry set's own storage layout. A template that
needs a specific order (alphabetical by hostname, grouped by tag, etc.)
sorts explicitly rather than relying on incoming order.

### `.ChangeID`

`.ChangeID` is the newest compatibility surface this contract publishes, and
it is easy to overclaim, so this section states exactly four things and no
more:

1. It is the ULID of the newest event in the server's log **as of the
   moment the snapshot began**.
2. It identifies **state, rather than transmission** — the same server
   state yields the same value for every consumer. That is what makes
   "resolver-a and resolver-b are both at `01K…4F`" a checkable statement,
   and what makes comparing `rendered_change_id` across two sidecars a real
   convergence answer rather than a coincidence.
3. It is a **lower bound** on the state `.Entries` reflects, not an exact
   identity. The server reads the ID before it reads the entries, so a
   mutation landing in between puts entries in the snapshot that the ID does
   not yet name.

   **In sink (follow) mode**, convergence from this is therefore
   **eventual within one notify cycle**: the mutation that landed in the gap
   triggers its own notification, which delivers a further snapshot carrying
   a strictly greater ID, and the consumer renders again. What an operator
   can conclude from a matching change ID: "this consumer has rendered at
   least the state named by this ID." What they cannot conclude: "this
   consumer's artifact contains exactly that state and nothing newer." This
   page does **not** say the ID identifies the exact streamed state — an
   atomic single-transaction `{entries, latestEventID}` read would be needed
   for that, and it is deliberately deferred (tracked alongside
   [#400](https://github.com/fzymgc-house/router-hosts/issues/400)).

   **A one-shot `render` has no next notify cycle.** The eventual-convergence
   mechanism above applies only to sink/follow mode; nothing re-delivers
   after a one-shot render, so the correction step simply does not apply
   there. What holds instead: the artifact reflects the state at invocation,
   and its ID understates its entries by at most the mutations committed
   between the ID read and the end of the entry read. This is benign because
   each `render` invocation is operator-driven — the operator decides when
   to re-run it. An operator who needs a continuously-correct artifact
   should run the sink (`watch`), not schedule `render` on a cron.
4. It is the empty-log zero ULID sentinel on a fresh server, and a
   compaction advances it without changing host state. Consumers compare it
   by **exact string equality only** — never by prefix, ordering, or numeric
   comparison.

## Template functions

The FuncMap is part of the contract, not an implementation detail — it lives
on this page beside the field set.

| Function | Signature | Behavior |
|----------|-----------|----------|
| `sanitize` | `func(string) string` | Collapses every CR (`\r`, `0x0D`) and LF (`\n`, `0x0A`) byte to a space. All other bytes, including multi-byte UTF-8 sequences and other Unicode line-break code points (e.g. U+2028), pass through unchanged — this is a byte-level operation, not Unicode-aware line-break normalization. |

`text/template` performs **no** escaping of any kind — that is what
`html/template` does, and this contract does not use it. `{{ .Comment }}`
emits the raw bytes verbatim. A `.Comment` or `.Tags` value containing a
newline, emitted directly into a line-oriented resolver config, terminates
the `#` comment line and turns everything after it into live resolver
directives.

This is reachable from cluster state, not only from a trusted operator at a
CLI: the Kubernetes operator writes host entries from annotations, so
`.Comment`/`.Tags` values are attacker-influenceable by anyone with write
access to that annotation surface. This closes the same injection class GH #349
found and fixed server-side (`router-hosts-00b.2`) — moving rendering to
the client (D-01) moved the responsibility for escaping with it, and
`sanitize` is how a consumer template reaches the identical fix.

Correct:

```text
{{ sanitize .Comment }}
```

Incorrect — a comment containing a newline breaks out of the comment line:

```text
{{ .Comment }}
```

**Compatibility rule:** adding a function to the FuncMap is a compatible
change and does not bump the contract version. Removing or renaming one
does.

## Declaring the version

Every template must declare the contract version it targets in a named
block:

```text
{{define "contract_version"}}1{{end}}
```

The CLI evaluates this block before opening any connection to the server. A
template missing it is refused immediately. After the server's snapshot
terminator arrives, the CLI compares the declared version against the
version the server served, using **exact string equality** — `"1.0"` is
refused against a served version of `"1"`, not treated as adjacent to it.
A mismatch is refused before rendering, and nothing is written to `--out`.
The error names both versions:

```text
template targets contract version "2", but this server serves version "1"; see docs/reference/template-contract.md
```

## Version change policy

- Adding a field to `.Entries`'s element type or to the top-level struct is a
  **compatible** change. It does not bump the contract version.
- Adding a function to the FuncMap is a **compatible** change. It does not
  bump the contract version.
- Renaming or removing a field, or renaming or removing a FuncMap function,
  **bumps** the contract version.
- A version bump means every consumer template must be updated and
  redeclared — `RequireVersion` refuses the old declaration against the new
  served version rather than rendering a silently wrong result.

## Streaming and memory

The server sends one host entry per stream message, so per-message wire
memory is bounded and the client receives ordinary gRPC flow-control
backpressure — the server cannot force an unbounded single response onto the
client. The client itself imposes a further collection cap and byte budget
that refuse rather than truncate once exceeded.

The client collects the whole entry set before rendering, because `.Count`
and `.GeneratedAt` require knowing the total before the first `{{range}}`
iteration can safely assume it has seen everything.

This is **bounded wire messages and client backpressure** — the scope
`REQUIREMENTS.md` TMPL-06 was amended to after cross-AI review (`01-REVIEWS.md`
H2). It is explicitly **not** constant server memory: `store.ListAll` still
enumerates every aggregate and replays its full event log into memory before
the server sends the first byte. Making that a cursor-based read is
deliberately deferred to a follow-up issue, tracked as
[#400](https://github.com/fzymgc-house/router-hosts/issues/400). Do not read
this section as claiming the server holds O(1) memory for a snapshot — it
does not, yet.

## What a sink does when something fails

A sink (or one-shot render) cycle has three distinct outcomes, not two —
knowing which one occurred determines what a template author or operator
should check next.

| Outcome | Artifact on disk | What is actually wrong |
|---------|-------------------|-------------------------|
| Render or write failed | **Unchanged** — the previous artifact is untouched | New data never reached disk |
| **Artifact written, post-write hook failed** | **Updated and retained** | The file is current, but the resolver may still be serving the old zone — this is reported separately from staleness |
| Connection lost | **Unchanged** — the previous artifact is untouched | No new data arrived; the artifact is stale |

The artifact is **never rolled back after the post-write hook has run.** By
the time the hook runs (typically a resolver reload command), it is unknown
whether the resolver already read the new file. Reverting the artifact at
that point could leave the on-disk file and the running resolver actively
disagreeing about the served zone — a strictly worse state than simply
retaining the new (correct) file and reporting the hook failure on its own
terms.

## Worked example

Three copy-paste-ready templates live in
[`examples/templates/`](https://github.com/fzymgc-house/router-hosts/tree/main/examples/templates)
in this repository: `hosts.tmpl`, `dnsmasq.tmpl`, and `unbound.tmpl`. Each
declares contract version 1 and sanitizes every `.Comment`/`.Tags` emission,
so they can be copied into a consumer's own template file and adjusted
rather than written from scratch. `unbound.tmpl` reproduces the per-name
`static` zone form this project's generators use — see
[Configuration Reference](configuration.md) for why that form matters.
