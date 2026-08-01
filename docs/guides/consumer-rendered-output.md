# Consumer-Rendered Output

router-hosts is one stateful server. DNS resolvers come in many shapes —
unbound, dnsmasq, a plain `/etc/hosts`, something else entirely — and the
server does not ship a generator for every one of them. Instead, each
consumer supplies its own [text/template](https://pkg.go.dev/text/template)
and renders the server's host data client-side, either once (`render`) or
continuously as a self-healing sink (`watch`). One server, N consumers, no
per-resolver format shipped upstream.

This guide covers both commands end to end. For the exact field set and
functions a template may reference, see the
[Template Data Contract](../reference/template-contract.md) — this page does not repeat
it.

## One certificate common name per consumer

Before deploying more than one sink: **each consumer must connect with its
own client certificate, issued with a distinct subject common name (CN).**
The server keys its per-consumer sink health registry — last-seen, write
health, reload health, convergence — by the mTLS CN, and nothing in the
server enforces that CNs are unique. Two consumers sharing one certificate
collapse into a single health record: their status reports overwrite each
other, last-writer-wins, and `router_hosts_sink_converged` reflects
whichever one reported most recently, not both.

The symptom an operator would actually see: one CN's convergence gauge
flapping between 0 and 1 with no corresponding change on either host,
because two different consumers are reporting under the same identity. The
fix is straightforward — issue a distinct client certificate per consumer —
but the symptom does not obviously point at "duplicate certificate" unless
you know to look for it, which is why it is called out here rather than
left to the metrics reference below.

## One-shot rendering: `render`

`router-hosts render` renders the current host data through a template
once and exits. Useful for scripting, for a cron-driven refresh, or for
generating a file to inspect before wiring up a long-lived sink.

```bash
router-hosts render --template ./my-template.tmpl --out /etc/dnsmasq.d/hosts.conf
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--template` | *(required)* | Path to a `text/template` file declaring its contract version. |
| `--out` | stdout | Artifact output path. Omit to write to stdout. |

`render` reads and parses the template, and declares its contract version,
**before** opening any connection to the server — a malformed or
undeclared template is refused without ever touching the network. It
collects the whole snapshot, checks the server's served contract version
against the template's declared one, and only then renders and writes.
If `--out` is set, the write is atomic (write-then-rename); a render or
version-mismatch failure never touches a pre-existing artifact at `--out`.

`render` has **no next notify cycle**: each invocation reflects the state
at the moment it ran, and nothing re-renders afterward. An operator who
needs a continuously-correct artifact should run `watch`, not schedule
`render` on a cron — see the Template Data Contract's `.ChangeID` section
for exactly why a one-shot render's ID is looser than a sink's.

## Long-lived sink: `watch`

`router-hosts watch` opens a long-lived stream, keeps `--out` current as
host data changes with no polling, survives connection loss with automatic
reconnect, and reports its own health both upstream (on the same stream)
and to a local sidecar status file.

```bash
router-hosts watch \
  --template ./examples/templates/unbound.tmpl \
  --out /etc/unbound/conf.d/router-hosts.conf \
  --exec 'unbound-control reload' \
  --status-file /var/lib/router-hosts/watch.status
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--template` | *(required)* | Path to a `text/template` file declaring its contract version. |
| `--out` | *(required)* | Artifact output path, kept current for the life of the process. |
| `--exec` | *(none)* | Command run via `sh -c` after every successful write — typically a resolver reload. |
| `--exec-timeout` | 30s | Timeout for the post-write command. |
| `--status-file` | `<out>.status` | Sidecar status file path (see below). |
| `--status-interval` | 30s | How often the sink reports its health upstream on the open stream, independent of whether data changed. |

These commands read the same global connection flags as the rest of the
CLI (`--server`, `--cert`, `--key`, `--ca`, `--config`) — see the
[CLI Reference](../reference/cli.md).

`watch` writes its artifact once immediately on startup and again on every
mutation, with no operator action required. `SIGINT`/`SIGTERM` end the
process cleanly. On restart, it loads its own sidecar status file and
adopts it — but only when the artifact the sidecar describes still exists
on disk; if the artifact is missing, the loaded state is discarded rather
than trusted, so an out-of-band deletion is always repaired rather than
permanently skipped.

### Worked example: unbound

[`examples/templates/unbound.tmpl`](https://github.com/fzymgc-house/router-hosts/blob/main/examples/templates/unbound.tmpl)
emits one `local-zone: "<fqdn>." static` + `local-data` pair per managed
name (hostname and every alias), sanitizing `.Comment`/`.Tags` before
emitting them as comments. Point `--out` at a file inside unbound's
`conf.d`/`conf-dir`, and reload unbound on write:

```bash
router-hosts watch \
  --template ./examples/templates/unbound.tmpl \
  --out /etc/unbound/conf.d/router-hosts.conf \
  --exec 'unbound-control reload' \
  --exec-timeout 10s
```

`unbound-control reload` runs with the sink process's own privileges and
under `--exec-timeout`; there is no reason to run the sink as a more
privileged user than the reload command itself requires. Keep the reload
command narrowly scoped to what it needs to do — reload the resolver,
nothing else.

### Reading the sidecar status file

`--status-file` (default `<out>.status`) is a small JSON record the sink
writes atomically alongside its artifact:

| Field | Meaning |
|-------|---------|
| `last_success` | Time of the sink's last successful render+write. |
| `last_error` | Text of the most recent render/write/connection failure, cleared on the next success. |
| `consecutive_failures` | Count of render/write/connection failures since the last success. Never incremented by a reload (hook) failure alone. |
| `contract_version` | The template/data contract version this sink was built against. |
| `rendered_change_id` | The change ID (see below) this sink last rendered. |
| `reload_failed` | `true` when the sink's last post-write reload hook failed. Independent of `last_success`/`consecutive_failures`. |
| `last_reload_success` | Time of the sink's last successful reload hook run. |

This file exists specifically for the server-down case: when the server is
unreachable, server-side metrics are unavailable by definition, while the
sink keeps serving its last-good artifact. The sidecar is then the only
health signal an operator has for that consumer.

### Is my artifact current?

`rendered_change_id` names the server state the artifact was rendered
from — the same server state produces the same ID for every consumer, so
comparing `rendered_change_id` across two sidecars answers "have both
resolvers converged?" directly, without needing to diff the rendered files
themselves.

This is also why a server restart does not cause a fleet-wide reload
storm: on reconnect, a sink whose artifact already carries the change ID
the server reports skips the render and the reload entirely — nothing
changed, so there is nothing to re-apply. That skip is bypassed the moment
it would be wrong: if the artifact file has gone missing out-of-band, the
sink renders (and reloads) again despite a matching change ID, because the
skip's whole justification — "the artifact already reflects this state" —
no longer holds.

The change ID is a **lower bound**, not an exact fingerprint of the
streamed entry set — see the Template Data Contract's `.ChangeID` section
for the precise guarantee and why it converges only eventually, within one
notify cycle, in sink mode.

### My file is right but DNS is wrong

This is the D-12a middle outcome, and it is common enough to call out on
its own: when the post-write reload command fails, **the artifact is
still updated and kept** — only the reload failed. The sidecar shows
`reload_failed: true` alongside a fresh `last_success`, and the server-side
`router_hosts_sink_reload_failed` gauge reads 1 for that consumer's CN,
while `router_hosts_sink_last_success_timestamp_seconds` stays current.

This is a **different problem, with a different fix**, from a stale
artifact: the file on disk is correct, but the resolver process has not
picked it up. Check the reload command itself (permissions, resolver
control socket, resolver still running) rather than looking for a data
problem. The artifact is **never rolled back** after the hook has run — by
that point it is unknown whether the resolver already read the new file,
and reverting could leave the file and the running resolver actively
disagreeing about the served zone. A subsequent successful reload clears
`reload_failed`.

### Reconnect behavior

`watch` survives connection loss and reconnects automatically with bounded
exponential backoff and jitter (starting at 1 second, capped at 60
seconds in production), so a fleet of sinks that all lost the server at
the same instant does not reconnect in lockstep. While disconnected, the
artifact stays exactly as it was — unchanged and possibly stale, never
truncated — and the sidecar's `consecutive_failures` count rises. On
reconnect, the sink sends a fresh follow request and receives the current
full snapshot; there is no resume token or cursor, by design, so the
sink always ends up consistent with server state rather than attempting
to replay a gap.

## Troubleshooting

Three loud failures an operator will actually encounter. In every one, the
previously written artifact is left untouched — that is the property that
makes a stale artifact a safe artifact.

**Undeclared or mismatched contract version.** A template missing its
`{{define "contract_version"}}1{{end}}` block is refused before any
connection is opened. A template declaring a version the server does not
serve is refused after the snapshot terminator arrives, before rendering:

```text
template targets contract version "2", but this server serves version "1"; see docs/reference/template-contract.md
```

Fix: update the template to match what the server serves, or check
whether the server was upgraded to a new contract version without the
template being updated alongside it.

**Exceeded collection limit or byte budget.** The client refuses — never
truncates — a snapshot whose entry count or total byte size exceeds its
configured limits:

```text
server response exceeds the client entry limit of 50000 entries; refusing the result rather than returning a truncated one — raise the limit via the client config file's limits.max_stream_entries key or the ROUTER_HOSTS_MAX_STREAM_ENTRIES environment variable
```

Fix: raise the limit via the client config file or the corresponding
environment variable (see the [Configuration Reference](../reference/configuration.md)),
or investigate why the inventory grew unexpectedly large.

**Render error.** A template referencing an undefined field, or any other
`text/template` execution error, fails the render before any write is
attempted:

```text
watch: render failed error=...
```

Fix: check the error against the [Template Data Contract](../reference/template-contract.md)'s
field set — a typo'd field name (`.Ip` instead of `.IPAddress`) is the most
common cause, and `missingkey=error` is what turns that typo into a loud
failure instead of a silently empty value.

## Metrics reference

The server exports seven OpenTelemetry gauges describing per-consumer sink
health, all labeled by `cn` (the client certificate's common name) except
where noted. See [Metrics and Tracing](operations.md#metrics-and-tracing-opentelemetry)
for how to enable OTel export.

| Metric | Labels | Meaning | What to alert on |
|--------|--------|---------|-------------------|
| `router_hosts_sink_last_seen_timestamp_seconds` | `cn` | Unix timestamp of the last time this consumer's stream was seen. | A value aging while the server is up means the consumer disconnected or crashed; absence after a server restart correctly means "not seen since restart" — it does not mean the consumer is gone. |
| `router_hosts_sink_last_success_timestamp_seconds` | `cn` | Unix timestamp of this consumer's last successful artifact write. | Aging relative to `last_seen` while the sink is otherwise connected suggests repeated render/write failures. |
| `router_hosts_sink_consecutive_failures` | `cn` | Consumer-reported count of consecutive render/write failures since its last success. | Any non-zero, sustained value. |
| `router_hosts_sink_reload_failed` | `cn` | 1 when the consumer's last post-write reload hook failed. | Non-zero — see "My file is right but DNS is wrong" above; this is a different alert from a stale artifact. |
| `router_hosts_sink_converged` | `cn` | 1 when the consumer's last rendered change ID equals the server's current change ID. | Sustained 0 for a consumer that should be current. |
| `router_hosts_sinks_connected` | *(none)* | Current number of connected sink streams. | Unexpected drops. |
| `router_hosts_sink_identity_failures` | *(none)* | Number of streams whose peer certificate identity could not be extracted since process start. | Any non-zero value: connections are being accepted and counted here while no per-consumer health record can be created for them, so `sinks_connected` will exceed the number of tracked identities. |

The exact change ID is deliberately **not** a metric label — it changes on
every mutation and would be unbounded cardinality by construction. Read it
from a sidecar status file's `rendered_change_id`, or from the server's
structured logs.
