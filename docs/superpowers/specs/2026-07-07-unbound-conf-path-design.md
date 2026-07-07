# `unbound_conf_path` Output — per-name `local-zone static` + `local-data` — Design

- **Date:** 2026-07-07
- **Status:** Draft (pending design-review gate)
- **Bead:** `router-hosts-fn5` (feature / design)
- **Issues:** #349
- **Related:** #325/#326 (dnsmasq conf output), #327/#328 (startup regen semantics)
- **Upstream context:** selfhosted-cluster design bead `hl-hqyv`, spec `docs/engineering/specs/2026-07-07-authoritative-house-resolver-design.md`

## Context

The Firewalla now runs native unbound as the authoritative resolver for `fzymgc.house`.
Firewalla's dnsmasq v2.82 **cannot suppress unknown RR types**, so the existing per-name
`dnsmasq_conf_path` output (#325/#326) still leaked HTTPS / type-65 ECH records for
Cloudflare-proxied names — breaking Chromium (`ERR_ECH_FALLBACK_CERTIFICATE_INVALID`) and
OAuth flows. AAAA was a prior recurrence of the same leak class.

unbound's per-name `local-zone … static` lists exactly the types it answers and returns
**NODATA** (not a forward) for everything else at that name, closing the leak class. The zone
is currently hand-written on the box; router-hosts should own it the same way it owns the
dnsmasq conf.

This design adds an optional third output file, a **sibling** of `dnsmasq_conf_path`, generated
by the same startup + per-mutation + hooks machinery.

## Grounding (Rule 7)

Probe (`internal/server/dnsmasqconf.go`), data model (`internal/domain/host.go`), and deepwiki
(`NLnetLabs/unbound`) consulted. Notes recorded on `router-hosts-fn5`.

- **The mirror is not line-for-line.** `DnsmasqConfGenerator.FormatConf` sorts entries by
  IP-then-hostname and emits `local=`/`address=` pairs **inline, per entry**; dnsmasq tolerates
  the same `local=/name/` appearing more than once. unbound's data model needs the records for
  one name **grouped** under a single `local-zone`.
- **`HostEntry.IP` is a single string** (`host.go:12`). A dual-stack host (A **and** AAAA for
  one name) is therefore stored as **two separate entries** sharing a hostname. Grouping across
  entries is the normal path for dual-stack / round-robin, not an edge case.
- **unbound `local-zone` type `static` semantics** (deepwiki, `services/localzone.c`): a name
  that has some `local-data` but not the queried type ⇒ **NODATA** (NOERROR, empty, no forward);
  a name inside the zone with **no** `local-data` ⇒ **NXDOMAIN**. This is the leak-closing
  behavior.
- **`local-data` TTL syntax** confirmed: `local-data: "host.example. 300 IN A 10.0.0.5"`.
- **Duplicate `local-zone` in config** does **not** error in unbound — it merges (last type
  wins). So name-grouping is a **cleanliness / determinism** choice (single `local-zone` +
  deduped comment block per name, stable diffs), not a hard requirement to avoid a parse failure.
- **Shared atomic write** helper (`atomicWriteFile`, used by `dnsmasqconf.go` /
  `hostsfile.go:112`) is reused verbatim — temp + fsync + rename.
- **`RegenerateOutputs`** (`internal/server/service.go:101`) already iterates the configured
  generators on startup (`serve.go:168`) and after every successful mutation, and is the point
  where `on_success`/`on_failure` hooks observe output writes.

## Goals / Non-goals

**Goals**
- New optional `[server]` config `unbound_conf_path` (+ `unbound_ttl`), a sibling of
  `dnsmasq_conf_path`.
- Emit, per managed name, a single `local-zone: "<fqdn>." static` and one `local-data` line per
  record (A for IPv4, AAAA for IPv6), grouped across entries.
- Identical write semantics to `dnsmasq_conf_path`: atomic write, regen on startup and every
  successful mutation, participation in hooks.

**Non-goals**
- **Reload of unbound.** The consuming deployment reloads via a host-side systemd path unit
  watching the conf directory; write and activation are deliberately decoupled.
- **PTR / reverse zones.** Forward A/AAAA only.
- **Enforcing FQDN inventories.** Names are emitted verbatim; bare aliases are the operator's
  responsibility (documented footgun below).
- **Sharing a grouping helper with the dnsmasq generator** (rejected Approach B) or a generic
  output-generator interface (rejected Approach C). See Decisions.

## Design

### Config — `internal/config/server.go`

Add two fields to `ServerConfig`:

```go
// UnboundConfPath, when set, emits authoritative unbound local-zone/local-data
// directives (sibling of DnsmasqConfPath). See GH #349.
UnboundConfPath string `toml:"unbound_conf_path"`
// UnboundTTL is the TTL (seconds) emitted in every local-data line. 0/unset
// defaults to 300. Only consulted when UnboundConfPath is set.
UnboundTTL int `toml:"unbound_ttl"`
```

Validation changes (`validate()`, unexported, currently `server.go:277`; the check is `server.go:282`):

- The "at least one output" gate becomes three-way: `hosts_file_path` **OR** `dnsmasq_conf_path`
  **OR** `unbound_conf_path` required. Error message updated to name all three.
- `unbound_ttl < 0` ⇒ validation error (`CodeValidation`).
- `unbound_ttl == 0` is normalized to the default `300` at generator construction (documented;
  TTL 0 — "do not cache" — is intentionally unreachable, which is correct for a static LAN zone).

### Generator — `internal/server/unboundconf.go` (new)

```go
const defaultUnboundTTL = 300

type UnboundConfGenerator struct {
    path string
    ttl  int
}

func NewUnboundConfGenerator(path string, ttl int) *UnboundConfGenerator // ttl<=0 => defaultUnboundTTL

func (g *UnboundConfGenerator) Regenerate(ctx, store) (int, error) // ListAll -> FormatConf -> atomicWriteFile
func (g *UnboundConfGenerator) FormatConf(entries []domain.HostEntry) string
```

`FormatConf` algorithm:

1. **Header** (parity with dnsmasq): `# Generated by router-hosts`, `# Last updated: <UTC>`,
   `# Entry count: <N>` (N = input entry count, matching the dnsmasq generator).
2. **Fold** entries into a per-name aggregate keyed by the emitted name:
   - Each entry contributes its `Hostname` **and** every `Alias`.
   - Name is **trailing-dot normalized**: `strings.TrimRight(name, ".") + "."`.
   - For each contributed name, record the entry's `IP` (classified A vs AAAA via
     `net.ParseIP(ip).To4() != nil` — **new** one-liner; no such helper exists today, and the
     dnsmasq mirror needs none because `address=` is type-agnostic) into an ordered dedup set,
     and the entry's comment/tags suffix (`formatSuffix(e.Comment, e.Tags)` — returns a single
     `"# comment [tags]"` line) into an ordered dedup set.
3. **Emit** names sorted by FQDN (ascending). Per name:
   - Each distinct comment/tags line (deduped-union order-preserved), as `#`-prefixed lines.
   - One `local-zone: "<fqdn>." static`.
   - `local-data` lines sorted **A before AAAA, then by IP**, each
     `local-data: "<fqdn>. <ttl> IN <A|AAAA> <ip>"`.

Empty store ⇒ header only (a valid, record-less unbound file), not an error.

### Service wiring — `internal/server/service.go`

- Add field `unboundGen *UnboundConfGenerator`.
- Add `WithUnboundGenerator(gen) ServiceOption`.
- In `regenerateOutputs`, add a branch after the `dnsmasqGen` branch (`service.go:116`) with
  **identical fail-soft semantics**: on error, log (mirroring the dnsmasq error line at
  `service.go:118`) and continue — a regen failure MUST NOT fail the host mutation (matching the
  existing dnsmasq/hosts behavior).
- Update the now-stale doc comments on `RegenerateOutputs` (`service.go:95-96`) and
  `regenerateOutputs` (`service.go:105-106`), both of which currently read "hosts file and/or
  dnsmasq conf", to include the unbound output.

### CLI wiring — `internal/client/commands/serve.go`

After the dnsmasq block (`serve.go:88-92`):

```go
if cfg.Server.UnboundConfPath != "" {
    unboundGen := server.NewUnboundConfGenerator(cfg.Server.UnboundConfPath, cfg.Server.UnboundTTL)
    svcOpts = append(svcOpts, server.WithUnboundGenerator(unboundGen))
}
```

Startup regeneration is already covered by the existing `svc.RegenerateOutputs(ctx)`
(`serve.go:168`).

### Data flow

`host mutation | startup` → `RegenerateOutputs(ctx)` → (hosts, dnsmasq, **unbound**) generators
each `Regenerate` → `atomicWriteFile` (temp + fsync + rename) → host-side systemd path unit
observes the rename → reloads unbound (out of scope for this repo). Hooks
(`on_success`/`on_failure`) fire via the existing `RegenerateOutputs` path.

### Error handling

`Regenerate` wraps `ListAll` and write failures with `oops.Wrapf` and the existing domain error
codes, matching `dnsmasqconf.go`. `RegenerateOutputs` logs generator errors without failing the
mutation.

### Example output

Dual-stack `api` (two entries, IPv4 + IPv6, comments `role=api` and `ipv6-managed`) plus a
single-A `db`:

```
# Generated by router-hosts
# Last updated: 2026-07-07 19:00:00 UTC
# Entry count: 3

# role=api
# ipv6-managed
local-zone: "api.fzymgc.house." static
local-data: "api.fzymgc.house. 300 IN A 10.0.0.5"
local-data: "api.fzymgc.house. 300 IN AAAA fd00::5"
# role=db
local-zone: "db.fzymgc.house." static
local-data: "db.fzymgc.house. 300 IN A 10.0.0.9"
```

### Footgun (documented, not enforced)

A bare, non-FQDN alias (e.g. `api`) emits `local-zone: "api." static`, making unbound
authoritative for the entire `api.` pseudo-TLD and NXDOMAIN-ing everything under it. Per #349,
names are emitted verbatim; inventories MUST carry FQDNs. Documented in the config option's
doc comment and the operations guide.

### Documentation updates (parity with the dnsmasq feature)

- `docs/reference/configuration.md`: add the `unbound_conf_path` / `unbound_ttl` table rows,
  update the "At least one of `hosts_file_path` or `dnsmasq_conf_path` must be set" line
  (`configuration.md:15`) to the three-way form, and add a worked `unbound_conf_path` example
  alongside the existing dnsmasq example block (`configuration.md:17`).
- `examples/server.toml.example`: add a commented `unbound_conf_path` / `unbound_ttl` block
  alongside the existing commented `dnsmasq_conf_path` block, for parity.
- `docs/guides/operations.md`: a DNS-output-files section covering the bare-alias FQDN footgun
  above and the out-of-scope unbound reload (host-side systemd path unit).
- The `unbound_conf_path` doc comment (config struct): the bare-alias FQDN footgun above.

## Testing — `internal/server/unboundconf_test.go` (new)

All filesystem tests use `t.TempDir()`; no real-filesystem writes.

- **format** — single A record, header + one `local-zone`/`local-data`.
- **ipv6** — AAAA emission for an IPv6 entry.
- **dual-stack grouping** — two entries, same hostname, v4 + v6 ⇒ **one** `local-zone`, both
  `local-data` (A then AAAA), **deduped-union** comment lines.
- **aliases** — hostname + N aliases, each its own name, aliases sorted, verbatim.
- **trailing-dot idempotency** — stored `foo.` does not become `foo..`.
- **bare non-FQDN alias** — emits `local-zone: "foo." static` (documents the caveat).
- **round-robin** — same name, same type, two IPs ⇒ two `local-data` lines (emit all).
- **empty store** — header only, valid file, no error.
- **atomic write** — result appears via rename; no partial/temp file left behind.
- **FQDN sort order** — deterministic ascending-by-name.
- **TTL** — `unbound_ttl` value applied; `0` ⇒ `300`.

Config tests — `internal/config/server_test.go`:

- parse `unbound_conf_path` + `unbound_ttl`.
- three-way "at least one output" validation (unbound-only config is valid).
- negative `unbound_ttl` rejected.

`task test` (race) and `task lint` MUST pass; coverage stays ≥ 80%.

## Decisions (and rationale)

1. **Approach A — standalone generator + internal grouping pass** (over B: shared grouping
   helper; C: generic generator interface). A isolates all new logic to new files, leaves the
   shipped `dnsmasqconf.go` (#325/#326) untouched, and matches the existing "three concrete
   sibling generators" pattern. B refactors a working file for a generalization only unbound
   needs; C rewrites `service.go`'s explicit fields for a fourth-output-type benefit that does
   not exist yet.
2. **Output shape: parity with dnsmasq** (header + per-name comment/tags), over the issue's
   literal "exactly two lines" — consistent operator experience across both generated files.
3. **`static`, per-name** — not `typetransparent` (passes missing types to recursion,
   re-leaks) and not zone-wide (would NXDOMAIN unmanaged siblings).
4. **`unbound_ttl` configurable** (default 300) rather than a hard constant — chosen during
   brainstorming; small config surface, `0`⇒default keeps the common case zero-config.
5. **Sort by FQDN** — natural zone-file order that keeps a dual-stack name's A/AAAA adjacent and
   yields stable diffs for the path-unit watcher (vs dnsmasq's IP-first sort, which scatters a
   grouped name's records).
6. **Deduped-union comments** for multi-sourced names — lossless, avoids an arbitrary "primary"
   entry.
7. **Grouping across entries** — required to produce the chosen single-`local-zone` output shape
   and deterministic diffs, even though unbound tolerates duplicate `local-zone`.

## Future (out of scope)

- unbound reload orchestration (owned by the host-side systemd path unit).
- PTR / reverse zones.
- FQDN enforcement / alias suffixing.
- Per-record TTL overrides.
