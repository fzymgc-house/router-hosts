# `unbound_conf_path` Output — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional `[server]` `unbound_conf_path` output that writes per-name `local-zone: "<fqdn>." static` + grouped `local-data` directives, a sibling of the shipped `dnsmasq_conf_path`, to close the HTTPS/type-65 ECH + AAAA DNS leak class on unbound.

**Architecture:** A new `UnboundConfGenerator` (mirroring `DnsmasqConfGenerator`'s shape but with an internal name-keyed grouping pass) is wired into the existing three-generator output pipeline (`regenerateOutputs`, run on startup + every successful mutation + hooks). All new logic lives in new files; the shipped `dnsmasqconf.go` is untouched. Config gains `unbound_conf_path` + `unbound_ttl`; validation becomes a three-way "at least one output" gate.

**Tech Stack:** Go 1.25, `zombiezen.com/go/sqlite` store, `samber/oops` errors, `testify` (assert/require), stdlib `net`/`sort`/`strings`. Build/test via `task`. VCS is **jj** (colocated) — see `references/vcs-preamble.md`; commit with `jj commit -m` / `jj describe -m`, never `git commit`.

**Spec:** `docs/superpowers/specs/2026-07-07-unbound-conf-path-design.md`
**Bead:** `router-hosts-fn5`

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `internal/config/server.go` | `UnboundConfPath` + `UnboundTTL` fields; three-way + non-negative-TTL validation | Modify (`:54-62`, `:277-298`) |
| `internal/config/server_test.go` | config parse + validation tests; fix stale message assertion | Modify (`:85-100`, append) |
| `internal/server/unboundconf.go` | `UnboundConfGenerator`: grouping, format, atomic write | **Create** |
| `internal/server/unboundconf_test.go` | generator unit tests + service-wiring test | **Create** |
| `internal/server/service.go` | `unboundGen` field, `WithUnboundGenerator`, `regenerateOutputs` branch, doc comments | Modify (`:36`, `:56`, `:95-121`) |
| `internal/client/commands/serve.go` | construct generator when `unbound_conf_path` set | Modify (`:88-92`) |
| `docs/reference/configuration.md` | config-table rows, three-way "at least one" line, worked example | Modify (`:12-35`) |
| `docs/guides/operations.md` | DNS-output-files section: unbound reload (systemd path unit) + FQDN footgun | Modify (insert before `:53`) |
| `examples/server.toml.example` | commented `unbound_conf_path` / `unbound_ttl` example block | Modify (after `:20`) |

Reused (not modified): `atomicWriteFile` + `formatSuffix` (`internal/server/hostsfile.go:92,113`), `storage.Storage.ListAll`, `domain.HostEntry` (`internal/domain/host.go:10`, single-valued `IP`).

---

## Task 1: Config — `unbound_conf_path` + `unbound_ttl` fields and three-way validation

**Files:**

- Modify: `internal/config/server.go:54-62` (fields), `internal/config/server.go:281-283` (validation)
- Modify/Test: `internal/config/server_test.go:99` (fix stale assertion), append new tests

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/server_test.go`:

```go
func TestLoadServerConfig_UnboundConfPathOnly(t *testing.T) {
	content := `
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = ""
unbound_conf_path = "/etc/unbound/unbound.conf.d/router-hosts.conf"

[tls]
cert_path = "/cert.pem"
key_path = "/key.pem"
ca_cert_path = "/ca.pem"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Empty(t, cfg.Server.HostsFilePath)
	assert.Equal(t, "/etc/unbound/unbound.conf.d/router-hosts.conf", cfg.Server.UnboundConfPath)
	// Unset TTL stays 0 at load; NewUnboundConfGenerator normalizes 0 -> 300.
	assert.Equal(t, 0, cfg.Server.UnboundTTL)
}

func TestLoadServerConfig_UnboundTTL(t *testing.T) {
	content := `
[server]
bind_address = "0.0.0.0:50051"
unbound_conf_path = "/etc/unbound/router-hosts.conf"
unbound_ttl = 600

[tls]
cert_path = "/cert.pem"
key_path = "/key.pem"
ca_cert_path = "/ca.pem"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Equal(t, 600, cfg.Server.UnboundTTL)
}

func TestLoadServerConfig_NegativeUnboundTTL(t *testing.T) {
	content := `
[server]
bind_address = "0.0.0.0:50051"
unbound_conf_path = "/etc/unbound/router-hosts.conf"
unbound_ttl = -5

[tls]
cert_path = "/cert.pem"
key_path = "/key.pem"
ca_cert_path = "/ca.pem"
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unbound_ttl must not be negative")
}
```

And **fix the existing stale assertion** at `internal/config/server_test.go:99` (the message changes in Step 3):

```go
	assert.Contains(t, err.Error(), "at least one of hosts_file_path, dnsmasq_conf_path, or unbound_conf_path is required")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestLoadServerConfig_(Unbound|MissingOutputPaths)' -v`
Expected: FAIL — `cfg.Server.UnboundConfPath`/`UnboundTTL` undefined (compile error), and `MissingOutputPaths` fails on the new message.

- [ ] **Step 3: Add the fields and validation**

In `internal/config/server.go`, extend `ServerConfig` (after `DnsmasqConfPath`, `:61`):

```go
	// UnboundConfPath, when set, emits authoritative unbound local-zone/local-data
	// directives to a conf-dir file: one `local-zone: "<fqdn>." static` per name plus
	// its A/AAAA `local-data`. `static` answers listed types and returns NODATA for
	// the rest, so a name's missing record types never leak upstream (closes the
	// HTTPS/type-65 ECH + AAAA leak class dnsmasq v2.82 cannot). Additive to
	// HostsFilePath/DnsmasqConfPath; at least one of the three must be configured.
	// Names are emitted verbatim (trailing-dot normalized) — a bare, non-FQDN alias
	// makes unbound authoritative for that pseudo-TLD, so inventories MUST carry
	// FQDNs. See GH #349.
	UnboundConfPath string `toml:"unbound_conf_path"`
	// UnboundTTL is the TTL (seconds) emitted in every local-data line. 0/unset
	// defaults to 300; only consulted when UnboundConfPath is set.
	UnboundTTL int `toml:"unbound_ttl"`
```

In `validate()` replace the two-way check (`:281-283`) with:

```go
	if c.Server.HostsFilePath == "" && c.Server.DnsmasqConfPath == "" && c.Server.UnboundConfPath == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: at least one of hosts_file_path, dnsmasq_conf_path, or unbound_conf_path is required")
	}
	if c.Server.UnboundTTL < 0 {
		return oops.Code(domain.CodeValidation).Errorf("config: unbound_ttl must not be negative")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS (all config tests, including the updated `MissingOutputPaths`).

- [ ] **Step 5: Commit**

```
jj commit -m "feat(config): add unbound_conf_path and unbound_ttl options

Three-way 'at least one output' validation; reject negative unbound_ttl.

Refs #349"
```

---

## Task 2: Generator — `UnboundConfGenerator` + `FormatConf` (grouping, format, sort, comments)

**Files:**

- Create: `internal/server/unboundconf.go`
- Create/Test: `internal/server/unboundconf_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/server/unboundconf_test.go`:

```go
package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

func TestUnboundFormatConf_Empty(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	content := gen.FormatConf(nil)

	assert.Contains(t, content, "# Generated by router-hosts")
	assert.Contains(t, content, "# Entry count: 0")
	assert.NotContains(t, content, "local-zone:")
	assert.NotContains(t, content, "local-data:")
}

func TestUnboundFormatConf_SingleA(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.5", Hostname: "api.fzymgc.house"},
	}
	content := gen.FormatConf(entries)
	assert.Contains(t, content, "local-zone: \"api.fzymgc.house.\" static\n")
	assert.Contains(t, content, "local-data: \"api.fzymgc.house. 300 IN A 10.0.0.5\"\n")
}

func TestUnboundFormatConf_IPv6AAAA(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "fd00::5", Hostname: "api.fzymgc.house"},
	}
	content := gen.FormatConf(entries)
	assert.Contains(t, content, "local-data: \"api.fzymgc.house. 300 IN AAAA fd00::5\"\n")
}

// Dual-stack: two entries, same hostname, v4 + v6 => ONE local-zone, both
// local-data (A before AAAA), deduped-union comments (sorted).
func TestUnboundFormatConf_DualStackGrouping(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	cA := "role=api"
	cV6 := "ipv6-managed"
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.5", Hostname: "api.fzymgc.house", Comment: &cA},
		{ID: ulid.Make(), IP: "fd00::5", Hostname: "api.fzymgc.house", Comment: &cV6},
	}
	content := gen.FormatConf(entries)
	assert.Equal(t, 1, strings.Count(content, "local-zone: \"api.fzymgc.house.\" static"))
	assert.Contains(t, content, "# ipv6-managed\n# role=api\nlocal-zone: \"api.fzymgc.house.\" static\n"+
		"local-data: \"api.fzymgc.house. 300 IN A 10.0.0.5\"\n"+
		"local-data: \"api.fzymgc.house. 300 IN AAAA fd00::5\"\n")
}

func TestUnboundFormatConf_Golden(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	cA := "role=api"
	cV6 := "ipv6-managed"
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.5", Hostname: "api.fzymgc.house", Comment: &cA},
		{ID: ulid.Make(), IP: "fd00::5", Hostname: "api.fzymgc.house", Comment: &cV6},
		{ID: ulid.Make(), IP: "10.0.0.9", Hostname: "db.fzymgc.house", Aliases: []string{"sql.fzymgc.house"}},
	}
	content := gen.FormatConf(entries)

	var kept []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "# Last updated:") {
			continue
		}
		kept = append(kept, line)
	}
	got := strings.Join(kept, "\n")

	want := "# Generated by router-hosts\n" +
		"# Entry count: 3\n" +
		"\n" +
		"# ipv6-managed\n" +
		"# role=api\n" +
		"local-zone: \"api.fzymgc.house.\" static\n" +
		"local-data: \"api.fzymgc.house. 300 IN A 10.0.0.5\"\n" +
		"local-data: \"api.fzymgc.house. 300 IN AAAA fd00::5\"\n" +
		"local-zone: \"db.fzymgc.house.\" static\n" +
		"local-data: \"db.fzymgc.house. 300 IN A 10.0.0.9\"\n" +
		"local-zone: \"sql.fzymgc.house.\" static\n" +
		"local-data: \"sql.fzymgc.house. 300 IN A 10.0.0.9\"\n"

	assert.Equal(t, want, got)
}

func TestUnboundFormatConf_TrailingDotIdempotent(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.5", Hostname: "foo.fzymgc.house."},
	}
	content := gen.FormatConf(entries)
	assert.Contains(t, content, "local-zone: \"foo.fzymgc.house.\" static\n")
	assert.NotContains(t, content, "fzymgc.house..")
}

func TestUnboundFormatConf_BareAliasPseudoTLD(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.5", Hostname: "host.fzymgc.house", Aliases: []string{"host"}},
	}
	content := gen.FormatConf(entries)
	assert.Contains(t, content, "local-zone: \"host.\" static\n")
	assert.Contains(t, content, "local-data: \"host. 300 IN A 10.0.0.5\"\n")
}

func TestUnboundFormatConf_RoundRobin(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.2", Hostname: "web.fzymgc.house"},
		{ID: ulid.Make(), IP: "10.0.0.1", Hostname: "web.fzymgc.house"},
	}
	content := gen.FormatConf(entries)
	assert.Equal(t, 1, strings.Count(content, "local-zone: \"web.fzymgc.house.\" static"))
	assert.Contains(t, content, "local-data: \"web.fzymgc.house. 300 IN A 10.0.0.1\"\n"+
		"local-data: \"web.fzymgc.house. 300 IN A 10.0.0.2\"\n")
}

func TestUnboundFormatConf_TTLApplied(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 600)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.5", Hostname: "api.fzymgc.house"},
	}
	assert.Contains(t, gen.FormatConf(entries), "IN A 10.0.0.5\"")
	assert.Contains(t, gen.FormatConf(entries), "api.fzymgc.house. 600 IN A 10.0.0.5")
}

func TestUnboundFormatConf_SortedByFQDN(t *testing.T) {
	gen := NewUnboundConfGenerator("/tmp/unbound.conf", 0)
	entries := []domain.HostEntry{
		{ID: ulid.Make(), IP: "10.0.0.3", Hostname: "zeta.fzymgc.house"},
		{ID: ulid.Make(), IP: "10.0.0.1", Hostname: "alpha.fzymgc.house"},
	}
	content := gen.FormatConf(entries)
	assert.Less(t,
		strings.Index(content, "alpha.fzymgc.house."),
		strings.Index(content, "zeta.fzymgc.house."))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ -run TestUnboundFormatConf -v`
Expected: FAIL — `NewUnboundConfGenerator` / `FormatConf` undefined (compile error).

- [ ] **Step 3: Write the generator**

Create `internal/server/unboundconf.go`:

```go
package server

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// defaultUnboundTTL is used when the configured TTL is unset or non-positive.
const defaultUnboundTTL = 300

// UnboundConfGenerator writes an unbound conf-dir file of authoritative
// local-zone/local-data directives atomically. For each managed name it emits
// one:
//
//	local-zone: "<fqdn>." static
//
// followed by one `local-data` line per address:
//
//	local-data: "<fqdn>. <ttl> IN A|AAAA <ip>"
//
// A `static` zone answers the listed record types and returns NODATA for any
// other type at that name (NXDOMAIN for names with no local-data), so a name's
// missing types are never forwarded upstream — closing the HTTPS/type-65 ECH +
// AAAA leak class. Records for one name are grouped across host entries: because
// domain.HostEntry carries a single IP, a dual-stack host is two entries sharing
// a hostname, and both fold into one local-zone. See GH #349.
type UnboundConfGenerator struct {
	path string
	ttl  int
}

// NewUnboundConfGenerator creates a generator writing to path. A ttl <= 0 is
// normalized to defaultUnboundTTL.
func NewUnboundConfGenerator(path string, ttl int) *UnboundConfGenerator {
	if ttl <= 0 {
		ttl = defaultUnboundTTL
	}
	return &UnboundConfGenerator{path: path, ttl: ttl}
}

// Regenerate loads all entries, formats them, and atomically writes the result.
// Returns the entry count.
func (g *UnboundConfGenerator) Regenerate(ctx context.Context, store storage.Storage) (int, error) {
	entries, err := store.ListAll(ctx)
	if err != nil {
		return 0, oops.Wrapf(err, "list hosts for unbound regeneration")
	}
	content := g.FormatConf(entries)
	if err := atomicWriteFile(g.path, content); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// unboundName accumulates the addresses and comment lines for one zone name.
type unboundName struct {
	ips      []string
	seenIP   map[string]bool
	comments []string
	seenCmt  map[string]bool
}

// FormatConf renders entries as grouped unbound local-zone/local-data blocks,
// one block per unique name (hostname + each alias), sorted by FQDN. Output is a
// pure function of the entry set (records and comments sorted), independent of
// input order, for stable diffs.
func (g *UnboundConfGenerator) FormatConf(entries []domain.HostEntry) string {
	var b strings.Builder

	now := time.Now().UTC()
	fmt.Fprintf(&b, "# Generated by router-hosts\n")
	fmt.Fprintf(&b, "# Last updated: %s\n", now.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "# Entry count: %d\n\n", len(entries))

	names := make(map[string]*unboundName)
	var order []string
	add := func(rawName, ip, suffix string) {
		key := normalizeFQDN(rawName)
		agg, ok := names[key]
		if !ok {
			agg = &unboundName{seenIP: map[string]bool{}, seenCmt: map[string]bool{}}
			names[key] = agg
			order = append(order, key)
		}
		if !agg.seenIP[ip] {
			agg.seenIP[ip] = true
			agg.ips = append(agg.ips, ip)
		}
		if suffix != "" && !agg.seenCmt[suffix] {
			agg.seenCmt[suffix] = true
			agg.comments = append(agg.comments, suffix)
		}
	}

	for _, e := range entries {
		suffix := formatSuffix(e.Comment, e.Tags)
		add(e.Hostname, e.IP, suffix)
		for _, a := range e.Aliases {
			add(a, e.IP, suffix)
		}
	}

	sort.Strings(order)
	for _, key := range order {
		agg := names[key]
		sort.Strings(agg.comments)
		for _, c := range agg.comments {
			b.WriteString(c)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "local-zone: %q static\n", key)
		sort.Slice(agg.ips, func(i, j int) bool {
			ti, tj := rrType(agg.ips[i]), rrType(agg.ips[j])
			if ti != tj {
				return ti == "A" // A before AAAA
			}
			return agg.ips[i] < agg.ips[j]
		})
		for _, ip := range agg.ips {
			data := fmt.Sprintf("%s %d IN %s %s", key, g.ttl, rrType(ip), ip)
			fmt.Fprintf(&b, "local-data: %q\n", data)
		}
	}

	return b.String()
}

// normalizeFQDN strips any trailing dots and appends exactly one, so a name
// stored with or without a trailing dot yields the same zone name.
func normalizeFQDN(name string) string {
	return strings.TrimRight(name, ".") + "."
}

// rrType returns "A" for an IPv4 address, "AAAA" otherwise. dnsmasq's address=
// directive is type-agnostic, so the sibling generator needs no such helper;
// unbound's local-data must name the type explicitly.
func rrType(ip string) string {
	if net.ParseIP(ip).To4() != nil {
		return "A"
	}
	return "AAAA"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestUnboundFormatConf -v`
Expected: PASS (all 10 `FormatConf` tests).

- [ ] **Step 5: Commit**

```
jj commit -m "feat(server): add UnboundConfGenerator FormatConf

Per-name local-zone static + grouped local-data (A/AAAA), grouped across
entries by FQDN, deterministic (sorted names/records/comments).

Refs #349"
```

---

## Task 3: Generator — `Regenerate` write path (atomic write, real store)

**Files:**

- Modify/Test: `internal/server/unboundconf_test.go` (append)
- Production code already exists (Task 2 wrote `Regenerate`); these tests exercise the write path end-to-end.

- [ ] **Step 1: Write the failing tests**

Append to `internal/server/unboundconf_test.go`:

```go
func TestUnboundRegenerate(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	_, err = handler.AddHost(ctx, "10.0.0.5", "api.fzymgc.house", nil, []string{"web"}, []string{"sso.fzymgc.house"})
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "router-hosts.conf")
	gen := NewUnboundConfGenerator(path, 0)

	count, err := gen.Regenerate(ctx, store)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "local-zone: \"api.fzymgc.house.\" static\n")
	assert.Contains(t, content, "local-data: \"api.fzymgc.house. 300 IN A 10.0.0.5\"\n")
	assert.Contains(t, content, "local-zone: \"sso.fzymgc.house.\" static\n")
}

func TestUnboundRegenerate_InvalidPath(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	gen := NewUnboundConfGenerator("/nonexistent/dir/router-hosts.conf", 0)
	_, err = gen.Regenerate(ctx, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temp file")
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestUnboundRegenerate -v`
Expected: PASS — `Regenerate` (written in Task 2) writes via the shared `atomicWriteFile`, and the invalid-path case surfaces the "create temp file" error.

> Note: this task has no separate red phase — `Regenerate` shipped with Task 2 so the generator file compiles as a unit. If you are executing strictly TDD and want a red phase, temporarily stub `Regenerate` to `panic("not implemented")` after Task 2, confirm these tests fail, then restore. Otherwise proceed.

- [ ] **Step 3: Commit**

```
jj commit -m "test(server): cover UnboundConfGenerator.Regenerate write path

Real store round-trip + atomic-write error on unwritable path.

Refs #349"
```

---

## Task 4: Service wiring — field, option, `regenerateOutputs` branch, doc comments

**Files:**

- Modify: `internal/server/service.go:36` (field), `:56` (option), `:95-121` (doc comments + branch)
- Modify/Test: `internal/server/unboundconf_test.go` (append wiring test)

- [ ] **Step 1: Write the failing test**

Append to `internal/server/unboundconf_test.go`:

```go
func TestRegenerateOutputs_WritesUnbound(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	_, err = handler.AddHost(ctx, "10.0.0.5", "api.fzymgc.house", nil, nil, nil)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "router-hosts.conf")
	svc := NewHostsServiceImpl(handler, store, WithUnboundGenerator(NewUnboundConfGenerator(path, 0)))

	svc.RegenerateOutputs(ctx)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "local-zone: \"api.fzymgc.house.\" static\n")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestRegenerateOutputs_WritesUnbound -v`
Expected: FAIL — `WithUnboundGenerator` undefined (compile error).

- [ ] **Step 3: Wire the generator into the service**

In `internal/server/service.go`, add the field to `HostsServiceImpl` (after `dnsmasqGen`, `:36`):

```go
	unboundGen        *UnboundConfGenerator
```

Add the option (after `WithDnsmasqGenerator`, `:56`):

```go
// WithUnboundGenerator sets the unbound conf-dir generator.
func WithUnboundGenerator(gen *UnboundConfGenerator) ServiceOption {
	return func(s *HostsServiceImpl) { s.unboundGen = gen }
}
```

Update the two doc comments to name the third output — `RegenerateOutputs` (`:95-96`) and `regenerateOutputs` (`:105-106`): change each "hosts file and/or\n// dnsmasq conf" to "hosts file, dnsmasq conf, and/or\n// unbound conf".

Add the branch in `regenerateOutputs`, after the `dnsmasqGen` branch (`:116-120`):

```go
	if s.unboundGen != nil {
		if _, err := s.unboundGen.Regenerate(ctx, s.store); err != nil {
			slog.Error("unbound conf regeneration failed", "op", op, "error", err)
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/ -run TestRegenerateOutputs_WritesUnbound -v`
Expected: PASS.

- [ ] **Step 5: Run the full server package + lint**

Run: `task test` then `task lint`
Expected: PASS (race-clean, no lint findings).

- [ ] **Step 6: Commit**

```
jj commit -m "feat(server): wire unbound generator into regenerateOutputs

WithUnboundGenerator option + fail-soft branch (log, never fail the
mutation), matching hosts/dnsmasq. Refresh output doc comments.

Refs #349"
```

---

## Task 5: CLI wiring — construct the generator in `serve`

**Files:**

- Modify: `internal/client/commands/serve.go:88-92`

- [ ] **Step 1: Add the wiring block**

In `internal/client/commands/serve.go`, after the dnsmasq block (`:88-92`):

```go
	// unbound conf-dir generator (optional, additive)
	if cfg.Server.UnboundConfPath != "" {
		unboundGen := server.NewUnboundConfGenerator(cfg.Server.UnboundConfPath, cfg.Server.UnboundTTL)
		svcOpts = append(svcOpts, server.WithUnboundGenerator(unboundGen))
	}
```

Startup regeneration is already covered by the existing `svc.RegenerateOutputs(ctx)` (`serve.go:168`); per-mutation regeneration and hooks run through the same `regenerateOutputs` path wired in Task 4. No further changes.

- [ ] **Step 2: Build**

Run: `task build`
Expected: PASS (compiles). This wiring mirrors the dnsmasq block exactly and, like it, has no `serve`-command unit test; it is exercised by the Task 4 service test plus the smoke check below.

- [ ] **Step 3: Smoke-test the write path**

Run (from repo root, adjust binary path from `task build` output):

```bash
tmp=$(mktemp -d)
cat > "$tmp/server.toml" <<EOF
[server]
bind_address = "127.0.0.1:0"
unbound_conf_path = "$tmp/router-hosts.conf"
[database]
path = "$tmp/hosts.db"
[tls]
cert_path = "$tmp/c" 
key_path = "$tmp/k"
ca_cert_path = "$tmp/ca"
EOF
```

Then confirm config **loads and validates** (the leak-class value here is that an unbound-only config is now accepted):

Run: `go test ./internal/config/ -run TestLoadServerConfig_UnboundConfPathOnly -v`
Expected: PASS — verifies the end-to-end config path that `serve` consumes. (A full `serve` boot needs real mTLS material; the config + service tests already cover the generator's runtime behavior, so a live boot is optional.)

- [ ] **Step 4: Commit**

```
jj commit -m "feat(server): construct unbound generator from serve config

Wire unbound_conf_path/unbound_ttl into the serve command, mirroring the
dnsmasq_conf_path block. Refs #349"
```

---

## Task 6: Documentation — `configuration.md` (rows, three-way line, example)

**Files:**

- Modify: `docs/reference/configuration.md:12-35`

- [ ] **Step 1: Update the config table and validation line**

In `docs/reference/configuration.md`, add a row after the `dnsmasq_conf_path` row (`:13`):

```markdown
| `unbound_conf_path` | path | - | Output unbound conf-dir file of `local-zone`/`local-data` directives (additive) |
| `unbound_ttl` | int | `300` | TTL (seconds) for `unbound_conf_path` `local-data` records |
```

Change the "at least one" line (`:15`) to:

```markdown
At least one of `hosts_file_path`, `dnsmasq_conf_path`, or `unbound_conf_path` must be set.
```

- [ ] **Step 2: Add a worked example + footgun note**

After the existing dnsmasq example block (`:17-35`), add:

````markdown
When `unbound_conf_path` is configured, router-hosts writes, per managed name,
one `local-zone: "<fqdn>." static` plus its `local-data` records:

```
local-zone: "api.fzymgc.house." static
local-data: "api.fzymgc.house. 300 IN A 10.0.0.5"
local-data: "api.fzymgc.house. 300 IN AAAA fd00::5"
```

`static` answers the listed record types and returns NODATA for any other type
at that name, so a name's missing types (e.g. AAAA, HTTPS/type-65) are never
forwarded upstream. Names are emitted **verbatim** (trailing-dot normalized): a
bare, non-FQDN alias (e.g. `api`) becomes `local-zone: "api." static`, making
unbound authoritative for that entire pseudo-TLD — inventories MUST carry FQDNs.
Reload is out of scope: point a host-side systemd path unit at the conf
directory to reload unbound on write.
````

- [ ] **Step 3: Add the operations-guide DNS-output section (spec-committed footgun)**

In `docs/guides/operations.md`, insert a new section immediately **before** `## Certificate Reload via SIGHUP` (`:53`):

````markdown
## DNS Output Files

Beyond the hosts file, the server can emit authoritative DNS config — one
generator per configured `[server]` path, all rewritten atomically on startup
and after every successful mutation, and observed by `on_success`/`on_failure`
hooks:

- `hosts_file_path` — hosts(5) file.
- `dnsmasq_conf_path` — dnsmasq `local=`/`address=` pairs.
- `unbound_conf_path` — unbound `local-zone: "<fqdn>." static` + `local-data`.

### unbound reload

router-hosts writes `unbound_conf_path` atomically but does **not** reload
unbound. Point a host-side systemd path unit at the conf directory so unbound
reloads on write:

```ini
# /etc/systemd/system/unbound-reload.path
[Path]
PathModified=/etc/unbound/unbound.conf.d
[Install]
WantedBy=multi-user.target
```

with a companion `unbound-reload.service` that runs `unbound-control reload`.

### FQDN footgun

`unbound_conf_path` emits every hostname and alias **verbatim** (trailing-dot
normalized). A bare, non-FQDN alias such as `api` becomes
`local-zone: "api." static`, making unbound authoritative for that entire
pseudo-TLD and returning NXDOMAIN for everything under it. Inventories MUST carry
FQDNs.
````

- [ ] **Step 4: Add the `server.toml.example` unbound block (parity with dnsmasq)**

In `examples/server.toml.example`, after the commented `dnsmasq_conf_path` line (`:20`), insert:

```toml

# Optional: also emit an unbound conf-dir file of authoritative local-zone/
# local-data directives (one `local-zone: "<fqdn>." static` plus A/AAAA
# local-data per name). `static` answers listed types and returns NODATA for the
# rest, so a name's missing types (AAAA, HTTPS/type-65 ECH) never leak upstream —
# even where dnsmasq cannot suppress unknown RR types. Names are emitted
# verbatim, so inventories must carry FQDNs. Additive; at least one output is
# required. unbound_ttl defaults to 300. See GH #349.
# unbound_conf_path = "/etc/unbound/unbound.conf.d/router-hosts.conf"
# unbound_ttl = 300
```

- [ ] **Step 5: Lint the docs**

Run: `rumdl check docs/reference/configuration.md docs/guides/operations.md`
Expected: PASS (no markdown lint findings). Note: rumdl runs via the lefthook pre-commit hook (`lefthook.yaml`), not `task lint`, so invoke it directly here. `examples/server.toml.example` is TOML — validated by build/config parsing, not rumdl.

- [ ] **Step 6: Commit**

```
jj commit -m "docs(config): document unbound_conf_path and unbound_ttl

configuration.md table rows + three-way validation line + worked example;
operations.md DNS-output section (unbound reload + FQDN footgun);
server.toml.example commented block.

Closes #349"
```

---

## Final verification

- [ ] **Run the full local CI pipeline**

Run: `task ci`
Expected: PASS — lint (golangci-lint + buf), race tests, build, coverage ≥ 80%.

- [ ] **Confirm spec coverage**

Every spec section maps to a task: config (T1), generator format + grouping (T2), write path (T3), service wiring + fail-soft (T4), CLI wiring (T5), docs surfaces — `configuration.md` + `operations.md` (FQDN footgun, spec-committed) + `server.toml.example` (T6). Reload, PTR, FQDN-enforcement remain out of scope per the spec.
<!-- adr-capture: sha256=3c9439c05c9f4e41; session=cli; ts=2026-07-07T21:06:21Z; adrs=router-hosts-bzg -->
