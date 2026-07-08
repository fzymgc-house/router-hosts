# Ingest Synthesis Summary

Single entry point for `gsd-roadmapper`. Mode: new (bootstrap). Precedence: ADR > SPEC > PRD > DOC.

## Doc counts by type (27 total)

- ADR: 4 (all locked)
- SPEC: 10
- PRD: 0
- DOC: 13

## Decisions locked (4)

- router-hosts-4w2 — Sacrifice GetAtTime time-travel across compaction — docs/adr/router-hosts-4w2-sacrifice-getattime-time-travel-across-compaction.md
- router-hosts-bzg — Use unbound static per-name zones (not zone-wide/typetransparent) — docs/adr/router-hosts-bzg-use-unbound-static-per-name-zones-not-zone-wide-or-typetrans.md
- router-hosts-v5b — Compact aggregates via HostCompacted seed event — docs/adr/router-hosts-v5b-compact-aggregates-via-hostcompacted-seed-event.md
- router-hosts-vl8 — Scope compaction to manual remediate+observe — docs/adr/router-hosts-vl8-scope-compaction-manual-remediate-observe.md

All four mutually consistent. Detail: intel/decisions.md

## Requirements extracted (0)

No PRDs in ingest set. No formal requirements or competing acceptance variants. Roadmapper should derive requirement candidates from SPEC constraints gated by the locked ADRs. Detail: intel/requirements.md

## Constraints (10 SPECs)

By type (SPECs often span multiple): api-contract/schema ~7 (v1 architecture, hosts-aliases, operator, service-controller, gateway-api, dns01, unbound-conf), protocol ~3 (sighup-cert-reload, acme-support, dns01), schema/nfr ~2 (aggregate-compaction, unbound-conf). Detail: intel/constraints.md

## Context topics (13 DOCs)

Certificate reload, hosts aliases, ACME/testing, Kubernetes operator, storage (SQLite/DuckDB), observability (OTel), Go migration, aggregate compaction, unbound conf output. Detail: intel/context.md

## Conflicts

- Blockers: 0
- Competing variants: 0
- Auto-resolved / INFO: 3 (ADR>SPEC on unbound; ADR>SPEC on compaction; Rust→Go stack supersession)

Full report: .planning/INGEST-CONFLICTS.md

## Notable synthesis flags for roadmapper

- Rust→Go supersession: sqlite-default-*, acme-pebble-testing, operator-impl, service-controller-impl reference a Rust stack superseded by the 2026-02-22 Go migration. Current architecture is Go, SQLite-only, Go cmd/operator. Do not plan against the Rust paths.
- Compaction feature (v5b/vl8/4w2 + aggregate-compaction SPEC) and unbound_conf_path feature (bzg + unbound-conf SPEC) are the two most recent, fully-decided feature spines — locked ADRs available.
