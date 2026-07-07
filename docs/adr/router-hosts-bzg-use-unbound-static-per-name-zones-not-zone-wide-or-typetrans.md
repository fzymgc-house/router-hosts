---
title: "Use unbound static per-name zones, not zone-wide or typetransparent"
---
<!-- markdownlint-disable MD013 -->
<!-- adr-render: source=bd:router-hosts-bzg; do not edit manually; use `/adr update router-hosts-bzg` -->

**Date:** 2026-07-07
**Status:** Accepted
**Decision:** router-hosts-bzg
**Deciders:** Sean

## Context

router-hosts optionally emits authoritative split-horizon DNS config so LAN names for `fzymgc.house` never leak upstream record types. The Firewalla's dnsmasq v2.82 cannot suppress unknown RR types, so the existing `dnsmasq_conf_path` output still leaked HTTPS/type-65 (ECH) and AAAA records for Cloudflare-proxied names, breaking Chromium (`ERR_ECH_FALLBACK_CERTIFICATE_INVALID`) and OAuth flows. The new `unbound_conf_path` output (GH #349) must close this leak class. unbound's `local-zone` type determines whether a queried type with no local-data returns NODATA, forwards to recursion, or NXDOMAINs — which directly decides whether the leak is closed and what collateral behavior unmanaged names get.

## Decision

Emit one `local-zone: "<fqdn>." static` per managed name (the hostname and each alias), with that name's A/AAAA `local-data` lines beneath it. A `static` zone answers the listed record types and returns NODATA for any other type at that name, and NXDOMAIN for a name inside the zone that has no local-data. Do NOT use `typetransparent`, and do NOT declare a single zone-wide `local-zone` for the domain.

## Rationale

- `typetransparent` passes missing record types through to recursion, re-leaking the public HTTPS/AAAA records — reproducing the exact bug being fixed.
- A single zone-wide `static` zone for `fzymgc.house.` would NXDOMAIN every unmanaged sibling name under the domain (collateral damage beyond managed names).
- Per-name `static` bounds the authoritative blast radius to exactly the managed name: NODATA for its missing types, while unmanaged names outside any emitted zone keep recursing normally.
- Grounded on unbound 1.19.1 and deepwiki `NLnetLabs/unbound` (`services/localzone.c`): `static` returns NODATA for unlisted types and NXDOMAIN for no-data names.

## Alternatives Considered

- **Per-name `local-zone "<fqdn>." static` (chosen):** closes the ECH/AAAA leak (NODATA, no forward) with a blast radius bounded to the managed name. Footgun: a bare, non-FQDN alias becomes authoritative for a whole pseudo-TLD.
- **`typetransparent` (rejected):** forwards missing types to recursion → re-leaks HTTPS/AAAA, reintroducing the bug.
- **Zone-wide `static` (rejected):** NXDOMAINs unmanaged sibling names under the domain.

## Consequences

- Positive: definitively closes the HTTPS/type-65 ECH + AAAA leak class at the resolver level.
- Negative: a bare, non-FQDN alias makes unbound authoritative for that entire pseudo-TLD, NXDOMAIN-ing everything under it — inventories MUST carry FQDNs (documented footgun, not enforced).
- Neutral: unmanaged names outside any emitted zone continue to recurse normally; unbound reload is out of scope (host-side systemd path unit).
