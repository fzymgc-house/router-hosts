# Constraints (SPEC Intel)

Extracted from 10 SPEC-classified design documents. Each defines implementation contracts (data models, API/gRPC schemas, config schemas, protocols). None is a locked ADR; where a SPEC overlaps a locked ADR, the ADR is authoritative (see INGEST-CONFLICTS.md INFO entries).

---

## CON-router-hosts-v1-architecture

- source: docs/plans/2025-12-01-router-hosts-v1-design.md
- type: api-contract / schema
- scope: gRPC API, mTLS, event store, hosts file, host-entry data model, domain events, CLI

Event-sourced DNS host management via gRPC/mTLS client-server architecture. Defines the host-entry data model, domain events, event-store contract, hosts-file output, and validation rules. Foundational spec for the whole system. (Cross-refs 2025-11-28 / 2025-11-30 predecessor docs that are outside this ingest set.)

---

## CON-sighup-cert-reload

- source: docs/plans/2025-12-15-sighup-cert-reload-design.md
- type: protocol
- scope: SIGHUP signal handling, TLS certificate reload, server run loop, graceful shutdown, Vault Agent cert rotation

Dynamic TLS certificate reload via SIGHUP with validation and graceful restart of the server loop, supporting Vault Agent cert rotation.

---

## CON-hosts-aliases

- source: docs/plans/2025-12-16-hosts-aliases-design.md
- type: api-contract / schema
- scope: hosts-file aliases, canonical hostname, UpdateHostRequest protobuf, TagsUpdate/AliasesUpdate wrappers, HostEntry data model, import/export

Adds hostname alias support with protobuf update-wrapper API changes (TagsUpdate/AliasesUpdate), HostEntry data-model changes, and breaking-change semantics for import/export.

---

## CON-acme-support

- source: docs/plans/2025-12-19-acme-support-design.md
- type: protocol / api-contract
- scope: ACME certificate management, server TLS, HTTP-01 + DNS-01 challenges, Cloudflare DNS provider, config env expansion, SIGHUP reload

Automatic TLS certificate management via ACME (HTTP-01/DNS-01) for the server, including config env expansion and integration with SIGHUP reload.

---

## CON-dns01-implementation

- source: docs/plans/2025-12-22-dns01-implementation-design.md
- type: api-contract / protocol
- scope: DNS-01 challenge, DnsProvider trait, Cloudflare + generic webhook providers, TXT-record propagation, renewal loop

DNS-01 ACME challenge support with a DNS provider trait abstraction, Cloudflare and generic webhook providers, TXT-record propagation, and a renewal loop. (High confidence.)

---

## CON-operator-design

- source: docs/plans/2025-12-24-router-hosts-operator-design.md
- type: api-contract / schema
- scope: Kubernetes controller, CRDs, RouterHostsConfig, IngressRoute, gRPC/mTLS API, IP resolution, deletion scheduler

Kubernetes operator that syncs Ingress/IngressRoute hostnames to a router-hosts server via gRPC/mTLS. Defines CRD schemas, IP resolution, and a deletion scheduler. Status: Draft.

---

## CON-service-controller

- source: docs/plans/2026-01-02-service-controller-design.md
- type: api-contract / schema
- scope: operator Service controller, LoadBalancer + NodePort Services, DNS entries, annotations

Operator controller watching Kubernetes Services to create DNS entries for LoadBalancer and NodePort types, with annotation schemas and IP-resolution rules.

---

## CON-gateway-api-support

- source: docs/plans/2026-06-07-gateway-api-support-design.md
- type: api-contract / schema
- scope: cmd/operator, GatewayRouteReconciler, HTTPRoute/GRPCRoute/TLSRoute, Gateway status.addresses, sigs.k8s.io/gateway-api, RBAC ClusterRole, Helm chart

New operator controller watching Kubernetes Gateway API route resources (HTTPRoute/GRPCRoute/TLSRoute) syncing route hostnames to the gRPC server, with RBAC and Helm chart updates. Status: Draft.

---

## CON-aggregate-compaction

- source: docs/superpowers/specs/2026-06-26-aggregate-compaction-design.md
- type: schema / nfr
- scope: aggregate compaction, event store, HostProjection, compaction event type, event-count metric, WriteQueue, SQLite eventstore

Operator-driven aggregate compaction operation plus a cardinality-safe per-aggregate event-count metric. Defines the compaction event type, storage atomicity, and metrics collection. GOVERNED BY locked ADRs router-hosts-v5b, -vl8, -4w2 — the ADRs are authoritative where they overlap. Status: Draft.

---

## CON-unbound-conf-path

- source: docs/superpowers/specs/2026-07-07-unbound-conf-path-design.md
- type: schema / protocol
- scope: unbound_conf_path + unbound_ttl config options, UnboundConfGenerator, internal/server/unboundconf.go, internal/config/server.go, service.go, serve.go, DNS output generation

New optional server output emitting authoritative unbound `local-zone`/`local-data` directives per managed name. Defines config schema, generator signatures, output format, and test plan. GOVERNED BY locked ADR router-hosts-bzg (per-name `static` zones, not typetransparent/zone-wide) — the ADR is authoritative for the local-zone type decision. Status: Draft.
