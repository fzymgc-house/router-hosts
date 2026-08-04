// Package ciwiring holds structural invariant tests over
// .github/workflows/ci-go.yml. It asserts that every gated-tier job declared
// in the workflow — currently the e2e-* tiers (Phase 1) and the bench-*
// LAZY-02 benchmark gate (Phase 2) — is represented in the ci-go-complete
// aggregator's needs list, its per-job result env var, and its
// "!= success" result check — so a tier that runs and reports but is never
// wired into the required check cannot be added silently. The package holds
// no production code: it exists only to give the invariant test a stable,
// importable home outside internal/e2e's build-tagged files.
package ciwiring
