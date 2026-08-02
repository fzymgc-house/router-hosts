// Package contract holds the template data contract's version, owned by
// neither the server package nor the client template package so that
// neither one claims the other's constant (cross-AI review round-2 L9).
// The server advertises this value on every WatchHosts SnapshotComplete
// terminator; the client template package compares a template's declared
// version against what the server served. Both import this package rather
// than one importing the other.
//
// This package is deliberately tiny: it holds constants only and imports
// nothing outside the standard library, so no import cycle is possible in
// either direction.
package contract

// TemplateVersion is the current version of the template data contract
// (internal/client/template.Data and internal/client/template.Entry). It
// changes only when a field or a template function is renamed or removed
// from the contract. See docs/reference/template-contract.md (added by
// phase plan 02) for the authoritative definition of the contract this
// version numbers.
const TemplateVersion = "1"
