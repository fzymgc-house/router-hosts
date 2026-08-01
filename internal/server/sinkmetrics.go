package server

import (
	"log/slog"
	"sync"
	"time"
)

// MaxTrackedSinks bounds the number of entries SinkHealth holds, and
// therefore the number of per-identity series the server exports at any one
// time. It does NOT bound the number of distinct label values a metrics
// backend has observed over the process's lifetime: an evicted common name
// that reconnects reappears in the registry, and the backend retains both
// the old and the new series. What genuinely bounds cardinality is the
// label source, not this ceiling — label values come only from CA-issued
// mTLS common names (D-13), never from anything a caller supplies in a
// request body. Declared as a var (not a const) so tests can temporarily
// lower it to drive eviction without seeding a thousand real entries.
var MaxTrackedSinks = 1000

// SinkState is one consumer's health record. LastSuccess (write health) and
// ReloadFailed/LastReloadSuccess (reload health) are deliberately separate
// fields, never derived from one another (D-12a): a consumer can write its
// rendered artifact successfully while its post-write reload hook fails,
// and that middle outcome — artifact current, resolver possibly stale — is
// a different operational signal from either a stale artifact or a failed
// write.
type SinkState struct {
	// LastSeen is refreshed on every RecordSeen or RecordStatus call for
	// this identity, independent of what either call reports.
	LastSeen time.Time
	// LastSuccess is the consumer-reported time of its last successful
	// artifact write.
	LastSuccess time.Time
	// ConsecutiveFailures is the consumer-reported count of consecutive
	// render/write failures since its last success.
	ConsecutiveFailures int64
	// ContractVersion is the consumer-reported template/data contract
	// version it last rendered against.
	ContractVersion string
	// RenderedChangeID is the change ID the consumer last rendered
	// against. Compared against the server's current change ID to derive
	// convergence; never emitted as a metric label (D-13, review M6) since
	// it changes on every mutation and would be unbounded cardinality by
	// construction.
	RenderedChangeID string
	// ReloadFailed is true when the consumer's last post-write reload hook
	// failed. Independent of LastSuccess (D-12a).
	ReloadFailed bool
	// LastReloadSuccess is the consumer-reported time of its last
	// successful reload.
	LastReloadSuccess time.Time
}

// SinkSnapshot is a point-in-time, defensively-copied read of a SinkHealth
// registry, safe to range over and mutate without affecting the registry.
type SinkSnapshot struct {
	States           map[string]SinkState
	Connected        int64
	IdentityFailures int64
	ServerChangeID   string
}

// SinkHealth is an in-memory, concurrency-safe per-consumer health
// registry. It is the durable source of truth (D-10): a consumer's record
// survives its stream closing and is lost only on server restart. The OTel
// observable-gauge callback (see (*Metrics).RegisterSinkGauges) only
// projects this state at scrape time — it never mutates the registry —
// which is what makes D-10's survives-close retention compatible with
// OTel's pull model.
type SinkHealth struct {
	mu               sync.Mutex
	states           map[string]SinkState
	connected        int64
	identityFailures int64
	serverChangeID   string
}

// NewSinkHealth creates an empty registry.
func NewSinkHealth() *SinkHealth {
	return &SinkHealth{states: make(map[string]SinkState)}
}

// ensureCapacityForNewLocked evicts the oldest-LastSeen entry before cn is
// inserted, if cn is not already tracked and the registry is at
// MaxTrackedSinks. Caller must hold h.mu. A no-op when cn already has an
// entry: an update to an existing identity never counts against the
// ceiling.
func (h *SinkHealth) ensureCapacityForNewLocked(cn string) {
	if _, exists := h.states[cn]; exists {
		return
	}
	if len(h.states) >= MaxTrackedSinks {
		h.evictOldestLocked()
	}
}

// evictOldestLocked removes the tracked identity with the oldest LastSeen.
// Caller must hold h.mu.
//
// Known limitation, accepted rather than fixed (review L3, rejected with
// rationale): eviction does not distinguish a connected sink from a
// disconnected one, so once more than MaxTrackedSinks identities are
// simultaneously tracked, a long-quiet but still-connected sink can lose
// its record; its gauges briefly read as absent until its next status
// report recreates the entry. Fixing this would require Connect/Disconnect
// to carry an identity, but they are deliberately identity-free (see
// Connect/Disconnect below) so that a stream whose peer common name could
// not be verified still counts. This is a self-healing limitation, not a
// bug: the entry reappears on the evicted sink's next report.
func (h *SinkHealth) evictOldestLocked() {
	var (
		oldestCN   string
		oldestSeen time.Time
		found      bool
	)
	for cn, st := range h.states {
		if !found || st.LastSeen.Before(oldestSeen) {
			oldestCN = cn
			oldestSeen = st.LastSeen
			found = true
		}
	}
	if !found {
		return
	}
	delete(h.states, oldestCN)
	slog.Warn("sink health registry evicted oldest tracked identity",
		"cn", oldestCN, "max_tracked_sinks", MaxTrackedSinks)
}

// RecordSeen sets LastSeen to now for cn, creating the entry if it does not
// already exist (subject to the MaxTrackedSinks eviction ceiling).
func (h *SinkHealth) RecordSeen(cn string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ensureCapacityForNewLocked(cn)
	st := h.states[cn]
	st.LastSeen = time.Now().UTC()
	h.states[cn] = st
}

// RecordStatus stores the reported LastSuccess, ConsecutiveFailures,
// ContractVersion, RenderedChangeID, ReloadFailed, and LastReloadSuccess
// fields for cn, and refreshes LastSeen. Takes a struct rather than a
// widening positional parameter list — six positional arguments is where
// transposed-argument bugs live. LastSuccess and ReloadFailed are
// independent fields (D-12a): this method never derives one from the
// other.
//
// Duplicate common names collapse, last-writer-wins (review M6): nothing
// in this repo enforces unique CN issuance, so two connections presenting
// the same certificate subject — for example, two consumers provisioned
// from one copied client certificate — share one record, and the later
// report overwrites the earlier one. For a duplicated CN, sink_converged
// and the failure count describe whichever consumer reported most
// recently, not both, and the two are indistinguishable in metrics. The
// key stays the CN rather than a certificate fingerprint: D-13 chose the
// CN because it is the operator's own readable consumer identifier, and a
// fingerprint label would be unreadable on a dashboard. The deployment
// requirement this implies — one certificate common name per consumer — is
// carried in plan 08's operator guide.
func (h *SinkHealth) RecordStatus(cn string, st SinkState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ensureCapacityForNewLocked(cn)
	st.LastSeen = time.Now().UTC()
	h.states[cn] = st
}

// RecordServerChange stores the server's single current change ID. One
// string for the whole server, not one per consumer — the change ID
// identifies state, so every consumer is compared against the same value
// (D-19).
func (h *SinkHealth) RecordServerChange(changeID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.serverChangeID = changeID
}

// Connect increments the connected-stream count. It takes no common name:
// router_hosts_sinks_connected carries no labels, so the count needs no
// identity, and keeping it identity-free is what lets a stream whose peer
// identity could not be verified still be counted — and lets a test
// observe handler teardown deterministically without needing a verified
// certificate chain.
func (h *SinkHealth) Connect() {
	h.mu.Lock()
	h.connected++
	h.mu.Unlock()
}

// Disconnect decrements the connected-stream count, floored at zero even if
// called more times than Connect. It deliberately leaves any state entry
// for the disconnecting stream's identity in place — that retention is
// D-10 and is what removes the clean-shutdown-versus-crash ambiguity from
// a sink's last-known health.
func (h *SinkHealth) Disconnect() {
	h.mu.Lock()
	if h.connected > 0 {
		h.connected--
	}
	h.mu.Unlock()
}

// RecordIdentityFailure increments the count of streams whose peer
// certificate identity could not be extracted. It takes no argument for
// the same reason Connect does not: there is by definition no verified
// identity to attribute the failure to, and attributing it to anything the
// caller supplied would be the exact substitution D-13 forbids (review
// L11).
func (h *SinkHealth) RecordIdentityFailure() {
	h.mu.Lock()
	h.identityFailures++
	h.mu.Unlock()
}

// Snapshot returns a point-in-time, defensively-copied view of the
// registry. Mutating the returned SinkSnapshot's map does not affect h.
func (h *SinkHealth) Snapshot() SinkSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	states := make(map[string]SinkState, len(h.states))
	for cn, st := range h.states {
		states[cn] = st
	}
	return SinkSnapshot{
		States:           states,
		Connected:        h.connected,
		IdentityFailures: h.identityFailures,
		ServerChangeID:   h.serverChangeID,
	}
}
