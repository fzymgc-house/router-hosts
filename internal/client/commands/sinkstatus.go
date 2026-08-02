package commands

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/atomicfile"
)

// sinkStatus is the local sidecar record a "watch" sink writes atomically
// alongside its rendered artifact (D-11, D-12a, TMPL-08). It exists
// specifically for the server-down case: when the server is unreachable,
// server-side metrics are unavailable by definition while the sink keeps
// serving its last-good artifact — this file is then the only health signal
// an operator has.
//
// LastSuccess/ConsecutiveFailures (write health) and
// ReloadFailed/LastReloadSuccess (reload health) are deliberately separate
// fields, never derived from one another (D-12a): a sink can write its
// rendered artifact successfully while its post-write reload hook fails,
// and that middle outcome — artifact current, resolver possibly stale — is
// a different operational signal than either a stale artifact or a failed
// write. "Your zone file is correct but your resolver did not pick it up"
// must be distinguishable from "your zone file is old".
type sinkStatus struct {
	// LastSuccess is the time of the sink's last successful render+write.
	LastSuccess time.Time `json:"last_success"`
	// LastError is the text of the most recent render/write/connection
	// failure, cleared on the next success.
	LastError string `json:"last_error"`
	// ConsecutiveFailures counts render/write/connection failures since the
	// last success. Never incremented by a reload (hook) failure.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// ContractVersion is the template/data contract version this sink was
	// built against.
	ContractVersion string `json:"contract_version"`
	// RenderedChangeID is the change ID (see SnapshotComplete.change_id)
	// this sink last rendered. A caller must not trust this value unless
	// the artifact itself still exists on disk: the sidecar and the
	// artifact are written separately, and an out-of-band deletion of the
	// artifact leaves this field pointing at data that is no longer
	// present.
	RenderedChangeID string `json:"rendered_change_id"`
	// ReloadFailed is true when the sink's last post-write reload hook
	// failed. Independent of LastSuccess/ConsecutiveFailures (D-12a).
	ReloadFailed bool `json:"reload_failed"`
	// LastReloadSuccess is the time of the sink's last successful reload
	// hook run.
	LastReloadSuccess time.Time `json:"last_reload_success"`
}

// defaultStatusPath returns the sidecar status path for an artifact at
// artifactPath: the artifact path with ".status" appended.
func defaultStatusPath(artifactPath string) string {
	return artifactPath + ".status"
}

// writeSinkStatus marshals st as indented JSON, appends a trailing newline,
// and writes it to path through the shared atomic writer (the same
// write-and-rename path the artifact itself uses), so a concurrent reader
// never observes a partial or torn record.
func writeSinkStatus(path string, st sinkStatus) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return oops.Wrapf(err, "marshal sink status")
	}
	data = append(data, '\n')
	if err := atomicfile.Write(path, data); err != nil {
		return oops.Wrapf(err, "write sink status %s", path)
	}
	return nil
}

// readSinkStatus reads and parses the sidecar status file at path. A
// nonexistent file is NOT an error — it returns the zero sinkStatus and a
// nil error, because a first run has nothing to report yet. Any other read
// failure, or content that does not parse as JSON, is returned as a wrapped
// error: a corrupt sidecar is reported so the caller treats the state as
// unknown, rather than being silently treated as "never rendered".
//
// See sinkStatus.RenderedChangeID's doc comment: a caller must additionally
// confirm the artifact still exists on disk before trusting that field.
func readSinkStatus(path string) (sinkStatus, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return sinkStatus{}, nil
	}
	if err != nil {
		return sinkStatus{}, oops.Wrapf(err, "read sink status %s", path)
	}
	var st sinkStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return sinkStatus{}, oops.Wrapf(err, "parse sink status %s", path)
	}
	return st, nil
}

// sinkHealthState is the single mutex-guarded owner of every field shared
// between the watch command's receive loop (which writes) and its status
// ticker (which reads) — review H4. Both access state only through the
// methods below; the ticker reads state only through snapshot(), which
// returns a value copy, so no caller ever holds a pointer into this type.
// sinkStatus stays a value type with no reference-typed fields so that copy
// is a real, independent copy. This mirrors the locking discipline
// internal/server/hookrunner.go already uses in this repo — it is the house
// style, not an invention, and the suite runs under -race so an unlocked
// accessor here would fail the build, not merely be untidy.
//
// The artifact is never rolled back on a hook (reload) failure, and no
// method on this type ever attempts to: on hook failure it is unknown
// whether the resolver already read the new file, so reverting the artifact
// could leave the on-disk file and the running resolver actively
// disagreeing — strictly worse than retaining a correct file whose reload
// failed. Retention plus a distinguishable health signal (ReloadFailed) is
// the contract (D-12a).
type sinkHealthState struct {
	mu sync.Mutex
	st sinkStatus
}

// adopt replaces the held status wholesale with st, without going through
// any of the record* transitions below. Used exactly once, at startup, to
// seed state from a sidecar loaded off disk (review M3) — see watch.go's
// startup sequence, which adopts a loaded record only when the artifact it
// describes still exists.
func (s *sinkHealthState) adopt(st sinkStatus) {
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
}

// setContractVersion records the contract version the running sink was
// built against, independent of whatever a loaded sidecar carried (which
// may describe an older template).
func (s *sinkHealthState) setContractVersion(v string) {
	s.mu.Lock()
	s.st.ContractVersion = v
	s.mu.Unlock()
}

// recordSuccess marks a successful render+write: sets LastSuccess and
// RenderedChangeID, clears LastError, and zeroes ConsecutiveFailures. This
// is D-12a's first outcome, and it always runs before any post-write hook —
// a hook failure recorded afterward (recordReloadFailure) never has to
// guess whether the write itself succeeded, because this call already
// settled that question.
func (s *sinkHealthState) recordSuccess(changeID string, at time.Time) {
	s.mu.Lock()
	s.st.LastSuccess = at
	s.st.RenderedChangeID = changeID
	s.st.LastError = ""
	s.st.ConsecutiveFailures = 0
	s.mu.Unlock()
}

// recordReloadFailure is called after a successful write whose post-write
// hook then failed — D-12a's middle outcome, and the one review H3 found
// impossible to express as a reinterpretation of the write-failure fields.
// It sets ReloadFailed and LastError, and deliberately leaves LastSuccess,
// RenderedChangeID, and ConsecutiveFailures exactly as recordSuccess just
// set them: the artifact is current, only the reload is unconfirmed, and
// folding that into the write-failure count would make a
// correct-file-stale-resolver outcome indistinguishable from a genuinely
// stale file. The timestamp parameter is accepted for signature symmetry
// with recordSuccess and recordReloadSuccess; today's sinkStatus contract
// has no last-reload-attempt field to store it in.
func (s *sinkHealthState) recordReloadFailure(err error, _ time.Time) {
	s.mu.Lock()
	s.st.ReloadFailed = true
	if err != nil {
		s.st.LastError = err.Error()
	}
	s.mu.Unlock()
}

// recordReloadSuccess clears ReloadFailed and sets LastReloadSuccess.
func (s *sinkHealthState) recordReloadSuccess(at time.Time) {
	s.mu.Lock()
	s.st.ReloadFailed = false
	s.st.LastReloadSuccess = at
	s.mu.Unlock()
}

// recordFailure increments ConsecutiveFailures and sets LastError, while
// preserving LastSuccess and RenderedChangeID. Covers D-12a's first outcome
// (a render or write failure) and third outcome (connection loss): in both,
// the artifact was never replaced, so the previously rendered state is still
// what is on disk and still what RenderedChangeID should keep naming.
func (s *sinkHealthState) recordFailure(err error) {
	s.mu.Lock()
	s.st.ConsecutiveFailures++
	if err != nil {
		s.st.LastError = err.Error()
	}
	s.mu.Unlock()
}

// snapshot returns a point-in-time value copy of the held status, safe to
// read or serialize without further locking.
func (s *sinkHealthState) snapshot() sinkStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}
