// Package eventid mints event IDs for router-hosts.
//
// Every domain.EventEnvelope.EventID in this system is a ULID, and
// MAX(event_id) is used as the server's change ID (TMPL-08, D-18). An ID that
// sorts below an ID already in the log would make the change ID fail to
// advance across a real state change, and a deduping consumer would then keep
// serving a stale zone with no error anywhere.
//
// This package makes minting monotonic; it does not make commits ordered.
// The ordering guarantee the change ID depends on is enforced in the append
// transaction (internal/storage/sqlite), and this package is what that guard
// mints through.
package eventid

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Generator mints ULIDs that are strictly increasing against a raisable
// floor: the greatest value this generator has issued or been seeded with.
// It is safe for concurrent use.
type Generator struct {
	mu      sync.Mutex
	entropy *ulid.LockedMonotonicReader
	floor   ulid.ULID
}

// NewGenerator returns a Generator with a zero floor. Production code uses
// the package-level New/Seed/NewAfter, which delegate to a shared singleton;
// NewGenerator exists so a test can construct one whose floor it fully
// controls, and so this package's own tests do not share state with each
// other.
func NewGenerator() *Generator {
	// ulid.Monotonic's inc=0 defaults the increment ceiling to math.MaxUint32,
	// which is what makes successive IDs inside one millisecond strictly
	// increasing rather than random. *ulid.MonotonicEntropy is not
	// goroutine-safe on its own, so it is wrapped in the library's
	// LockedMonotonicReader; Generator's own mutex additionally guards the
	// floor read-compare-write, which must be atomic with the mint.
	return &Generator{
		entropy: &ulid.LockedMonotonicReader{MonotonicReader: ulid.Monotonic(rand.Reader, 0)},
	}
}

// New mints a ULID guaranteed to sort strictly greater than every value this
// generator has previously returned or been seeded with, even when many
// calls land inside the same millisecond or the wall clock steps backward.
func (g *Generator) New() ulid.ULID {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := ulid.MustNew(ulid.Timestamp(time.Now()), g.entropy)
	if id.Compare(g.floor) <= 0 {
		id = next(g.floor)
	}
	g.floor = id
	return id
}

// Seed raises the floor to u when u compares greater than the current floor,
// and otherwise does nothing. Seed is monotonic and idempotent: a caller can
// never lower the floor by calling it. Its purpose is to make this generator
// monotonic against a persisted log at startup, not only against its own
// history.
func (g *Generator) Seed(u ulid.ULID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if u.Compare(g.floor) > 0 {
		g.floor = u
	}
}

// NewAfter seeds the floor with lower and then mints, guaranteeing the
// result sorts strictly greater than lower regardless of what this
// generator's floor already was. This is the entry point the in-transaction
// append guard uses to re-mint a proposed event ID that does not already
// sort above the log's current maximum.
func (g *Generator) NewAfter(lower ulid.ULID) ulid.ULID {
	g.Seed(lower)
	return g.New()
}

// next returns the smallest ULID strictly greater than u: it increments the
// 80-bit entropy portion (bytes 6 through 15, big-endian) with carry, and if
// that wraps to all zeros, carries into the 48-bit timestamp portion (bytes
// 0 through 5) and leaves the entropy at zero. Carrying into the timestamp
// can produce an ID whose embedded millisecond is a hair in the future,
// which is correct and preferable to a tie — the timestamp is an ordering
// key here, not a claim about wall-clock time.
func next(u ulid.ULID) ulid.ULID {
	out := u
	for i := 15; i >= 6; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	for i := 5; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// defaultGenerator is the process-wide singleton production code mints
// through. defaultMu guards swapping the singleton itself; it does not guard
// minting, which Generator's own mutex already serializes.
var (
	defaultMu        sync.RWMutex
	defaultGenerator = NewGenerator()
)

// New mints a ULID through the package singleton. This is the production
// entry point every non-test caller uses; nothing outside this package
// touches a *Generator directly except a test.
func New() ulid.ULID {
	defaultMu.RLock()
	g := defaultGenerator
	defaultMu.RUnlock()
	return g.New()
}

// Seed raises the package singleton's floor. See Generator.Seed. Its purpose
// is to make the process generator monotonic against a persisted log at
// startup: sqlite.Storage.Initialize calls this with LatestEventID after
// migrations.
func Seed(u ulid.ULID) {
	defaultMu.RLock()
	g := defaultGenerator
	defaultMu.RUnlock()
	g.Seed(u)
}

// NewAfter mints through the package singleton after seeding it with lower.
// See Generator.NewAfter. This is the entry point the in-transaction
// append guard uses to re-mint a proposed event ID.
func NewAfter(lower ulid.ULID) ulid.ULID {
	defaultMu.RLock()
	g := defaultGenerator
	defaultMu.RUnlock()
	return g.NewAfter(lower)
}

// SwapDefault installs g as the package singleton and returns a restore
// function that reinstalls the previous one. It exists for exactly one
// purpose: a test that must observe a generator whose floor it controls,
// because the floor is monotonic by design and therefore cannot be lowered.
// Production code never calls this. A test that calls it must not use
// t.Parallel(), because it mutates process-wide state.
func SwapDefault(g *Generator) (restore func()) {
	defaultMu.Lock()
	prev := defaultGenerator
	defaultGenerator = g
	defaultMu.Unlock()
	return func() {
		defaultMu.Lock()
		defaultGenerator = prev
		defaultMu.Unlock()
	}
}
