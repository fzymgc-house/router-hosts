package commands

import (
	"math/rand"
	"time"
)

// WatchPolicy is the injectable runtime policy for the "watch" sink command:
// backoff bounds, jitter, and the status-report interval. It exists so
// timing can be injected from outside this package (review H4, H5, L13,
// M5): the phase 8 e2e suite lives in `package e2e_test`
// (e2e/helpers_test.go:3), an EXTERNAL test package, and cannot reach
// unexported package-level variables here — a package-level backoff
// variable, which the round-1 plan proposed, would not compile against from
// there.
//
// Production callers use DefaultWatchPolicy(). InitialBackoff, MaxBackoff,
// and Jitter are deliberately NOT CLI flags or TOML keys: each would be a
// permanent compatibility surface for a tuning need nobody has expressed.
//
// StatusInterval is the one exception, because it IS operator-facing (the
// --status-interval flag). Its precedence is stated once, at the flag's
// registration site in watch.go: the resolved policy supplies the flag's
// default, and an explicitly-changed flag overrides the policy (review
// round-3 M2).
type WatchPolicy struct {
	// InitialBackoff is the wait before the first reconnect attempt after a
	// stream ends in error.
	InitialBackoff time.Duration
	// MaxBackoff is the ceiling the exponential backoff is clamped to.
	MaxBackoff time.Duration
	// StatusInterval is how often the sink reports its health upstream on
	// the open stream, independent of whether host data changed.
	StatusInterval time.Duration
	// Jitter perturbs a computed backoff duration before it is used as a
	// wait. It is a function field, not an inline math/rand call, because a
	// backoff test that must assert an EXACT wait cannot do so against
	// package-level randomness (review L13): injecting the identity
	// function makes the schedule deterministic without weakening
	// production behavior. math/rand (not crypto/rand) is correct here —
	// this is scheduling jitter to break lockstep reconnects across a fleet
	// of sinks, not a security decision.
	Jitter func(time.Duration) time.Duration
}

// DefaultWatchPolicy returns the production policy: a 1 second initial
// backoff, a 60 second maximum, a 30 second status interval, and
// defaultJitter.
func DefaultWatchPolicy() WatchPolicy {
	return WatchPolicy{
		InitialBackoff: time.Second,
		MaxBackoff:     60 * time.Second,
		StatusInterval: 30 * time.Second,
		Jitter:         defaultJitter,
	}
}

// normalized substitutes DefaultWatchPolicy()'s value for any zero-valued
// field and the identity function for a nil Jitter, so a test (or a
// partially-populated caller) supplying only the fields it cares about
// cannot panic on a nil call or silently run with a zero interval.
func (p WatchPolicy) normalized() WatchPolicy {
	d := DefaultWatchPolicy()
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = d.InitialBackoff
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = d.MaxBackoff
	}
	if p.StatusInterval <= 0 {
		p.StatusInterval = d.StatusInterval
	}
	if p.Jitter == nil {
		p.Jitter = func(dur time.Duration) time.Duration { return dur }
	}
	return p
}

// defaultJitter returns a duration between half and one and a half times d,
// spreading reconnect attempts from a fleet of sinks that lost a server at
// the same instant (T-1-28) rather than reconnecting in lockstep.
func defaultJitter(d time.Duration) time.Duration {
	factor := 0.5 + rand.Float64()
	return time.Duration(float64(d) * factor)
}
