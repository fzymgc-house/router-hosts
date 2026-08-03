// Package wait provides bounded-timeout polling helpers for tests that must
// wait for an external condition to become true — a server accepting
// connections, a file appearing on disk, a value converging.
//
// Until and UntilValue report timeout failures through testing.TB.Fatalf and
// therefore MUST be called from the goroutine running the test, exactly as
// testing.TB's own documented contract requires: Fatalf marks the test
// failed and stops the calling goroutine via runtime.Goexit, which only
// unwinds that goroutine's stack. There is no error return either function
// can silently drop — a timeout is always surfaced through Fatalf.
package wait

import (
	"testing"
	"time"
)

// Until polls cond every interval until it returns true or timeout elapses.
// cond is evaluated at least once, even when timeout is zero or has already
// elapsed by the time Until is called. On timeout, Until calls tb.Fatalf
// with a message naming timeout and desc.
func Until(tb testing.TB, timeout, interval time.Duration, desc string, cond func() bool) {
	tb.Helper()

	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(interval)
	}
	tb.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}

// UntilValue polls fetch every interval until it returns a value for which
// pred is true, or timeout elapses, returning the satisfying value. fetch is
// evaluated at least once, even when timeout is zero or has already elapsed
// by the time UntilValue is called. A fetch error is retried rather than
// treated as fatal immediately, so a transient failure (e.g. a file that
// does not exist yet) does not need its own retry loop at the call site.
//
// On timeout, UntilValue calls tb.Fatalf with a message naming timeout and
// desc, plus either the last error fetch returned or the last successfully
// observed value if fetch never errored but pred was never satisfied.
func UntilValue[T any](tb testing.TB, timeout, interval time.Duration, desc string, fetch func() (T, error), pred func(T) bool) T {
	tb.Helper()

	deadline := time.Now().Add(timeout)
	var last T
	var lastErr error
	for {
		v, err := fetch()
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			last = v
			if pred(v) {
				return v
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(interval)
	}

	if lastErr != nil {
		tb.Fatalf("timed out after %s waiting for %s; last error: %v", timeout, desc, lastErr)
	} else {
		tb.Fatalf("timed out after %s waiting for %s; last value: %+v", timeout, desc, last)
	}
	var zero T
	return zero
}
