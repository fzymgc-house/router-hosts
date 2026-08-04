//go:build lazybench

// Package heapsample provides a peak-live-heap sampler for the lazybench
// benchmark tier (D-11/D-13). It exists only to give the two peak-memory
// benchmarks (internal/storage/sqlite/projection_bench_test.go and
// internal/server/export_bench_test.go) a single shared measurement
// primitive, following the internal/ciwiring precedent of a small internal
// package that exists to support a test tier rather than production code.
//
// This package is build-tagged behind lazybench (D-13) even though it has
// no production dependency, because it exists solely to support a tier that
// must never run under -race — bundling it under the same tag keeps its
// purpose unambiguous and keeps it out of the default build's import graph.
package heapsample

import (
	"runtime"
	"time"
)

// PollInterval is the interval PeakDuring polls runtime.MemStats.HeapAlloc
// at. This is a tunable, not a constant, so a future run can retune it
// without touching call sites — see the package doc comment on PeakDuring
// for the reasoning behind the current value.
//
// runtime.ReadMemStats briefly stops the world, so polling too aggressively
// perturbs the very quantity being measured. Verified empirically against
// the real storage-layer benchmark this session (02-05-SUMMARY.md): 100µs
// produced both a visibly wider run-to-run peak spread at the 1k fixture
// (~13%, several runs) and a measurably slower benchmark (each run several
// ms slower) than 250µs or 500µs — direct evidence of STW-poll overhead
// perturbing the measurement at that interval. 250µs and 500µs performed
// comparably to each other (~8-9% spread, similar wall time); 250µs was
// kept as the interval every recorded number in 02-05-SUMMARY.md was
// produced with. It sits inside RESEARCH.md's recommended 100-500µs range,
// re-verified rather than carried over unverified.
var PollInterval = 250 * time.Microsecond

// PeakDuring runs f while a background goroutine polls
// runtime.MemStats.HeapAlloc on a PollInterval ticker, tracking the maximum
// observed value, and returns the MARGINAL peak in bytes once f returns:
// the sampled peak minus a baseline taken immediately before f starts.
//
// The marginal (delta-from-baseline) form, not the raw absolute peak, is
// deliberate: this project's pure-Go SQLite driver (zombiezen.com/go/sqlite)
// keeps its own page cache and per-connection state on the Go heap, and a
// 10-connection pool (sqlitex.NewPool) holds a multi-megabyte, largely
// fixture-size-INVARIANT floor that swamps a raw peak-to-peak ratio at the
// fixture sizes this benchmark uses — observed directly this session (see
// 02-05-SUMMARY.md: the same 1k-vs-10k comparison on RAW HeapAlloc produced
// a paged/drained separation far too small to be a meaningful signal, purely
// from that shared floor, not from anything the paged-vs-drained code
// difference actually did). Subtracting the immediately-prior baseline
// isolates what the call under measurement itself contributed.
//
// This is a SAMPLED APPROXIMATION of peak live heap, not an exact
// high-water mark: a peak narrower than PollInterval can be missed
// entirely. It is not testing.AllocsPerRun and not -benchmem's B/op —
// those report CUMULATIVE allocation over the call, which is O(N) for both
// a paged and a fully-drained read because both eventually touch every
// entry, and therefore cannot distinguish the two (see RESEARCH.md
// Pitfall 1). Sampling HeapAlloc DURING the call is the only technique used
// here that distinguishes "held all at once" from "held one page at a
// time".
//
// runtime.GC() runs immediately before the baseline is captured, so the
// baseline reflects only what genuinely survives a collection right before
// f starts, not garbage left over from whatever ran earlier in the process.
//
// The sampler goroutine is the sole writer of the peak value; PeakDuring
// blocks until that goroutine has observed the stop signal and returned,
// via a channel close-and-receive join rather than a shared mutex, before
// reading the final value. This tier never runs under -race (D-13), so a
// data race here would otherwise be invisible.
func PeakDuring(f func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	baseline := base.HeapAlloc

	stop := make(chan struct{})
	stopped := make(chan struct{})

	peak := baseline
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(PollInterval)
		defer ticker.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > peak {
					peak = ms.HeapAlloc
				}
			}
		}
	}()

	f()
	close(stop)
	<-stopped // join: the goroutine above is the sole writer of peak

	if peak < baseline {
		return 0
	}
	return peak - baseline
}
