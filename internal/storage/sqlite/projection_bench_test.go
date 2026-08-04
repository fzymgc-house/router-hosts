//go:build lazybench

package sqlite

// This file uses `go test -bench` directly rather than `task test` (D-13,
// mirroring append_bench_test.go's review round-4 L5 precedent): `task
// test` runs the full suite under -race, which both slows a 10k-entry
// fixture significantly and perturbs allocation accounting — the exact
// quantity BenchmarkPeakMemory measures (RESEARCH.md Pitfall 4). Unlike
// append_bench_test.go, this file also lives behind its own build tag
// (lazybench) rather than relying solely on the Benchmark-func-not-run-by-
// `go test` convention, because D-13 requires stronger isolation: a
// dedicated, own-build-tag CI job (plan 02-06) that never runs -race.
//
// Run with:
//
//	go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/storage/sqlite/
//
// This is a recorded measurement AND a ratio assertion (D-11), not a
// wall-clock timing gate: the asserted quantity is a cross-fixture-size
// RATIO of peak sampled heap (internal/heapsample), never an absolute byte
// ceiling — an absolute number is a magic constant someone bumps whenever
// it goes red. The polling interval, observed run-to-run spread, and the
// derived tolerance are recorded in 02-05-SUMMARY.md, not chosen in
// advance.

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/heapsample"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// deepAggregateCount and deepAggregateEvents are the D-12 "deliberate
// minority with deep histories" — fixed counts, independent of the fixture
// size, so the deep share shrinks (not grows) as liveCount grows from 1k to
// 10k, matching "mostly shallow, a minority deep" at both sizes rather than
// scaling the minority with N.
const (
	deepAggregateCount  = 20
	deepAggregateEvents = 50
)

// fixtureCounts records the exact per-depth-tier counts a fixture build
// produced, so the caller can log (and, if ever needed, assert against)
// D-12's "at least three distinct aggregate depths plus a non-zero deleted
// share" requirement rather than trusting it implicitly.
type fixtureCounts struct {
	deep, shallowTwoEvent, shallowOneEvent, deleted int
}

// buildMixedDepthFixture seeds store with a D-12 mixed-depth fixture:
// liveCount live aggregates split across three distinct depths —
// deepAggregateCount deep (deepAggregateEvents events each), and the
// remaining shallow majority split evenly between one-event and two-event
// aggregates — plus a deleted share (liveCount/10 aggregates, created then
// deleted) to exercise ListPage's D-08 fill-to-N loop.
func buildMixedDepthFixture(b *testing.B, store *Storage, liveCount int) fixtureCounts {
	b.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	counts := fixtureCounts{deep: deepAggregateCount}
	if counts.deep > liveCount {
		counts.deep = liveCount
	}
	counts.deleted = liveCount / 10

	batch := make([]storage.AggregateEvents, 0, liveCount+counts.deleted)
	for i := 0; i < liveCount; i++ {
		aggID := ulid.Make()
		switch {
		case i < counts.deep:
			batch = append(batch, storage.AggregateEvents{
				AggregateID:     aggID,
				Events:          deepEvents(aggID, now),
				ExpectedVersion: 0,
			})
		case i%2 == 0:
			// D-12/three-depths: half the shallow majority gets exactly one
			// event (create only) — a third, distinct depth alongside the
			// two-event shallow variant and the deep tier above.
			counts.shallowOneEvent++
			batch = append(batch, storage.AggregateEvents{
				AggregateID: aggID,
				Events: []domain.EventEnvelope{hostEventEnvelope(aggID, domain.HostCreated{
					IPAddress: "10.9.0.1",
					Hostname:  "bench-single.example.com",
					Aliases:   []string{},
					Tags:      []string{},
					CreatedAt: now,
				}, 1, now)},
				ExpectedVersion: 0,
			})
		default:
			counts.shallowTwoEvent++
			batch = append(batch, storage.AggregateEvents{
				AggregateID:     aggID,
				Events:          shallowEvents(aggID, now),
				ExpectedVersion: 0,
			})
		}
	}
	for i := 0; i < counts.deleted; i++ {
		aggID := ulid.Make()
		batch = append(batch, storage.AggregateEvents{
			AggregateID:     aggID,
			Events:          deletedEvents(aggID, now),
			ExpectedVersion: 0,
		})
	}

	if err := store.AppendEventsBatch(ctx, batch); err != nil {
		b.Fatalf("seed mixed-depth fixture: %v", err)
	}
	return counts
}

// shallowEvents builds a two-event aggregate (create, then one IP change) —
// the D-12 "mostly shallow (one or two events)" majority.
func shallowEvents(aggID ulid.ULID, now time.Time) []domain.EventEnvelope {
	created := hostEventEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.9.0.1",
		Hostname:  "bench.example.com",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now)
	changed := hostEventEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.9.0.1",
		NewIP:     "10.9.0.2",
		ChangedAt: now,
	}, 2, now)
	return []domain.EventEnvelope{created, changed}
}

// deepEvents builds a deepAggregateEvents-event aggregate (create plus
// repeated IP flaps) — the D-12 "deliberate minority with deep histories,
// enough events that replaying one is a visible cost". This is also the one
// term paging does not bound (D-06): a single page fetch spanning this
// aggregate still replays all deepAggregateEvents events for it.
func deepEvents(aggID ulid.ULID, now time.Time) []domain.EventEnvelope {
	events := make([]domain.EventEnvelope, 0, deepAggregateEvents)
	events = append(events, hostEventEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.9.1.1",
		Hostname:  "deep-bench.example.com",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now))
	for v := 2; v <= deepAggregateEvents; v++ {
		ip := "10.9.1." + strconv.Itoa(1+(v%254))
		events = append(events, hostEventEnvelope(aggID, domain.IPAddressChanged{
			OldIP:     "10.9.1.1",
			NewIP:     ip,
			ChangedAt: now,
		}, int64(v), now))
	}
	return events
}

// deletedEvents builds a create-then-delete aggregate — the D-12 "realistic
// share of deleted aggregates" that exercises ListPage's fill-to-N loop
// (D-08): a page fetch must skip past these without counting them toward
// the requested limit.
func deletedEvents(aggID ulid.ULID, now time.Time) []domain.EventEnvelope {
	created := hostEventEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.9.2.1",
		Hostname:  "deleted-bench.example.com",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now)
	deleted := hostEventEnvelope(aggID, domain.HostDeleted{
		IPAddress: "10.9.2.1",
		Hostname:  "deleted-bench.example.com",
		DeletedAt: now,
	}, 2, now)
	return []domain.EventEnvelope{created, deleted}
}

// hostEventEnvelope mirrors append_bench_test.go's inline envelope
// construction (no storagetest import: that package's helpers are
// unexported and this file lives in a different package).
func hostEventEnvelope(aggID ulid.ULID, event any, version int64, createdAt time.Time) domain.EventEnvelope {
	he, err := domain.NewHostEvent(event)
	if err != nil {
		panic("hostEventEnvelope: NewHostEvent: " + err.Error())
	}
	return domain.EventEnvelope{
		EventID:     eventid.New(),
		AggregateID: aggID,
		Event:       he,
		Version:     version,
		CreatedAt:   createdAt,
	}
}

// drainPaged drains the entire store via ListPage, discarding each page
// after use — the D-11 "paged path": peak live heap should never hold more
// than one page plus bookkeeping, regardless of total entry count.
func drainPaged(b *testing.B, store *Storage, pageSize int) {
	b.Helper()
	ctx := context.Background()
	var cursor ulid.ULID
	for {
		page, next, done, err := store.ListPage(ctx, cursor, pageSize)
		if err != nil {
			b.Fatalf("ListPage: %v", err)
		}
		_ = page // discarded after use, matching a real page-at-a-time consumer
		if done {
			return
		}
		cursor = next
	}
}

// BenchmarkPeakMemory is LAZY-02's measured proof (D-11): the paged path's
// peak sampled heap stays flat as the fixture grows 10x (~1k to ~10k live
// entries), while the drained path (ListAll, which still materializes every
// entry into one slice) scales roughly with entry count. The ratio
// assertion — not an absolute ceiling — is the load-bearing check; see the
// package-level comment above and 02-05-SUMMARY.md for the observed numbers
// this was tuned against.
func BenchmarkPeakMemory(b *testing.B) {
	sizes := []int{1000, 10000}
	pagedPeaks := make(map[int]uint64, len(sizes))
	drainedPeaks := make(map[int]uint64, len(sizes))

	for _, n := range sizes {
		n := n
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			dbPath := filepath.Join(b.TempDir(), "bench.db")
			store, err := New(dbPath, slog.Default())
			if err != nil {
				b.Fatalf("create store: %v", err)
			}
			defer func() { _ = store.Close() }()
			if err := store.Initialize(context.Background()); err != nil {
				b.Fatalf("initialize store: %v", err)
			}

			counts := buildMixedDepthFixture(b, store, n)
			b.Logf("fixture: live=%d deep(%d events)=%d shallow(2 events)=%d shallow(1 event)=%d deleted=%d",
				n, deepAggregateEvents, counts.deep, counts.shallowTwoEvent, counts.shallowOneEvent, counts.deleted)

			b.Run("paged", func(b *testing.B) {
				b.ReportAllocs() // informational only — see PeakDuring's doc comment
				peak := heapsample.PeakDuring(func() {
					for i := 0; i < b.N; i++ {
						drainPaged(b, store, defaultListPageSize)
					}
				})
				b.ReportMetric(float64(peak), "peak-heap-bytes")
				pagedPeaks[n] = peak
			})

			b.Run("drained", func(b *testing.B) {
				b.ReportAllocs() // informational only — see PeakDuring's doc comment
				ctx := context.Background()
				peak := heapsample.PeakDuring(func() {
					for i := 0; i < b.N; i++ {
						entries, listErr := store.ListAll(ctx)
						if listErr != nil {
							b.Fatalf("ListAll: %v", listErr)
						}
						_ = entries // held for the whole call, unlike drainPaged
					}
				})
				b.ReportMetric(float64(peak), "peak-heap-bytes")
				drainedPeaks[n] = peak
			})
		})
	}

	pagedRatio := float64(pagedPeaks[10000]) / float64(pagedPeaks[1000])
	drainedRatio := float64(drainedPeaks[10000]) / float64(drainedPeaks[1000])
	b.Logf("paged peak ratio (10k/1k) = %.3f (peaks: %d / %d bytes)", pagedRatio, pagedPeaks[10000], pagedPeaks[1000])
	b.Logf("drained peak ratio (10k/1k) = %.3f (peaks: %d / %d bytes)", drainedRatio, drainedPeaks[10000], drainedPeaks[1000])

	// D-11: a ratio, derived from observed run-to-run spread, never an
	// absolute byte ceiling. 15 local runs against this final fixture shape
	// (02-05-SUMMARY.md) put pagedRatio consistently in [1.04, 1.12] and
	// drainedRatio consistently in [2.50, 2.65] — never overlapping.
	//
	// Note the observed drainedRatio (~3x) is well below the ~10x a naive
	// "N entries scale linearly" model predicts: this project's pure-Go
	// SQLite driver keeps a multi-megabyte, largely fixture-size-invariant
	// floor on the Go heap (connection pool + page cache), which
	// heapsample.PeakDuring's baseline subtraction removes from the ABSOLUTE
	// peak but cannot remove from the MARGINAL contribution's own scaling —
	// GC pacing and allocator span-class overhead also grow sub-linearly
	// with live-object count. The two paths remain clearly, consistently
	// separated; that separation, not a specific multiplier, is what D-11
	// asserts.
	//
	// The drained arm asserts SEPARATION FROM pagedRatio, not an absolute
	// magnitude, and that is deliberate. It previously asserted a fixed
	// `drainedRatio > 2.2`, derived from those 15 runs — all of them on
	// macOS/arm64. That gate went RED on its first real Linux CI run
	// (workflow_dispatch 30867901912, goos=linux goarch=amd64, AMD EPYC):
	// pagedRatio was 1.010 and drainedRatio only 1.775, because Linux's
	// allocator and GC grow the drained path's marginal peak less than
	// macOS's do. The qualitative behavior travelled — 1.775 vs 1.010 is
	// still a decisive gap — but the magnitude constant did not. A tolerance
	// derived from repeated LOCAL runs is exactly as machine-specific as a
	// locally-observed behavior.
	//
	// Do NOT "simplify" this back to a fixed multiplier, and do NOT widen a
	// threshold to turn a red run green (02-05 prohibits that outright). If
	// this assertion goes red, the paths have genuinely stopped separating.
	const pagedTolerance = 1.8
	const drainedSeparation = 1.4
	require.Lessf(b, pagedRatio, pagedTolerance,
		"paged path's peak must stay flat (ratio < %.1f) as entry count grows 10x — got %.3f", pagedTolerance, pagedRatio)
	require.Greaterf(b, drainedRatio, pagedRatio*drainedSeparation,
		"drained path's peak must scale while the paged path stays flat: drainedRatio must exceed pagedRatio by %.1fx — got drained %.3f vs paged %.3f (threshold %.3f)",
		drainedSeparation, drainedRatio, pagedRatio, pagedRatio*drainedSeparation)
}
