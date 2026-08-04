//go:build lazybench

package server

// This is the consumer-level half of D-11's measured proof: the
// storage-layer benchmark (internal/storage/sqlite/projection_bench_test.go)
// alone does not demonstrate plan 02-04's change, because the three
// materializations D-03 removed (entries, out/csvBuf, data) lived in
// ExportHosts itself, not in the storage layer. This file drives the real
// exportJSONStream/exportCSVStream methods (the same code ExportHosts' json
// and csv branches call) through a discarding fake exportChunkSender, and
// separately reconstructs the pre-02-04 buffered shape (quoted verbatim in
// 02-04-SUMMARY.md) as a THIS-FILE-ONLY comparison baseline — that buffered
// shape is not reintroduced into production anywhere.
//
// Same D-13 isolation as the storage-layer benchmark: own build tag, never
// -race. Run with:
//
//	go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/server/

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/heapsample"
	"github.com/fzymgc-house/router-hosts/internal/storage"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// discardChunkSender is a minimal exportChunkSender that discards every
// chunk — the "fake exportChunkSender" this benchmark drives ExportHosts'
// json/csv streaming methods through, so a chunk's transient allocation
// never itself becomes what's being measured.
type discardChunkSender struct{}

func (discardChunkSender) Send(*hostsv1.ExportHostsResponse) error { return nil }

// exportFixtureCounts records the exact per-depth-tier counts a fixture
// build produced, mirroring projection_bench_test.go's fixtureCounts (D-12
// "at least three distinct aggregate depths plus a non-zero deleted share").
type exportFixtureCounts struct {
	deep, shallowTwoEvent, shallowOneEvent, deleted int
}

// buildExportFixture mirrors the D-12 mixed-depth, deleted-aggregate
// fixture used by the storage-layer benchmark (deliberately duplicated
// rather than shared: the two benchmarks live in different packages, and
// this plan's file list does not add a third shared package beyond
// internal/heapsample). See projection_bench_test.go's buildMixedDepthFixture
// doc comment for the full D-12 rationale.
func buildExportFixture(b *testing.B, store storage.EventStore, liveCount int) exportFixtureCounts {
	b.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	const deepAggCount = 20
	const deepAggEvents = 50

	counts := exportFixtureCounts{deep: deepAggCount}
	if counts.deep > liveCount {
		counts.deep = liveCount
	}
	counts.deleted = liveCount / 10

	batch := make([]storage.AggregateEvents, 0, liveCount+counts.deleted)
	for i := 0; i < liveCount; i++ {
		aggID := ulid.Make()
		switch {
		case i < counts.deep:
			events := make([]domain.EventEnvelope, 0, deepAggEvents)
			events = append(events, exportHostEventEnvelope(aggID, domain.HostCreated{
				IPAddress: "10.9.1.1",
				Hostname:  "deep-export-bench.example.com",
				Aliases:   []string{},
				Tags:      []string{},
				CreatedAt: now,
			}, 1, now))
			for v := 2; v <= deepAggEvents; v++ {
				ip := "10.9.1." + strconv.Itoa(1+(v%254))
				events = append(events, exportHostEventEnvelope(aggID, domain.IPAddressChanged{
					OldIP:     "10.9.1.1",
					NewIP:     ip,
					ChangedAt: now,
				}, int64(v), now))
			}
			batch = append(batch, storage.AggregateEvents{AggregateID: aggID, Events: events, ExpectedVersion: 0})
		case i%2 == 0:
			// D-12/three-depths: half the shallow majority gets exactly one
			// event (create only) — a third, distinct depth alongside the
			// two-event shallow variant and the deep tier above.
			counts.shallowOneEvent++
			created := exportHostEventEnvelope(aggID, domain.HostCreated{
				IPAddress: "10.9.0.1",
				Hostname:  "export-bench-single.example.com",
				Aliases:   []string{},
				Tags:      []string{},
				CreatedAt: now,
			}, 1, now)
			batch = append(batch, storage.AggregateEvents{
				AggregateID:     aggID,
				Events:          []domain.EventEnvelope{created},
				ExpectedVersion: 0,
			})
		default:
			counts.shallowTwoEvent++
			created := exportHostEventEnvelope(aggID, domain.HostCreated{
				IPAddress: "10.9.0.1",
				Hostname:  "export-bench.example.com",
				Aliases:   []string{},
				Tags:      []string{},
				CreatedAt: now,
			}, 1, now)
			changed := exportHostEventEnvelope(aggID, domain.IPAddressChanged{
				OldIP:     "10.9.0.1",
				NewIP:     "10.9.0.2",
				ChangedAt: now,
			}, 2, now)
			batch = append(batch, storage.AggregateEvents{
				AggregateID:     aggID,
				Events:          []domain.EventEnvelope{created, changed},
				ExpectedVersion: 0,
			})
		}
	}
	for i := 0; i < counts.deleted; i++ {
		aggID := ulid.Make()
		created := exportHostEventEnvelope(aggID, domain.HostCreated{
			IPAddress: "10.9.2.1",
			Hostname:  "deleted-export-bench.example.com",
			Aliases:   []string{},
			Tags:      []string{},
			CreatedAt: now,
		}, 1, now)
		deleted := exportHostEventEnvelope(aggID, domain.HostDeleted{
			IPAddress: "10.9.2.1",
			Hostname:  "deleted-export-bench.example.com",
			DeletedAt: now,
		}, 2, now)
		batch = append(batch, storage.AggregateEvents{
			AggregateID:     aggID,
			Events:          []domain.EventEnvelope{created, deleted},
			ExpectedVersion: 0,
		})
	}

	if err := store.AppendEventsBatch(ctx, batch); err != nil {
		b.Fatalf("seed export fixture: %v", err)
	}
	return counts
}

func exportHostEventEnvelope(aggID ulid.ULID, event any, version int64, createdAt time.Time) domain.EventEnvelope {
	he, err := domain.NewHostEvent(event)
	if err != nil {
		panic("exportHostEventEnvelope: NewHostEvent: " + err.Error())
	}
	return domain.EventEnvelope{
		EventID:     eventid.New(),
		AggregateID: aggID,
		Event:       he,
		Version:     version,
		CreatedAt:   createdAt,
	}
}

// benchExportJSONStreaming drives the real, current (post-02-04) production
// path: newChunkWriter(exportChunkSender) + exportJSONStream — exactly what
// ExportHosts' "json" case does, minus the real gRPC stream.
func benchExportJSONStreaming(b *testing.B, svc *HostsServiceImpl) {
	b.Helper()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		w := newChunkWriter(discardChunkSender{})
		if err := svc.exportJSONStream(ctx, w); err != nil {
			b.Fatalf("exportJSONStream: %v", err)
		}
		if err := w.Close(); err != nil {
			b.Fatalf("close chunk writer: %v", err)
		}
	}
}

func benchExportCSVStreaming(b *testing.B, svc *HostsServiceImpl) {
	b.Helper()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		w := newChunkWriter(discardChunkSender{})
		if err := svc.exportCSVStream(ctx, w); err != nil {
			b.Fatalf("exportCSVStream: %v", err)
		}
		if err := w.Close(); err != nil {
			b.Fatalf("close chunk writer: %v", err)
		}
	}
}

// benchExportJSONBuffered reconstructs the pre-02-04 buffered ExportHosts
// json shape — three full materializations (entries, out, data) before
// anything is sent — quoted verbatim in 02-04-SUMMARY.md as the code this
// plan's benchmark needs gone from production. It exists HERE ONLY, as a
// D-11 comparison baseline; it is not called from anywhere in production.
func benchExportJSONBuffered(b *testing.B, store storage.Storage) {
	b.Helper()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		entries, err := store.ListAll(ctx)
		if err != nil {
			b.Fatalf("list all: %v", err)
		}
		out := make([]jsonEntry, len(entries))
		for j, e := range entries {
			out[j] = jsonEntry{
				ID:        e.ID.String(),
				IPAddress: e.IP,
				Hostname:  e.Hostname,
				Comment:   e.Comment,
				Tags:      e.Tags,
				Aliases:   e.Aliases,
			}
		}
		data, merr := json.MarshalIndent(out, "", "  ")
		if merr != nil {
			b.Fatalf("marshal: %v", merr)
		}
		_ = data
	}
}

// benchExportCSVBuffered reconstructs the pre-02-04 buffered ExportHosts csv
// shape (bytes.Buffer accumulating every row before anything is sent) —
// same D-11 comparison-baseline-only status as benchExportJSONBuffered.
func benchExportCSVBuffered(b *testing.B, store storage.Storage) {
	b.Helper()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		entries, err := store.ListAll(ctx)
		if err != nil {
			b.Fatalf("list all: %v", err)
		}
		var csvBuf bytes.Buffer
		w := csv.NewWriter(&csvBuf)
		_ = w.Write([]string{"id", "ip_address", "hostname", "comment", "tags", "aliases"})
		for _, e := range entries {
			comment := ""
			if e.Comment != nil {
				comment = *e.Comment
			}
			_ = w.Write([]string{
				e.ID.String(), e.IP, e.Hostname, comment,
				strings.Join(e.Tags, ";"), strings.Join(e.Aliases, ";"),
			})
		}
		w.Flush()
		if ferr := w.Error(); ferr != nil {
			b.Fatalf("csv write: %v", ferr)
		}
		_ = csvBuf.Bytes()
	}
}

// benchExportHostsResidual measures the "hosts" format's D-02-descoped
// residual: drains ListAll and renders via FormatHostsFile exactly as
// production does today. No ratio is asserted for this format — D-02
// explicitly sanctions its O(entry count) residual — this is measured and
// recorded, not gated.
func benchExportHostsResidual(b *testing.B, store storage.Storage) {
	b.Helper()
	ctx := context.Background()
	gen := &HostsFileGenerator{}
	for i := 0; i < b.N; i++ {
		entries, err := store.ListAll(ctx)
		if err != nil {
			b.Fatalf("list all: %v", err)
		}
		data := gen.FormatHostsFile(entries)
		_ = data
	}
}

// BenchmarkPeakMemory is LAZY-02's consumer-level measured proof (D-11):
// json/csv streaming's peak sampled heap stays flat as the fixture grows
// 10x (~1k to ~10k live entries), while the reconstructed pre-02-04
// buffered shape scales. The storage-layer benchmark alone would not show
// this — the three materializations D-03 removed lived in ExportHosts, not
// in ListPage/ListAll.
func BenchmarkPeakMemory(b *testing.B) {
	sizes := []int{1000, 10000}
	streamingPeaks := make(map[int]uint64, len(sizes))
	bufferedPeaks := make(map[int]uint64, len(sizes))

	for _, n := range sizes {
		n := n
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			dbPath := filepath.Join(b.TempDir(), "export-bench.db")
			store, err := sqlite.New(dbPath, slog.Default())
			if err != nil {
				b.Fatalf("create store: %v", err)
			}
			defer func() { _ = store.Close() }()
			if err := store.Initialize(context.Background()); err != nil {
				b.Fatalf("initialize store: %v", err)
			}

			counts := buildExportFixture(b, store, n)
			b.Logf("fixture: live=%d deep(50 events)=%d shallow(2 events)=%d shallow(1 event)=%d deleted=%d",
				n, counts.deep, counts.shallowTwoEvent, counts.shallowOneEvent, counts.deleted)

			handler := NewCommandHandler(store)
			svc := NewHostsServiceImpl(handler, store)

			b.Run("json_streaming", func(b *testing.B) {
				b.ReportAllocs() // informational only — see heapsample.PeakDuring's doc comment
				peak := heapsample.PeakDuring(func() { benchExportJSONStreaming(b, svc) })
				b.ReportMetric(float64(peak), "peak-heap-bytes")
				streamingPeaks[n] = peak
			})

			b.Run("json_buffered_preD03", func(b *testing.B) {
				b.ReportAllocs() // informational only
				peak := heapsample.PeakDuring(func() { benchExportJSONBuffered(b, store) })
				b.ReportMetric(float64(peak), "peak-heap-bytes")
				bufferedPeaks[n] = peak
			})

			b.Run("csv_streaming", func(b *testing.B) {
				b.ReportAllocs()
				peak := heapsample.PeakDuring(func() { benchExportCSVStreaming(b, svc) })
				b.ReportMetric(float64(peak), "peak-heap-bytes")
			})

			b.Run("csv_buffered_preD03", func(b *testing.B) {
				b.ReportAllocs()
				peak := heapsample.PeakDuring(func() { benchExportCSVBuffered(b, store) })
				b.ReportMetric(float64(peak), "peak-heap-bytes")
			})

			b.Run("hosts_D02_residual", func(b *testing.B) {
				b.ReportAllocs()
				peak := heapsample.PeakDuring(func() { benchExportHostsResidual(b, store) })
				b.ReportMetric(float64(peak), "peak-heap-bytes")
				b.Logf("hosts D-02 residual peak at %d entries: %d bytes (measured, not asserted)", n, peak)
			})
		})
	}

	streamingRatio := float64(streamingPeaks[10000]) / float64(streamingPeaks[1000])
	bufferedRatio := float64(bufferedPeaks[10000]) / float64(bufferedPeaks[1000])
	b.Logf("json streaming peak ratio (10k/1k) = %.3f (peaks: %d / %d bytes)", streamingRatio, streamingPeaks[10000], streamingPeaks[1000])
	b.Logf("json buffered (pre-D03) peak ratio (10k/1k) = %.3f (peaks: %d / %d bytes)", bufferedRatio, bufferedPeaks[10000], bufferedPeaks[1000])

	// D-11, same shape as the storage-layer benchmark: a ratio derived from
	// observed run-to-run spread, never an absolute byte ceiling. 8 local
	// runs (02-05-SUMMARY.md) put streamingRatio consistently in
	// [1.15, 1.23] and bufferedRatio consistently in [2.54, 4.19] — never
	// overlapping. See projection_bench_test.go's assertion comment for why
	// the buffered ratio is well below a naive ~10x linear-scaling
	// expectation.
	const streamingTolerance = 1.8
	const bufferedMinRatio = 2.2
	require.Lessf(b, streamingRatio, streamingTolerance,
		"json streaming's peak must stay flat (ratio < %.1f) as entry count grows 10x — got %.3f", streamingTolerance, streamingRatio)
	require.Greaterf(b, bufferedRatio, bufferedMinRatio,
		"pre-D03 buffered json's peak must scale with entry count (ratio > %.1f) — got %.3f", bufferedMinRatio, bufferedRatio)
}
