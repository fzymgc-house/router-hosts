package sqlite

// This file uses `go test -bench` directly rather than `task test` (review
// round-4 L5): `task test` runs the full suite under -race, which distorts
// benchmark timings and would make the recorded ns/op figures meaningless.
// Run with:
//
//	go test -bench BenchmarkAppendEventsBatch -benchtime 1x -run '^$' ./internal/storage/sqlite/
//
// This is a recorded measurement, not a CI gate: no threshold is wired into
// task ci, and none should be — a wall-clock threshold on a timing-sensitive
// benchmark is flaky by construction, and a flaky gate teaches the next
// maintainer to ignore it. The four ns/op figures observed for 1/100/1,000/
// 10,000 events are recorded in the plan 01-09 SUMMARY.

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// BenchmarkAppendEventsBatch measures the cost the in-transaction ordering
// guard adds to the bulk append path (T-1-54): AppendEventsBatch is both the
// import path and the RollbackToSnapshot path
// (internal/server/service.go:836), so a rollback over N entries issues N
// indexed MAX(event_id) seeks, all bounded by the single write transaction
// AppendEventsBatch already holds. CompactAggregate pays one per replacement
// seed.
func BenchmarkAppendEventsBatch(b *testing.B) {
	for _, n := range []int{1, 100, 1000, 10000} {
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

			ctx := context.Background()
			batch := make([]storage.AggregateEvents, 0, n)
			for i := 0; i < n; i++ {
				aggID := ulid.Make()
				he, err := domain.NewHostEvent(domain.HostCreated{
					IPAddress: "10.7.0.1",
					Hostname:  "bench.example.com",
					Aliases:   []string{},
					Tags:      []string{},
					CreatedAt: time.Now().UTC(),
				})
				if err != nil {
					b.Fatalf("build host event: %v", err)
				}
				batch = append(batch, storage.AggregateEvents{
					AggregateID: aggID,
					Events: []domain.EventEnvelope{{
						EventID:     eventid.New(),
						AggregateID: aggID,
						Event:       he,
						Version:     1,
						CreatedAt:   time.Now().UTC(),
					}},
					ExpectedVersion: 0,
				})
			}

			b.ResetTimer()
			if err := store.AppendEventsBatch(ctx, batch); err != nil {
				b.Fatalf("append events batch: %v", err)
			}
		})
	}
}
