package storage

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// AggregateEvents groups a set of events for a single aggregate, used for
// multi-aggregate atomic writes.
type AggregateEvents struct {
	AggregateID     ulid.ULID
	Events          []domain.EventEnvelope
	ExpectedVersion int64
}

// CompactResult summarizes a CompactAggregate operation.
type CompactResult struct {
	AggregateID  ulid.ULID
	EventsBefore int64
	EventsAfter  int64
	Version      int64 // preserved high-water version
}

// EventStore is the write side of the CQRS pattern.
//
// Design Spec Divergences (intentional improvements):
//
// The implementation diverges from the design spec (docs/plans/2026-02-22-golang-migration-design.md)
// in the following ways to better reflect actual usage patterns and runtime requirements:
//
//  1. AppendEvents signature: Spec defines AppendEvents(ctx, []Event) without aggregateID or
//     expectedVersion. Implementation requires both parameters because events belong to a specific
//     aggregate and concurrency control (expectedVersion) applies per aggregate, not globally.
//     This reflects the event sourcing domain model constraint.
//
//  2. AppendEventsBatch method: Not in spec but crucial for multi-aggregate atomic writes.
//     Enables atomic transactions across multiple aggregates (e.g., snapshot + event deletion),
//     which is essential for snapshot cleanup and retention policies.
//
//  3. Event type: Spec uses generic "Event" type. Implementation uses domain.EventEnvelope,
//     which includes metadata (event ID, timestamp, version) necessary for storage layer operations
//     and audit trail integrity.
//
//  4. CountEvents signature: Spec defines CountEvents(ctx) globally. Implementation requires
//     aggregateID parameter. This aligns with typical access patterns (counting events for a
//     specific host/aggregate) and allows for efficient scoped queries on large datasets.
type EventStore interface {
	// AppendEvent appends a single event with optimistic concurrency control.
	//
	// An implementation MUST NOT commit an event whose EventID sorts at or
	// below the store's current maximum (see LatestEventID) — it MAY
	// therefore replace a proposed EventID that does not. A caller must not
	// assume the ID it supplied is the ID persisted; read the event back
	// (LoadEvents) if the actual persisted ID matters.
	AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion int64) error
	// AppendEvents appends multiple events atomically with optimistic
	// concurrency control. The same ordering obligation as AppendEvent
	// applies to every event in the slice: an implementation MUST NOT
	// commit any of them at or below the store's running maximum as of its
	// own insert, and MAY replace a proposed EventID accordingly.
	AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion int64) error
	// AppendEventsBatch writes events for multiple aggregates atomically in a
	// single transaction. If any write fails, no events are persisted. The
	// same ordering obligation as AppendEvent applies to every event across
	// every aggregate in the batch.
	AppendEventsBatch(ctx context.Context, batch []AggregateEvents) error
	LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]domain.EventEnvelope, error)
	GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (int64, error)
	CountEvents(ctx context.Context, aggregateID ulid.ULID) (int64, error)
	// ListAggregateIDs returns every distinct aggregate ID in the event log,
	// INCLUDING deleted aggregates (reads distinct aggregate_id from events).
	ListAggregateIDs(ctx context.Context) ([]ulid.ULID, error)
	// CompactAggregate folds the aggregate's event log and atomically replaces
	// it with a single HostCompacted seed event at the preserved high-water
	// version. No-op if the aggregate has <= 1 event. The whole operation is one
	// transaction; any failure rolls back and leaves the log intact.
	CompactAggregate(ctx context.Context, aggregateID ulid.ULID) (CompactResult, error)
	// LatestEventID returns the greatest event_id in the log, or the zero ULID
	// with a nil error when the log is empty. This is the server's change ID
	// (TMPL-08, D-18), and it is a valid high-water mark only because an
	// implementation MUST NOT commit an event whose EventID sorts at or below
	// the store's current maximum — an implementation MAY therefore replace a
	// proposed EventID that does not, and a caller must not assume the ID it
	// supplied is the ID persisted (see the AppendEvent/AppendEvents/
	// AppendEventsBatch doc comments for that obligation). The ordering
	// property this method depends on is a requirement on the append path, not
	// a property of how an ID is minted — see internal/eventid for the shared
	// generator every production mint goes through, which makes minting
	// monotonic but does not by itself make commits ordered. If that append
	// obligation is ever violated, the change ID fails to advance across a
	// real state change and a deduping consumer silently keeps serving a
	// stale zone.
	LatestEventID(ctx context.Context) (ulid.ULID, error)
}

// ZeroChangeID is the canonical string form of the zero ULID
// (ulid.ULID{}.String()): the sentinel LatestEventID's result represents on
// the wire when the event log is empty. It is the one spelling every
// backend, the compliance suite and the server agree on (D-22). A consumer
// comparing change IDs must treat it as a value like any other — comparison
// is exact string equality, never a prefix or numeric comparison. No commit
// may ever persist the zero ULID as an event ID (see the AppendEvent family's
// doc comments); that invariant is what keeps this sentinel unambiguous.
const ZeroChangeID = "00000000000000000000000000"

// SnapshotStore manages point-in-time snapshots.
type SnapshotStore interface {
	SaveSnapshot(ctx context.Context, snapshot domain.Snapshot) error
	GetSnapshot(ctx context.Context, snapshotID ulid.ULID) (*domain.Snapshot, error)
	ListSnapshots(ctx context.Context, limit, offset *uint32) ([]domain.SnapshotMetadata, error)
	DeleteSnapshot(ctx context.Context, snapshotID ulid.ULID) error
	ApplyRetentionPolicy(ctx context.Context, maxCount *int, maxAgeDays *int) (int, error)
}

// HostProjection is the read side of the CQRS pattern.
type HostProjection interface {
	ListAll(ctx context.Context) ([]domain.HostEntry, error)
	GetByID(ctx context.Context, id ulid.ULID) (*domain.HostEntry, error)
	FindByIPAndHostname(ctx context.Context, ip, hostname string) (*domain.HostEntry, error)
	Search(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error)
	GetAtTime(ctx context.Context, at time.Time) ([]domain.HostEntry, error)
}

// WriteStore is the write side of the CQRS split: event appends and snapshot
// mutations. Defined separately for documentation purposes; Storage embeds it.
type WriteStore interface {
	EventStore
	SnapshotStore
}

// ReadStore is the read side of the CQRS split: projections and queries.
// Defined separately for documentation purposes; Storage embeds it.
type ReadStore interface {
	HostProjection
}

// Storage combines all storage interfaces with lifecycle management.
//
// CQRS note: The Storage interface intentionally merges the read side
// (HostProjection / ReadStore) and the write side (EventStore + SnapshotStore /
// WriteStore) into a single interface. This is deliberate for the SQLite-only
// implementation: a single SQLite file cannot be split across separate read and
// write connections in a meaningful way, and adding that indirection would
// complicate the codebase without benefit. If a future backend warrants true
// read/write separation (e.g., a read replica), callers can accept ReadStore or
// WriteStore independently, as both are embedded in Storage.
type Storage interface {
	WriteStore
	ReadStore
	Initialize(ctx context.Context) error
	HealthCheck(ctx context.Context) error
	Close() error
	BackendName() string
}
