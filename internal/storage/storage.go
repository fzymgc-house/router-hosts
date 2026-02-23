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
	AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion int64) error
	AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion int64) error
	// AppendEventsBatch writes events for multiple aggregates atomically in a
	// single transaction. If any write fails, no events are persisted.
	AppendEventsBatch(ctx context.Context, batch []AggregateEvents) error
	LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]domain.EventEnvelope, error)
	GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (int64, error)
	CountEvents(ctx context.Context, aggregateID ulid.ULID) (int64, error)
}

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
