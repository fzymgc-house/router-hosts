package storage

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// EventStore is the write side of the CQRS pattern.
type EventStore interface {
	AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion string) error
	AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion string) error
	LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]domain.EventEnvelope, error)
	GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (string, error)
	CountEvents(ctx context.Context, aggregateID ulid.ULID) (int64, error)
}

// SnapshotStore manages point-in-time snapshots.
type SnapshotStore interface {
	SaveSnapshot(ctx context.Context, snapshot domain.Snapshot) error
	GetSnapshot(ctx context.Context, snapshotID string) (*domain.Snapshot, error)
	ListSnapshots(ctx context.Context, limit, offset *uint32) ([]domain.SnapshotMetadata, error)
	DeleteSnapshot(ctx context.Context, snapshotID string) error
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

// Storage combines all storage interfaces with lifecycle management.
type Storage interface {
	EventStore
	SnapshotStore
	HostProjection
	Initialize(ctx context.Context) error
	HealthCheck(ctx context.Context) error
	Close() error
	BackendName() string
}
