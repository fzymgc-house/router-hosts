// Package storagetest provides a reusable compliance test suite that any
// storage.Storage implementation must pass. Embed these functions into a
// backend-specific _test.go file and call them with a freshly initialised store.
package storagetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// helpers

func makeEnvelope(aggregateID ulid.ULID, event any, version int64, createdAt time.Time) domain.EventEnvelope {
	he, err := domain.NewHostEvent(event)
	if err != nil {
		panic(fmt.Sprintf("storagetest.makeEnvelope: NewHostEvent: %v", err))
	}
	return domain.EventEnvelope{
		EventID:     ulid.Make(),
		AggregateID: aggregateID,
		Event:       he,
		Version:     version,
		CreatedAt:   createdAt,
	}
}

func hostCreatedEnvelope(aggID ulid.ULID, ip, hostname string, t time.Time) domain.EventEnvelope {
	return makeEnvelope(aggID, domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: t,
	}, 1, t)
}

func ptr[T any](v T) *T { return &v }

// ---------- EventStore compliance ----------

// TestEventStoreAppendAndLoad verifies that a single event can be written and
// read back with all fields preserved.
func TestEventStoreAppendAndLoad(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := hostCreatedEnvelope(aggID, "10.1.0.1", "compliance.local", now)
	require.NoError(t, store.AppendEvent(ctx, aggID, env, 0))

	events, err := store.LoadEvents(ctx, aggID)
	require.NoError(t, err)
	require.Len(t, events, 1)

	got := events[0]
	require.Equal(t, env.EventID, got.EventID)
	require.Equal(t, aggID, got.AggregateID)
	require.Equal(t, int64(1), got.Version)
	require.Equal(t, domain.EventTypeHostCreated, got.Event.Type)

	decoded, err := got.Event.Decode()
	require.NoError(t, err)
	hc, ok := decoded.(domain.HostCreated)
	require.True(t, ok, "decoded event must be HostCreated")
	require.Equal(t, "10.1.0.1", hc.IPAddress)
	require.Equal(t, "compliance.local", hc.Hostname)
}

// TestEventStoreVersionConflict verifies that appending with an incorrect
// expectedVersion returns an error containing "version conflict".
func TestEventStoreVersionConflict(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := hostCreatedEnvelope(aggID, "10.1.0.2", "conflict.local", now)
	require.NoError(t, store.AppendEvent(ctx, aggID, env, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.1.0.2",
		NewIP:     "10.1.0.3",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))

	// Pass wrong expected version — must fail.
	err := store.AppendEvent(ctx, aggID, env2, 999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version conflict")
}

// TestEventStoreEmptyLoad verifies that loading events for an unknown aggregate
// returns an empty slice without an error.
func TestEventStoreEmptyLoad(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	events, err := store.LoadEvents(ctx, ulid.Make())
	require.NoError(t, err)
	require.Empty(t, events)
}

// TestEventStoreGetCurrentVersion verifies that version tracking is correct
// after sequential appends and returns zero for a new aggregate.
func TestEventStoreGetCurrentVersion(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()

	// New aggregate — expect version 0.
	zeroVer, err := store.GetCurrentVersion(ctx, ulid.Make())
	require.NoError(t, err)
	require.Equal(t, int64(0), zeroVer)

	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := hostCreatedEnvelope(aggID, "10.1.0.4", "version.local", now)
	require.NoError(t, store.AppendEvent(ctx, aggID, env1, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.1.0.4",
		NewIP:     "10.1.0.5",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	require.NoError(t, store.AppendEvent(ctx, aggID, env2, 1))

	ver, err := store.GetCurrentVersion(ctx, aggID)
	require.NoError(t, err)
	require.Equal(t, int64(2), ver)
}

// TestEventStoreMultipleAggregatesIsolated verifies that events for distinct
// aggregates do not bleed into each other's load results.
func TestEventStoreMultipleAggregatesIsolated(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, agg1, hostCreatedEnvelope(agg1, "10.2.0.1", "agg1.local", now), 0))
	require.NoError(t, store.AppendEvent(ctx, agg2, hostCreatedEnvelope(agg2, "10.2.0.2", "agg2.local", now), 0))

	events1, err := store.LoadEvents(ctx, agg1)
	require.NoError(t, err)
	require.Len(t, events1, 1)

	events2, err := store.LoadEvents(ctx, agg2)
	require.NoError(t, err)
	require.Len(t, events2, 1)

	require.Equal(t, agg1, events1[0].AggregateID)
	require.Equal(t, agg2, events2[0].AggregateID)
}

// TestEventStoreBatchAppend verifies that AppendEventsBatch writes events for
// multiple aggregates atomically.
func TestEventStoreBatchAppend(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	batch := []storage.AggregateEvents{
		{
			AggregateID:     agg1,
			Events:          []domain.EventEnvelope{hostCreatedEnvelope(agg1, "10.3.0.1", "batch1.local", now)},
			ExpectedVersion: 0,
		},
		{
			AggregateID:     agg2,
			Events:          []domain.EventEnvelope{hostCreatedEnvelope(agg2, "10.3.0.2", "batch2.local", now)},
			ExpectedVersion: 0,
		},
	}
	require.NoError(t, store.AppendEventsBatch(ctx, batch))

	for _, aggID := range []ulid.ULID{agg1, agg2} {
		events, err := store.LoadEvents(ctx, aggID)
		require.NoError(t, err)
		require.Len(t, events, 1, "aggregate %s should have exactly one event", aggID)
	}
}

// ---------- HostProjection compliance ----------

// TestHostProjectionListAll verifies that creating hosts via events causes them
// to appear in ListAll.
func TestHostProjectionListAll(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	// Empty store returns empty slice, not an error.
	entries, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Empty(t, entries)

	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, agg1, hostCreatedEnvelope(agg1, "10.4.0.1", "list1.local", now), 0))
	require.NoError(t, store.AppendEvent(ctx, agg2, hostCreatedEnvelope(agg2, "10.4.0.2", "list2.local", now), 0))

	entries, err = store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	ips := make(map[string]bool)
	for _, e := range entries {
		ips[e.IP] = true
	}
	require.True(t, ips["10.4.0.1"])
	require.True(t, ips["10.4.0.2"])
}

// TestHostProjectionGetByID verifies point lookup by aggregate ID.
func TestHostProjectionGetByID(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.5.0.1", "byid.local", now), 0))

	entry, err := store.GetByID(ctx, aggID)
	require.NoError(t, err)
	require.Equal(t, aggID, entry.ID)
	require.Equal(t, "10.5.0.1", entry.IP)
	require.Equal(t, "byid.local", entry.Hostname)

	// Unknown ID must return a "not found" error.
	_, err = store.GetByID(ctx, ulid.Make())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestHostProjectionDeletedExcludedFromListAll verifies that a HostDeleted event
// removes the entry from ListAll.
func TestHostProjectionDeletedExcludedFromListAll(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.6.0.1", "todelete.local", now), 0))

	del := makeEnvelope(aggID, domain.HostDeleted{
		IPAddress: "10.6.0.1",
		Hostname:  "todelete.local",
		DeletedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	require.NoError(t, store.AppendEvent(ctx, aggID, del, 1))

	entries, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// ---------- SnapshotStore compliance ----------

// TestSnapshotStoreRoundTrip verifies that a snapshot saved via SaveSnapshot can
// be retrieved intact via GetSnapshot with all fields preserved.
func TestSnapshotStoreRoundTrip(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	snapID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	snap := domain.Snapshot{
		SnapshotID:   snapID,
		CreatedAt:    now,
		HostsContent: "",
		Entries: []domain.HostEntry{
			{
				ID:        ulid.Make(),
				IP:        "10.7.0.1",
				Hostname:  "snap.local",
				Tags:      []string{"compliance"},
				Aliases:   []string{},
				Version:   1,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		EntryCount: 1,
		Trigger:    "compliance-test",
		Name:       ptr("compliance snapshot"),
	}

	require.NoError(t, store.SaveSnapshot(ctx, snap))

	got, err := store.GetSnapshot(ctx, snapID)
	require.NoError(t, err)
	require.Equal(t, snapID, got.SnapshotID)
	require.Equal(t, int32(1), got.EntryCount)
	require.Equal(t, "compliance-test", got.Trigger)
	require.NotNil(t, got.Name)
	require.Equal(t, "compliance snapshot", *got.Name)
	require.Len(t, got.Entries, 1)
	require.Equal(t, "10.7.0.1", got.Entries[0].IP)
}

// TestSnapshotStoreNotFound verifies that GetSnapshot for an unknown ID returns
// an error containing "not found".
func TestSnapshotStoreNotFound(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	_, err := store.GetSnapshot(ctx, ulid.Make())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestSnapshotStoreDelete verifies that DeleteSnapshot removes the snapshot and
// subsequent retrieval returns "not found".
func TestSnapshotStoreDelete(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	snapID := ulid.Make()

	require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
		SnapshotID:   snapID,
		CreatedAt:    time.Now().UTC(),
		HostsContent: "",
		EntryCount:   0,
		Trigger:      "manual",
	}))

	require.NoError(t, store.DeleteSnapshot(ctx, snapID))

	_, err := store.GetSnapshot(ctx, snapID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestSnapshotStoreListOrdering verifies that ListSnapshots returns results
// ordered by CreatedAt descending (newest first).
func TestSnapshotStoreListOrdering(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	early := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	oldID := ulid.Make()
	newID := ulid.Make()

	require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
		SnapshotID: oldID, CreatedAt: early, HostsContent: "", EntryCount: 0, Trigger: "auto",
	}))
	require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
		SnapshotID: newID, CreatedAt: late, HostsContent: "", EntryCount: 0, Trigger: "auto",
	}))

	metas, err := store.ListSnapshots(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, metas, 2)
	require.Equal(t, newID, metas[0].SnapshotID, "newest snapshot must be first")
	require.Equal(t, oldID, metas[1].SnapshotID)
}

// TestSnapshotStoreRetentionByCount verifies that ApplyRetentionPolicy removes
// older snapshots when the count exceeds maxCount.
func TestSnapshotStoreRetentionByCount(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	for i := range 5 {
		require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
			SnapshotID:   ulid.Make(),
			CreatedAt:    time.Now().UTC().Add(time.Duration(i) * time.Minute),
			HostsContent: "",
			EntryCount:   0,
			Trigger:      "auto",
		}))
	}

	maxCount := 2
	deleted, err := store.ApplyRetentionPolicy(ctx, &maxCount, nil)
	require.NoError(t, err)
	require.Equal(t, 3, deleted)

	metas, err := store.ListSnapshots(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, metas, 2)
}

// ---------- Storage lifecycle compliance ----------

// TestStorageInitializeIdempotent verifies that calling Initialize multiple
// times does not return an error.
func TestStorageInitializeIdempotent(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
}

// TestStorageHealthCheck verifies that HealthCheck returns nil for a live store.
func TestStorageHealthCheck(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.HealthCheck(ctx))
}

// RunAll executes every compliance test against the provided store. Callers
// pass a factory function that returns a fresh, initialised store for each
// sub-test, keeping tests hermetic.
//
// Usage in a backend test file:
//
//	func TestCompliance(t *testing.T) {
//	    storagetest.RunAll(t, func(t *testing.T) storage.Storage {
//	        s, err := mybackend.New(...)
//	        require.NoError(t, err)
//	        require.NoError(t, s.Initialize(context.Background()))
//	        t.Cleanup(func() { _ = s.Close() })
//	        return s
//	    })
//	}
func RunAll(t *testing.T, factory func(t *testing.T) storage.Storage) {
	t.Helper()

	// EventStore
	t.Run("EventStoreAppendAndLoad", func(t *testing.T) {
		TestEventStoreAppendAndLoad(t, factory(t))
	})
	t.Run("EventStoreVersionConflict", func(t *testing.T) {
		TestEventStoreVersionConflict(t, factory(t))
	})
	t.Run("EventStoreEmptyLoad", func(t *testing.T) {
		TestEventStoreEmptyLoad(t, factory(t))
	})
	t.Run("EventStoreGetCurrentVersion", func(t *testing.T) {
		TestEventStoreGetCurrentVersion(t, factory(t))
	})
	t.Run("EventStoreMultipleAggregatesIsolated", func(t *testing.T) {
		TestEventStoreMultipleAggregatesIsolated(t, factory(t))
	})
	t.Run("EventStoreBatchAppend", func(t *testing.T) {
		TestEventStoreBatchAppend(t, factory(t))
	})

	// HostProjection
	t.Run("HostProjectionListAll", func(t *testing.T) {
		TestHostProjectionListAll(t, factory(t))
	})
	t.Run("HostProjectionGetByID", func(t *testing.T) {
		TestHostProjectionGetByID(t, factory(t))
	})
	t.Run("HostProjectionDeletedExcludedFromListAll", func(t *testing.T) {
		TestHostProjectionDeletedExcludedFromListAll(t, factory(t))
	})

	// SnapshotStore
	t.Run("SnapshotStoreRoundTrip", func(t *testing.T) {
		TestSnapshotStoreRoundTrip(t, factory(t))
	})
	t.Run("SnapshotStoreNotFound", func(t *testing.T) {
		TestSnapshotStoreNotFound(t, factory(t))
	})
	t.Run("SnapshotStoreDelete", func(t *testing.T) {
		TestSnapshotStoreDelete(t, factory(t))
	})
	t.Run("SnapshotStoreListOrdering", func(t *testing.T) {
		TestSnapshotStoreListOrdering(t, factory(t))
	})
	t.Run("SnapshotStoreRetentionByCount", func(t *testing.T) {
		TestSnapshotStoreRetentionByCount(t, factory(t))
	})

	// Lifecycle
	t.Run("StorageInitializeIdempotent", func(t *testing.T) {
		TestStorageInitializeIdempotent(t, factory(t))
	})
	t.Run("StorageHealthCheck", func(t *testing.T) {
		TestStorageHealthCheck(t, factory(t))
	})
}
