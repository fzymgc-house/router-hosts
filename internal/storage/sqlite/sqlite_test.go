package sqlite

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/suite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// StorageSuite runs compliance tests against the SQLite storage implementation.
type StorageSuite struct {
	suite.Suite
	store *Storage
	ctx   context.Context
}

func TestStorageSuite(t *testing.T) {
	suite.Run(t, new(StorageSuite))
}

func (s *StorageSuite) SetupTest() {
	var err error
	s.ctx = context.Background()
	s.store, err = New("file::memory:?mode=memory&cache=shared", slog.Default())
	s.Require().NoError(err)
	s.Require().NoError(s.store.Initialize(s.ctx))
}

func (s *StorageSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
	}
}

// ---------- helpers ----------

func makeEnvelope(aggregateID ulid.ULID, event any, version int64, createdAt time.Time) domain.EventEnvelope {
	he, err := domain.NewHostEvent(event)
	if err != nil {
		panic(fmt.Sprintf("NewHostEvent: %v", err))
	}
	return domain.EventEnvelope{
		EventID:     ulid.Make(),
		AggregateID: aggregateID,
		Event:       he,
		Version:     version,
		CreatedAt:   createdAt,
	}
}

func ptr[T any](v T) *T { return &v }

func (s *StorageSuite) createHostEvents(aggID ulid.ULID, ip, hostname string, t time.Time) domain.EventEnvelope {
	return makeEnvelope(aggID, domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: t,
	}, 1, t)
}

// ---------- EventStore tests ----------

func (s *StorageSuite) TestAppendAndLoadEventsRoundTrip() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "192.168.1.1", "host1.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 1)
	s.Equal(env.EventID, events[0].EventID)
	s.Equal(aggID, events[0].AggregateID)
	s.Equal(int64(1), events[0].Version)
	s.Equal(domain.EventTypeHostCreated, events[0].Event.Type)
}

func (s *StorageSuite) TestAppendEventsBatchAndOrdering() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	create := s.createHostEvents(aggID, "10.0.0.1", "batch.local", now)
	update := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.0.0.1",
		NewIP:     "10.0.0.2",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))

	s.Require().NoError(s.store.AppendEvents(s.ctx, aggID, []domain.EventEnvelope{create, update}, 0))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 2)
	s.Equal(int64(1), events[0].Version)
	s.Equal(int64(2), events[1].Version)
}

func (s *StorageSuite) TestVersionConflictOnAppendEvent() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "192.168.1.1", "conflict.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "192.168.1.1",
		NewIP:     "192.168.1.2",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))

	// Wrong expected version
	err := s.store.AppendEvent(s.ctx, aggID, env2, 999)
	s.Require().Error(err)
	s.Contains(err.Error(), "version conflict")
}

func (s *StorageSuite) TestVersionConflictOnAppendEvents() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "192.168.1.1", "conflict2.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "192.168.1.1",
		NewIP:     "192.168.1.2",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))

	err := s.store.AppendEvents(s.ctx, aggID, []domain.EventEnvelope{env2}, 999)
	s.Require().Error(err)
	s.Contains(err.Error(), "version conflict")
}

func (s *StorageSuite) TestGetCurrentVersionReturnsLatest() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := s.createHostEvents(aggID, "10.0.0.1", "ver.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.0.0.1",
		NewIP:     "10.0.0.2",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, 1))

	ver, err := s.store.GetCurrentVersion(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal(int64(2), ver)
}

func (s *StorageSuite) TestGetCurrentVersionEmptyForNewAggregate() {
	ver, err := s.store.GetCurrentVersion(s.ctx, ulid.Make())
	s.Require().NoError(err)
	s.Equal(int64(0), ver)
}

func (s *StorageSuite) TestCountEvents() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	count, err := s.store.CountEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal(int64(0), count)

	env := s.createHostEvents(aggID, "10.0.0.1", "count.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	count, err = s.store.CountEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal(int64(1), count)
}

func (s *StorageSuite) TestLoadEventsEmptyForUnknownAggregate() {
	events, err := s.store.LoadEvents(s.ctx, ulid.Make())
	s.Require().NoError(err)
	s.Empty(events)
}

func (s *StorageSuite) TestAppendEventWithCreatedBy() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "10.0.0.1", "author.local", now)
	env.CreatedBy = ptr("testuser")
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 1)
	s.Require().NotNil(events[0].CreatedBy)
	s.Equal("testuser", *events[0].CreatedBy)
}

func (s *StorageSuite) TestAppendEventWithNilCreatedBy() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "10.0.0.1", "noauthor.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 1)
	s.Nil(events[0].CreatedBy)
}

func (s *StorageSuite) TestAppendEventCorrectVersionSequence() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := s.createHostEvents(aggID, "10.0.0.1", "seq.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, 1))

	env3 := makeEnvelope(aggID, domain.HostnameChanged{
		OldHostname: "seq.local", NewHostname: "seq2.local", ChangedAt: now.Add(2 * time.Second),
	}, 3, now.Add(2*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env3, 2))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 3)
	s.Equal(int64(1), events[0].Version)
	s.Equal(int64(2), events[1].Version)
	s.Equal(int64(3), events[2].Version)
}

func (s *StorageSuite) TestMultipleAggregatesIsolated() {
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, s.createHostEvents(agg1, "10.0.0.1", "a.local", now), 0))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, s.createHostEvents(agg2, "10.0.0.2", "b.local", now), 0))

	events1, err := s.store.LoadEvents(s.ctx, agg1)
	s.Require().NoError(err)
	s.Len(events1, 1)

	events2, err := s.store.LoadEvents(s.ctx, agg2)
	s.Require().NoError(err)
	s.Len(events2, 1)

	count1, _ := s.store.CountEvents(s.ctx, agg1)
	count2, _ := s.store.CountEvents(s.ctx, agg2)
	s.Equal(int64(1), count1)
	s.Equal(int64(1), count2)
}

func (s *StorageSuite) TestAppendEventPreservesEventType() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "10.0.0.1", "type.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 1)
	s.Equal(domain.EventTypeHostCreated, events[0].Event.Type)

	decoded, decodeErr := events[0].Event.Decode()
	s.Require().NoError(decodeErr)
	created, ok := decoded.(domain.HostCreated)
	s.Require().True(ok)
	s.Equal("10.0.0.1", created.IPAddress)
	s.Equal("type.local", created.Hostname)
}

func (s *StorageSuite) TestVersionOrderingBeyondTen() {
	// Regression test for Finding 133.61: TEXT sort would order "10" before "2"
	// lexicographically. This confirms int64 column sorting is correct.
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Append version 1 (HostCreated) then versions 2-15 as IPAddressChanged events.
	env1 := s.createHostEvents(aggID, "10.0.0.1", "order.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, 0))

	for v := int64(2); v <= 15; v++ {
		env := makeEnvelope(aggID, domain.IPAddressChanged{
			OldIP:     fmt.Sprintf("10.0.0.%d", v-1),
			NewIP:     fmt.Sprintf("10.0.0.%d", v),
			ChangedAt: now.Add(time.Duration(v) * time.Second),
		}, v, now.Add(time.Duration(v)*time.Second))
		s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, v-1))
	}

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 15)

	for i, ev := range events {
		expected := int64(i + 1)
		s.Equal(expected, ev.Version, "event at index %d should have version %d, got %d", i, expected, ev.Version)
	}
}

// ---------- HostProjection / Search tests ----------

// TestSearchByAliasNotSupported documents that the current Search implementation
// does not match aliases when using the Query filter. The Query field matches
// against IP, hostname, comment, and tags — but not aliases. This test creates a
// host with an alias and confirms that a query matching only the alias does NOT
// return the host. If alias search support is added in the future, this test
// should be updated to assert the host IS found.
func (s *StorageSuite) TestSearchByAlias_NotCurrentlySupported() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Create host with an alias "myalias.local"
	createEnv := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.1.2.3",
		Hostname:  "primary.local",
		Aliases:   []string{"myalias.local"},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, createEnv, 0))

	// Search using a query that matches only the alias (not the hostname or IP)
	q := "myalias"
	results, err := s.store.Search(s.ctx, domain.SearchFilter{Query: &q})
	s.Require().NoError(err)

	// Alias search is not yet implemented: the host is NOT found via alias query.
	// When alias search is added, change this assertion to s.Len(results, 1) and
	// verify the returned entry matches the host above.
	s.Empty(results, "alias search is not supported; expected no results for alias-only query")
}

// ---------- SnapshotStore tests ----------

func (s *StorageSuite) TestSaveAndGetSnapshotRoundTrip() {
	snapID := ulid.Make()
	snap := domain.Snapshot{
		SnapshotID:   snapID,
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
		HostsContent: "",
		Entries: []domain.HostEntry{
			{ID: ulid.Make(), IP: "10.0.0.1", Hostname: "a.local", Tags: []string{"web"}, Aliases: []string{}, Version: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		EntryCount: 1,
		Trigger:    "manual",
		Name:       ptr("test snapshot"),
	}

	s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))

	got, err := s.store.GetSnapshot(s.ctx, snapID)
	s.Require().NoError(err)
	s.Equal(snapID, got.SnapshotID)
	s.Equal(int32(1), got.EntryCount)
	s.Equal("manual", got.Trigger)
	s.Require().NotNil(got.Name)
	s.Equal("test snapshot", *got.Name)
	s.Require().Len(got.Entries, 1)
	s.Equal("10.0.0.1", got.Entries[0].IP)
}

func (s *StorageSuite) TestGetSnapshotNotFound() {
	_, err := s.store.GetSnapshot(s.ctx, ulid.Make())
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestListSnapshotsWithPagination() {
	for i := range 5 {
		snap := domain.Snapshot{
			SnapshotID:   ulid.Make(),
			CreatedAt:    time.Now().UTC().Add(time.Duration(i) * time.Minute).Truncate(time.Millisecond),
			HostsContent: "[]",
			EntryCount:   0,
			Trigger:      "auto",
		}
		s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))
	}

	limit := uint32(2)
	metas, err := s.store.ListSnapshots(s.ctx, &limit, nil)
	s.Require().NoError(err)
	s.Len(metas, 2)
}

func (s *StorageSuite) TestListSnapshotsOrdering() {
	early := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	oldID := ulid.Make()
	newID := ulid.Make()

	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: oldID, CreatedAt: early, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: newID, CreatedAt: late, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))

	metas, err := s.store.ListSnapshots(s.ctx, nil, nil)
	s.Require().NoError(err)
	s.Require().Len(metas, 2)
	s.Equal(newID, metas[0].SnapshotID)
	s.Equal(oldID, metas[1].SnapshotID)
}

func (s *StorageSuite) TestListSnapshotsWithOffset() {
	for i := range 5 {
		snap := domain.Snapshot{
			SnapshotID:   ulid.Make(),
			CreatedAt:    time.Now().UTC().Add(time.Duration(i) * time.Minute).Truncate(time.Millisecond),
			HostsContent: "[]",
			EntryCount:   0,
			Trigger:      "auto",
		}
		s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))
	}

	limit := uint32(2)
	offset := uint32(2)
	metas, err := s.store.ListSnapshots(s.ctx, &limit, &offset)
	s.Require().NoError(err)
	s.Len(metas, 2)
}

func (s *StorageSuite) TestDeleteSnapshotSuccess() {
	deleteID := ulid.Make()
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: deleteID, CreatedAt: time.Now().UTC(), HostsContent: "[]", EntryCount: 0, Trigger: "manual",
	}))

	s.Require().NoError(s.store.DeleteSnapshot(s.ctx, deleteID))

	_, err := s.store.GetSnapshot(s.ctx, deleteID)
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestDeleteSnapshotNotFound() {
	err := s.store.DeleteSnapshot(s.ctx, ulid.Make())
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestApplyRetentionPolicyByCount() {
	for i := range 5 {
		snap := domain.Snapshot{
			SnapshotID:   ulid.Make(),
			CreatedAt:    time.Now().UTC().Add(time.Duration(i) * time.Minute).Truncate(time.Millisecond),
			HostsContent: "[]",
			EntryCount:   0,
			Trigger:      "auto",
		}
		s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))
	}

	maxCount := 2
	deleted, err := s.store.ApplyRetentionPolicy(s.ctx, &maxCount, nil)
	s.Require().NoError(err)
	s.Equal(3, deleted)

	metas, err := s.store.ListSnapshots(s.ctx, nil, nil)
	s.Require().NoError(err)
	s.Len(metas, 2)
}

func (s *StorageSuite) TestApplyRetentionPolicyByAge() {
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	recent := time.Now().UTC()

	recentID := ulid.Make()
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: ulid.Make(), CreatedAt: old, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: recentID, CreatedAt: recent, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))

	maxAge := 30
	deleted, err := s.store.ApplyRetentionPolicy(s.ctx, nil, &maxAge)
	s.Require().NoError(err)
	s.Equal(1, deleted)

	metas, err := s.store.ListSnapshots(s.ctx, nil, nil)
	s.Require().NoError(err)
	s.Len(metas, 1)
	s.Equal(recentID, metas[0].SnapshotID)
}

func (s *StorageSuite) TestSaveSnapshotWithEventLogPosition() {
	posID := ulid.Make()
	pos := int64(42)
	snap := domain.Snapshot{
		SnapshotID:       posID,
		CreatedAt:        time.Now().UTC().Truncate(time.Millisecond),
		HostsContent:     "[]",
		EntryCount:       0,
		Trigger:          "auto",
		EventLogPosition: &pos,
	}
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))

	got, err := s.store.GetSnapshot(s.ctx, posID)
	s.Require().NoError(err)
	s.Require().NotNil(got.EventLogPosition)
	s.Equal(int64(42), *got.EventLogPosition)
}

// ---------- HostProjection tests ----------

func (s *StorageSuite) TestListAllEmpty() {
	entries, err := s.store.ListAll(s.ctx)
	s.Require().NoError(err)
	s.Empty(entries)
}

func (s *StorageSuite) TestListAllWithHosts() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)
	env := s.createHostEvents(aggID, "10.0.0.1", "listed.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	entries, err := s.store.ListAll(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(entries, 1)
	s.Equal("10.0.0.1", entries[0].IP)
	s.Equal("listed.local", entries[0].Hostname)
}

func (s *StorageSuite) TestGetByIDFound() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)
	env := s.createHostEvents(aggID, "10.0.0.1", "found.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	entry, err := s.store.GetByID(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal(aggID, entry.ID)
	s.Equal("10.0.0.1", entry.IP)
}

func (s *StorageSuite) TestGetByIDNotFound() {
	_, err := s.store.GetByID(s.ctx, ulid.Make())
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestFindByIPAndHostnameFound() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)
	env := s.createHostEvents(aggID, "10.0.0.5", "findme.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	entry, err := s.store.FindByIPAndHostname(s.ctx, "10.0.0.5", "findme.local")
	s.Require().NoError(err)
	s.Equal(aggID, entry.ID)
}

func (s *StorageSuite) TestFindByIPAndHostnameNotFound() {
	_, err := s.store.FindByIPAndHostname(s.ctx, "99.99.99.99", "nope.local")
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestSearchByQuery() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1",
		Hostname:  "webserver.prod",
		Tags:      []string{"production", "web"},
		Aliases:   []string{},
		CreatedAt: now,
	}, 1, now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	// Search by hostname
	q := "webserver"
	entries, err := s.store.Search(s.ctx, domain.SearchFilter{Query: &q})
	s.Require().NoError(err)
	s.Len(entries, 1)

	// Search by IP
	q = "10.0.0"
	entries, err = s.store.Search(s.ctx, domain.SearchFilter{Query: &q})
	s.Require().NoError(err)
	s.Len(entries, 1)

	// Search by tag
	q = "production"
	entries, err = s.store.Search(s.ctx, domain.SearchFilter{Query: &q})
	s.Require().NoError(err)
	s.Len(entries, 1)

	// No match
	q = "nonexistent"
	entries, err = s.store.Search(s.ctx, domain.SearchFilter{Query: &q})
	s.Require().NoError(err)
	s.Empty(entries)
}

func (s *StorageSuite) TestSearchByTagFilter() {
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := makeEnvelope(agg1, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "a.local", Tags: []string{"web"}, Aliases: []string{}, CreatedAt: now,
	}, 1, now)
	env2 := makeEnvelope(agg2, domain.HostCreated{
		IPAddress: "10.0.0.2", Hostname: "b.local", Tags: []string{"db"}, Aliases: []string{}, CreatedAt: now,
	}, 1, now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, env1, 0))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, env2, 0))

	entries, err := s.store.Search(s.ctx, domain.SearchFilter{Tags: []string{"web"}})
	s.Require().NoError(err)
	s.Len(entries, 1)
	s.Equal("a.local", entries[0].Hostname)
}

func (s *StorageSuite) TestSearchByIPPattern() {
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, s.createHostEvents(agg1, "192.168.1.1", "a.local", now), 0))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, s.createHostEvents(agg2, "10.0.0.1", "b.local", now), 0))

	pattern := "192.168"
	entries, err := s.store.Search(s.ctx, domain.SearchFilter{IPPattern: &pattern})
	s.Require().NoError(err)
	s.Len(entries, 1)
	s.Equal("a.local", entries[0].Hostname)
}

func (s *StorageSuite) TestSearchByHostnamePattern() {
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, s.createHostEvents(agg1, "10.0.0.1", "web.prod.local", now), 0))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, s.createHostEvents(agg2, "10.0.0.2", "db.staging.local", now), 0))

	pattern := "prod"
	entries, err := s.store.Search(s.ctx, domain.SearchFilter{HostnamePattern: &pattern})
	s.Require().NoError(err)
	s.Len(entries, 1)
	s.Equal("web.prod.local", entries[0].Hostname)
}

func (s *StorageSuite) TestDeleteHostExcludedFromListAll() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := s.createHostEvents(aggID, "10.0.0.1", "deleted.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, 0))

	env2 := makeEnvelope(aggID, domain.HostDeleted{
		IPAddress: "10.0.0.1",
		Hostname:  "deleted.local",
		DeletedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, 1))

	entries, err := s.store.ListAll(s.ctx)
	s.Require().NoError(err)
	s.Empty(entries)
}

func (s *StorageSuite) TestUpdateFieldsViaGranularEvents() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Create
	env1 := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1",
		Hostname:  "orig.local",
		Tags:      []string{"old-tag"},
		Aliases:   []string{"old-alias"},
		Comment:   ptr("old comment"),
		CreatedAt: now,
	}, 1, now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, 0))

	// Change IP
	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, 1))

	// Change hostname
	env3 := makeEnvelope(aggID, domain.HostnameChanged{
		OldHostname: "orig.local", NewHostname: "new.local", ChangedAt: now.Add(2 * time.Second),
	}, 3, now.Add(2*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env3, 2))

	// Change comment
	env4 := makeEnvelope(aggID, domain.CommentUpdated{
		OldComment: ptr("old comment"), NewComment: ptr("new comment"), UpdatedAt: now.Add(3 * time.Second),
	}, 4, now.Add(3*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env4, 3))

	// Change tags
	env5 := makeEnvelope(aggID, domain.TagsModified{
		OldTags: []string{"old-tag"}, NewTags: []string{"new-tag"}, ModifiedAt: now.Add(4 * time.Second),
	}, 5, now.Add(4*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env5, 4))

	// Change aliases
	env6 := makeEnvelope(aggID, domain.AliasesModified{
		OldAliases: []string{"old-alias"}, NewAliases: []string{"new-alias"}, ModifiedAt: now.Add(5 * time.Second),
	}, 6, now.Add(5*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env6, 5))

	entry, err := s.store.GetByID(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal("10.0.0.2", entry.IP)
	s.Equal("new.local", entry.Hostname)
	s.Require().NotNil(entry.Comment)
	s.Equal("new comment", *entry.Comment)
	s.Equal([]string{"new-tag"}, entry.Tags)
	s.Equal([]string{"new-alias"}, entry.Aliases)
	s.Equal(int64(6), entry.Version)
}

func (s *StorageSuite) TestGetAtTimeReturnsStateAtPoint() {
	aggID := ulid.Make()
	t1 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2025, 1, 3, 12, 0, 0, 0, time.UTC)

	env1 := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "time.local", Tags: []string{}, Aliases: []string{}, CreatedAt: t1,
	}, 1, t1)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: t3,
	}, 2, t3)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, 1))

	// At t2, should see original IP
	entries, err := s.store.GetAtTime(s.ctx, t2)
	s.Require().NoError(err)
	s.Require().Len(entries, 1)
	s.Equal("10.0.0.1", entries[0].IP)

	// At t3, should see updated IP
	entries, err = s.store.GetAtTime(s.ctx, t3)
	s.Require().NoError(err)
	s.Require().Len(entries, 1)
	s.Equal("10.0.0.2", entries[0].IP)
}

func (s *StorageSuite) TestGetAtTimeBeforeCreation() {
	aggID := ulid.Make()
	t1 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	env := s.createHostEvents(aggID, "10.0.0.1", "future.local", t1)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	entries, err := s.store.GetAtTime(s.ctx, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	s.Require().NoError(err)
	s.Empty(entries)
}

// TestGetByIDDeletedHostNotFound verifies that GetByID returns not-found for
// a host that was created and then deleted (Finding 133.55).
func (s *StorageSuite) TestGetByIDDeletedHostNotFound() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Create the host.
	createEnv := s.createHostEvents(aggID, "10.0.0.1", "deleted-by-id.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, createEnv, 0))

	// Delete the host.
	deleteEnv := makeEnvelope(aggID, domain.HostDeleted{
		IPAddress: "10.0.0.1",
		Hostname:  "deleted-by-id.local",
		DeletedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, deleteEnv, 1))

	// GetByID must return not-found, not the deleted entry.
	entry, err := s.store.GetByID(s.ctx, aggID)
	s.Require().Error(err)
	s.Nil(entry)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestHostImportedCreatesEntry() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := makeEnvelope(aggID, domain.HostImported{
		IPAddress:  "172.16.0.1",
		Hostname:   "imported.local",
		Comment:    ptr("imported host"),
		Tags:       []string{"imported"},
		Aliases:    []string{"imp.local"},
		OccurredAt: now,
	}, 1, now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	entry, err := s.store.GetByID(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal("172.16.0.1", entry.IP)
	s.Equal("imported.local", entry.Hostname)
	s.Require().NotNil(entry.Comment)
	s.Equal("imported host", *entry.Comment)
	s.Equal([]string{"imported"}, entry.Tags)
	s.Equal([]string{"imp.local"}, entry.Aliases)
}

func (s *StorageSuite) TestSearchEmptyFilterReturnsAll() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, s.createHostEvents(aggID, "10.0.0.1", "all.local", now), 0))

	entries, err := s.store.Search(s.ctx, domain.SearchFilter{})
	s.Require().NoError(err)
	s.Len(entries, 1)
}

// ---------- replayEvents error propagation tests ----------

// TestReplayEventsDecodeError verifies that replayEvents surfaces decode errors
// rather than silently skipping corrupt events (regression for Finding 133.10).
func (s *StorageSuite) TestReplayEventsDecodeError() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Insert a valid HostCreated event via the public API.
	env := s.createHostEvents(aggID, "10.0.0.1", "decode-err.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, 0))

	// Directly insert a corrupt event into the events table using raw SQL.
	// The event_data is valid JSON at the outer level (so scanEventEnvelope's
	// json.Unmarshal succeeds), but the payload has ip_address as an integer
	// instead of a string, which causes HostCreated decode to fail.
	corruptData := `{"type":"host_created","ip_address":99999,"hostname":"bad","aliases":[],"tags":[]}`
	conn, err := s.store.pool.Take(s.ctx)
	s.Require().NoError(err)
	err = sqlitex.Execute(conn,
		`INSERT INTO events (event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		&sqlitex.ExecOptions{
			Args: []any{
				ulid.Make().String(),
				aggID.String(),
				"host_created",
				corruptData,
				int64(2),
				now.Add(time.Second).UTC().Format(timeFormat),
			},
		})
	s.store.pool.Put(conn)
	s.Require().NoError(err)

	// GetByID uses replayEvents — must return an error, not silently skip.
	_, err = s.store.GetByID(s.ctx, aggID)
	s.Require().Error(err, "GetByID must propagate decode error from corrupt event")

	// ListAll also uses replayEvents — must likewise return an error.
	_, err = s.store.ListAll(s.ctx)
	s.Require().Error(err, "ListAll must propagate decode error from corrupt event")
}

// ---------- Lifecycle tests ----------

func (s *StorageSuite) TestInitializeIdempotent() {
	// Initialize was already called in SetupTest, call again
	s.Require().NoError(s.store.Initialize(s.ctx))
}

func (s *StorageSuite) TestHealthCheckSucceeds() {
	s.Require().NoError(s.store.HealthCheck(s.ctx))
}

func (s *StorageSuite) TestBackendName() {
	s.Equal("sqlite", s.store.BackendName())
}
