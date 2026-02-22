package sqlite

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/suite"

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

func makeEnvelope(aggregateID ulid.ULID, event any, version string, createdAt time.Time) domain.EventEnvelope {
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
	}, "1", t)
}

// ---------- EventStore tests ----------

func (s *StorageSuite) TestAppendAndLoadEventsRoundTrip() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "192.168.1.1", "host1.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 1)
	s.Equal(env.EventID, events[0].EventID)
	s.Equal(aggID, events[0].AggregateID)
	s.Equal("1", events[0].Version)
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
	}, "2", now.Add(time.Second))

	s.Require().NoError(s.store.AppendEvents(s.ctx, aggID, []domain.EventEnvelope{create, update}, ""))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 2)
	s.Equal("1", events[0].Version)
	s.Equal("2", events[1].Version)
}

func (s *StorageSuite) TestVersionConflictOnAppendEvent() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "192.168.1.1", "conflict.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "192.168.1.1",
		NewIP:     "192.168.1.2",
		ChangedAt: now.Add(time.Second),
	}, "2", now.Add(time.Second))

	// Wrong expected version
	err := s.store.AppendEvent(s.ctx, aggID, env2, "wrong")
	s.Require().Error(err)
	s.Contains(err.Error(), "version conflict")
}

func (s *StorageSuite) TestVersionConflictOnAppendEvents() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := s.createHostEvents(aggID, "192.168.1.1", "conflict2.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "192.168.1.1",
		NewIP:     "192.168.1.2",
		ChangedAt: now.Add(time.Second),
	}, "2", now.Add(time.Second))

	err := s.store.AppendEvents(s.ctx, aggID, []domain.EventEnvelope{env2}, "wrong")
	s.Require().Error(err)
	s.Contains(err.Error(), "version conflict")
}

func (s *StorageSuite) TestGetCurrentVersionReturnsLatest() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := s.createHostEvents(aggID, "10.0.0.1", "ver.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, ""))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.0.0.1",
		NewIP:     "10.0.0.2",
		ChangedAt: now.Add(time.Second),
	}, "2", now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, "1"))

	ver, err := s.store.GetCurrentVersion(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal("2", ver)
}

func (s *StorageSuite) TestGetCurrentVersionEmptyForNewAggregate() {
	ver, err := s.store.GetCurrentVersion(s.ctx, ulid.Make())
	s.Require().NoError(err)
	s.Equal("", ver)
}

func (s *StorageSuite) TestCountEvents() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	count, err := s.store.CountEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal(int64(0), count)

	env := s.createHostEvents(aggID, "10.0.0.1", "count.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 1)
	s.Nil(events[0].CreatedBy)
}

func (s *StorageSuite) TestAppendEventCorrectVersionSequence() {
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := s.createHostEvents(aggID, "10.0.0.1", "seq.local", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, ""))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: now.Add(time.Second),
	}, "2", now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, "1"))

	env3 := makeEnvelope(aggID, domain.HostnameChanged{
		OldHostname: "seq.local", NewHostname: "seq2.local", ChangedAt: now.Add(2 * time.Second),
	}, "3", now.Add(2*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env3, "2"))

	events, err := s.store.LoadEvents(s.ctx, aggID)
	s.Require().NoError(err)
	s.Require().Len(events, 3)
	s.Equal("1", events[0].Version)
	s.Equal("2", events[1].Version)
	s.Equal("3", events[2].Version)
}

func (s *StorageSuite) TestMultipleAggregatesIsolated() {
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, s.createHostEvents(agg1, "10.0.0.1", "a.local", now), ""))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, s.createHostEvents(agg2, "10.0.0.2", "b.local", now), ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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

// ---------- SnapshotStore tests ----------

func (s *StorageSuite) TestSaveAndGetSnapshotRoundTrip() {
	snap := domain.Snapshot{
		SnapshotID:   "snap-001",
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
		HostsContent: "",
		Entries: []domain.HostEntry{
			{ID: ulid.Make(), IP: "10.0.0.1", Hostname: "a.local", Tags: []string{"web"}, Aliases: []string{}, Version: "1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		EntryCount: 1,
		Trigger:    "manual",
		Name:       ptr("test snapshot"),
	}

	s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))

	got, err := s.store.GetSnapshot(s.ctx, "snap-001")
	s.Require().NoError(err)
	s.Equal("snap-001", got.SnapshotID)
	s.Equal(int32(1), got.EntryCount)
	s.Equal("manual", got.Trigger)
	s.Require().NotNil(got.Name)
	s.Equal("test snapshot", *got.Name)
	s.Require().Len(got.Entries, 1)
	s.Equal("10.0.0.1", got.Entries[0].IP)
}

func (s *StorageSuite) TestGetSnapshotNotFound() {
	_, err := s.store.GetSnapshot(s.ctx, "nonexistent")
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestListSnapshotsWithPagination() {
	for i := range 5 {
		snap := domain.Snapshot{
			SnapshotID:   fmt.Sprintf("snap-%03d", i),
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

	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: "old", CreatedAt: early, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: "new", CreatedAt: late, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))

	metas, err := s.store.ListSnapshots(s.ctx, nil, nil)
	s.Require().NoError(err)
	s.Require().Len(metas, 2)
	s.Equal("new", metas[0].SnapshotID)
	s.Equal("old", metas[1].SnapshotID)
}

func (s *StorageSuite) TestListSnapshotsWithOffset() {
	for i := range 5 {
		snap := domain.Snapshot{
			SnapshotID:   fmt.Sprintf("snap-%03d", i),
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
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: "to-delete", CreatedAt: time.Now().UTC(), HostsContent: "[]", EntryCount: 0, Trigger: "manual",
	}))

	s.Require().NoError(s.store.DeleteSnapshot(s.ctx, "to-delete"))

	_, err := s.store.GetSnapshot(s.ctx, "to-delete")
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestDeleteSnapshotNotFound() {
	err := s.store.DeleteSnapshot(s.ctx, "nonexistent")
	s.Require().Error(err)
	s.Contains(err.Error(), "not found")
}

func (s *StorageSuite) TestApplyRetentionPolicyByCount() {
	for i := range 5 {
		snap := domain.Snapshot{
			SnapshotID:   fmt.Sprintf("ret-count-%03d", i),
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

	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: "old-snap", CreatedAt: old, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, domain.Snapshot{
		SnapshotID: "recent-snap", CreatedAt: recent, HostsContent: "[]", EntryCount: 0, Trigger: "auto",
	}))

	maxAge := 30
	deleted, err := s.store.ApplyRetentionPolicy(s.ctx, nil, &maxAge)
	s.Require().NoError(err)
	s.Equal(1, deleted)

	metas, err := s.store.ListSnapshots(s.ctx, nil, nil)
	s.Require().NoError(err)
	s.Len(metas, 1)
	s.Equal("recent-snap", metas[0].SnapshotID)
}

func (s *StorageSuite) TestSaveSnapshotWithEventLogPosition() {
	pos := int64(42)
	snap := domain.Snapshot{
		SnapshotID:       "snap-pos",
		CreatedAt:        time.Now().UTC().Truncate(time.Millisecond),
		HostsContent:     "[]",
		EntryCount:       0,
		Trigger:          "auto",
		EventLogPosition: &pos,
	}
	s.Require().NoError(s.store.SaveSnapshot(s.ctx, snap))

	got, err := s.store.GetSnapshot(s.ctx, "snap-pos")
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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	}, "1", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	}, "1", now)
	env2 := makeEnvelope(agg2, domain.HostCreated{
		IPAddress: "10.0.0.2", Hostname: "b.local", Tags: []string{"db"}, Aliases: []string{}, CreatedAt: now,
	}, "1", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, env1, ""))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, env2, ""))

	entries, err := s.store.Search(s.ctx, domain.SearchFilter{Tags: []string{"web"}})
	s.Require().NoError(err)
	s.Len(entries, 1)
	s.Equal("a.local", entries[0].Hostname)
}

func (s *StorageSuite) TestSearchByIPPattern() {
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, s.createHostEvents(agg1, "192.168.1.1", "a.local", now), ""))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, s.createHostEvents(agg2, "10.0.0.1", "b.local", now), ""))

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

	s.Require().NoError(s.store.AppendEvent(s.ctx, agg1, s.createHostEvents(agg1, "10.0.0.1", "web.prod.local", now), ""))
	s.Require().NoError(s.store.AppendEvent(s.ctx, agg2, s.createHostEvents(agg2, "10.0.0.2", "db.staging.local", now), ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, ""))

	env2 := makeEnvelope(aggID, domain.HostDeleted{
		IPAddress: "10.0.0.1",
		Hostname:  "deleted.local",
		DeletedAt: now.Add(time.Second),
	}, "2", now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, "1"))

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
	}, "1", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, ""))

	// Change IP
	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: now.Add(time.Second),
	}, "2", now.Add(time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, "1"))

	// Change hostname
	env3 := makeEnvelope(aggID, domain.HostnameChanged{
		OldHostname: "orig.local", NewHostname: "new.local", ChangedAt: now.Add(2 * time.Second),
	}, "3", now.Add(2*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env3, "2"))

	// Change comment
	env4 := makeEnvelope(aggID, domain.CommentUpdated{
		OldComment: ptr("old comment"), NewComment: ptr("new comment"), UpdatedAt: now.Add(3 * time.Second),
	}, "4", now.Add(3*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env4, "3"))

	// Change tags
	env5 := makeEnvelope(aggID, domain.TagsModified{
		OldTags: []string{"old-tag"}, NewTags: []string{"new-tag"}, ModifiedAt: now.Add(4 * time.Second),
	}, "5", now.Add(4*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env5, "4"))

	// Change aliases
	env6 := makeEnvelope(aggID, domain.AliasesModified{
		OldAliases: []string{"old-alias"}, NewAliases: []string{"new-alias"}, ModifiedAt: now.Add(5 * time.Second),
	}, "6", now.Add(5*time.Second))
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env6, "5"))

	entry, err := s.store.GetByID(s.ctx, aggID)
	s.Require().NoError(err)
	s.Equal("10.0.0.2", entry.IP)
	s.Equal("new.local", entry.Hostname)
	s.Require().NotNil(entry.Comment)
	s.Equal("new comment", *entry.Comment)
	s.Equal([]string{"new-tag"}, entry.Tags)
	s.Equal([]string{"new-alias"}, entry.Aliases)
	s.Equal("6", entry.Version)
}

func (s *StorageSuite) TestGetAtTimeReturnsStateAtPoint() {
	aggID := ulid.Make()
	t1 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2025, 1, 3, 12, 0, 0, 0, time.UTC)

	env1 := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "time.local", Tags: []string{}, Aliases: []string{}, CreatedAt: t1,
	}, "1", t1)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env1, ""))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: t3,
	}, "2", t3)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env2, "1"))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

	entries, err := s.store.GetAtTime(s.ctx, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	s.Require().NoError(err)
	s.Empty(entries)
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
	}, "1", now)
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, env, ""))

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
	s.Require().NoError(s.store.AppendEvent(s.ctx, aggID, s.createHostEvents(aggID, "10.0.0.1", "all.local", now), ""))

	entries, err := s.store.Search(s.ctx, domain.SearchFilter{})
	s.Require().NoError(err)
	s.Len(entries, 1)
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
