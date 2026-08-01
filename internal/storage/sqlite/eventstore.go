package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

const timeFormat = "2006-01-02T15:04:05.000Z"

// AppendEvent appends a single event with optimistic concurrency control.
func (s *Storage) AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion int64) error {
	if cerr := ctx.Err(); cerr != nil {
		return oops.Wrapf(cerr, "append aborted: context already done")
	}
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return oops.Wrapf(err, "take connection")
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return oops.Wrapf(err, "begin transaction")
	}
	defer endFn(&err)

	if err = checkVersion(conn, aggregateID, expectedVersion); err != nil {
		return oops.Wrapf(err, "append event to aggregate %s", aggregateID)
	}

	if err = insertEvent(conn, event); err != nil {
		return oops.Wrapf(err, "append event to aggregate %s", aggregateID)
	}

	// The deferred endFn(&err) commits only when err == nil. If the request
	// deadline passed while we were working, force a rollback so a timed-out
	// request does not silently persist (which would defeat OCC on retry — #330).
	if err = ctx.Err(); err != nil {
		return oops.Wrapf(err, "append aborted: context done before commit")
	}
	return nil
}

// AppendEvents appends multiple events atomically with optimistic concurrency control.
func (s *Storage) AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion int64) error {
	if cerr := ctx.Err(); cerr != nil {
		return oops.Wrapf(cerr, "append aborted: context already done")
	}
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return oops.Wrapf(err, "take connection")
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return oops.Wrapf(err, "begin transaction")
	}
	defer endFn(&err)

	if err = checkVersion(conn, aggregateID, expectedVersion); err != nil {
		return oops.Wrapf(err, "append event to aggregate %s", aggregateID)
	}

	for _, event := range events {
		if err = insertEvent(conn, event); err != nil {
			return oops.Wrapf(err, "append event to aggregate %s", aggregateID)
		}
	}

	// The deferred endFn(&err) commits only when err == nil. If the request
	// deadline passed while we were working, force a rollback so a timed-out
	// request does not silently persist (which would defeat OCC on retry — #330).
	if err = ctx.Err(); err != nil {
		return oops.Wrapf(err, "append aborted: context done before commit")
	}
	return nil
}

// AppendEventsBatch writes events for multiple aggregates atomically in a
// single SQLite transaction. If any individual write fails (including a
// version conflict), the entire transaction is rolled back.
func (s *Storage) AppendEventsBatch(ctx context.Context, batch []storage.AggregateEvents) error {
	if cerr := ctx.Err(); cerr != nil {
		return oops.Wrapf(cerr, "batch append aborted: context already done")
	}
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return oops.Wrapf(err, "take connection")
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return oops.Wrapf(err, "begin transaction")
	}
	defer endFn(&err)

	for _, ag := range batch {
		if err = checkVersion(conn, ag.AggregateID, ag.ExpectedVersion); err != nil {
			return oops.Wrapf(err, "batch append: check version for aggregate %s", ag.AggregateID)
		}
		for _, event := range ag.Events {
			if err = insertEvent(conn, event); err != nil {
				return oops.Wrapf(err, "batch append: insert event for aggregate %s", ag.AggregateID)
			}
		}
	}

	// The deferred endFn(&err) commits only when err == nil. If the request
	// deadline passed while we were working, force a rollback so a timed-out
	// request does not silently persist (which would defeat OCC on retry — #330).
	if err = ctx.Err(); err != nil {
		return oops.Wrapf(err, "batch append aborted: context done before commit")
	}
	return nil
}

// LoadEvents returns all events for an aggregate ordered by version.
func (s *Storage) LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]domain.EventEnvelope, error) {
	var events []domain.EventEnvelope
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn,
			`SELECT event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by
			 FROM events WHERE aggregate_id = ? ORDER BY event_version ASC`,
			&sqlitex.ExecOptions{
				Args: []any{aggregateID.String()},
				ResultFunc: func(stmt *sqlite.Stmt) error {
					env, scanErr := scanEventEnvelope(stmt)
					if scanErr != nil {
						return scanErr
					}
					events = append(events, env)
					return nil
				},
			})
	})
	if err != nil {
		return nil, oops.Wrapf(err, "load events for aggregate %s", aggregateID)
	}
	return events, nil
}

// GetCurrentVersion returns the latest event version for an aggregate, or 0 if none.
func (s *Storage) GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (int64, error) {
	var version int64
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn,
			`SELECT event_version FROM events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1`,
			&sqlitex.ExecOptions{
				Args: []any{aggregateID.String()},
				ResultFunc: func(stmt *sqlite.Stmt) error {
					version = stmt.ColumnInt64(0)
					return nil
				},
			})
	})
	if err != nil {
		return 0, oops.Wrapf(err, "get current version for aggregate %s", aggregateID)
	}
	return version, nil
}

// CountEvents returns the number of events for an aggregate.
func (s *Storage) CountEvents(ctx context.Context, aggregateID ulid.ULID) (int64, error) {
	var count int64
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn,
			`SELECT COUNT(*) FROM events WHERE aggregate_id = ?`,
			&sqlitex.ExecOptions{
				Args: []any{aggregateID.String()},
				ResultFunc: func(stmt *sqlite.Stmt) error {
					count = stmt.ColumnInt64(0)
					return nil
				},
			})
	})
	if err != nil {
		return 0, oops.Wrapf(err, "count events for aggregate %s", aggregateID)
	}
	return count, nil
}

// ListAggregateIDs returns every distinct aggregate ID in the event log.
func (s *Storage) ListAggregateIDs(ctx context.Context) ([]ulid.ULID, error) {
	var ids []ulid.ULID
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		var innerErr error
		ids, innerErr = getDistinctAggregateIDs(conn)
		return innerErr
	})
	if err != nil {
		return nil, oops.Wrapf(err, "list aggregate ids")
	}
	return ids, nil
}

// LatestEventID returns the greatest event_id in the log (the server's
// change ID, TMPL-08/D-18), or the zero ULID when the log is empty.
func (s *Storage) LatestEventID(ctx context.Context) (ulid.ULID, error) {
	var max ulid.ULID
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		var innerErr error
		max, innerErr = selectLatestEventID(conn)
		return innerErr
	})
	if err != nil {
		return ulid.ULID{}, oops.Wrapf(err, "latest event id")
	}
	return max, nil
}

// selectLatestEventID reads MAX(event_id) over the events table. event_id is
// TEXT PRIMARY KEY (migrations/001_initial.sql:3), so this is an indexed
// seek rather than a table scan. Takes a *sqlite.Conn directly (rather than
// doing its own withConn) so Task 3's in-transaction append guard can call
// it from inside an already-open transaction. A NULL result (an empty
// events table) is reported as the zero ULID, never an error.
func selectLatestEventID(conn *sqlite.Conn) (ulid.ULID, error) {
	var max ulid.ULID
	err := sqlitex.Execute(conn,
		`SELECT MAX(event_id) FROM events`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				if stmt.ColumnType(0) == sqlite.TypeNull {
					return nil
				}
				parsed, parseErr := ulid.Parse(stmt.ColumnText(0))
				if parseErr != nil {
					return oops.Wrapf(parseErr, "parse max event_id")
				}
				max = parsed
				return nil
			},
		})
	if err != nil {
		return ulid.ULID{}, err
	}
	return max, nil
}

// CompactAggregate collapses an aggregate's event log to a single HostCompacted
// seed event at the preserved high-water version, atomically.
func (s *Storage) CompactAggregate(ctx context.Context, aggregateID ulid.ULID) (storage.CompactResult, error) {
	result := storage.CompactResult{AggregateID: aggregateID}
	err := s.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		endFn, txErr := sqlitex.ImmediateTransaction(conn)
		if txErr != nil {
			return oops.Wrapf(txErr, "begin transaction")
		}
		defer endFn(&err)

		events, loadErr := loadEventsForAggregate(conn, aggregateID)
		if loadErr != nil {
			return loadErr
		}
		result.EventsBefore = int64(len(events))
		if len(events) <= 1 {
			result.EventsAfter = result.EventsBefore
			if len(events) == 1 {
				result.Version = events[0].Version
			}
			return nil // no-op
		}

		entry, replayErr := replayEvents(aggregateID, events)
		if replayErr != nil {
			return replayErr
		}
		if entry == nil {
			return oops.Errorf("compact: aggregate %s folded to nil", aggregateID)
		}

		highWater := events[len(events)-1].Version // events are ORDER BY version ASC
		seedEvent := domain.HostCompacted{
			IPAddress:        entry.IP,
			Hostname:         entry.Hostname,
			Aliases:          entry.Aliases,
			Comment:          entry.Comment,
			Tags:             entry.Tags,
			Deleted:          entry.Deleted,
			CreatedAt:        entry.CreatedAt,
			UpdatedAt:        entry.UpdatedAt,
			CompactedAt:      time.Now().UTC(),
			FoldedEventCount: int64(len(events)),
		}
		he, evErr := domain.NewHostEvent(seedEvent)
		if evErr != nil {
			return oops.Wrapf(evErr, "build compacted seed")
		}
		// The replacement seed must be minted through the shared generator
		// (internal/eventid), not a bare ulid.Make(): MAX(event_id) is the
		// server's change ID, and a bare ULID minted here can sort below the
		// maximum this compaction just deleted, which would make the change
		// ID fail to advance or move backward.
		//
		// This function deletes the aggregate's rows (see deleteEventsForAggregate
		// below) BEFORE calling insertEvent, so if the deleted aggregate happened
		// to hold the global maximum, insertEvent's in-transaction MAX(event_id)
		// read sees only the remaining log and has no knowledge of the value
		// that was just removed. What covers that difference is the generator's
		// floor, which sqlite.Storage.Initialize seeded from the persisted
		// maximum and which every prior mint has already raised past the
		// deleted value. Seeding, floor and the in-transaction guard are
		// load-bearing together here; each alone leaves a hole.
		seed := domain.EventEnvelope{
			EventID:     eventid.New(),
			AggregateID: aggregateID,
			Event:       he,
			Version:     highWater,
			CreatedAt:   time.Now().UTC(),
		}

		if delErr := deleteEventsForAggregate(conn, aggregateID); delErr != nil {
			return oops.Wrapf(delErr, "delete events for %s", aggregateID)
		}
		if insErr := insertEvent(conn, seed); insErr != nil {
			return oops.Wrapf(insErr, "insert compacted seed for %s", aggregateID)
		}
		result.EventsAfter = 1
		result.Version = highWater

		// deadline passed while we were working, force a rollback so a timed-out
		// request does not silently persist (which would defeat OCC on retry — #330).
		if err = ctx.Err(); err != nil {
			return oops.Wrapf(err, "compact aborted: context done before commit")
		}
		return nil
	})
	if err != nil {
		return storage.CompactResult{}, oops.Wrapf(err, "compact aggregate %s", aggregateID)
	}
	return result, nil
}

// checkVersion verifies optimistic concurrency by comparing expected vs actual version.
// Pass expectedVersion = -1 to skip the version check entirely (unconditional write).
func checkVersion(conn *sqlite.Conn, aggregateID ulid.ULID, expectedVersion int64) error {
	if expectedVersion == -1 {
		return nil
	}
	var actual int64
	err := sqlitex.Execute(conn,
		`SELECT event_version FROM events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1`,
		&sqlitex.ExecOptions{
			Args: []any{aggregateID.String()},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				actual = stmt.ColumnInt64(0)
				return nil
			},
		})
	if err != nil {
		return oops.Wrapf(err, "check version")
	}
	if actual != expectedVersion {
		return domain.ErrVersionConflict(aggregateID.String(), expectedVersion, actual)
	}
	return nil
}

// insertEvent persists a single event envelope to the events table.
func insertEvent(conn *sqlite.Conn, env domain.EventEnvelope) error {
	// Ordering guard: no commit may land an event ID at or below the log's
	// current maximum (T-1-33, T-1-51, T-1-55). Read the maximum inside this
	// transaction and re-mint above it whenever the proposed ID does not
	// already sort strictly greater. insertEvent receives env by value, so
	// this replacement is local — no caller observes a mutated struct.
	//
	// The comparison is UNCONDITIONAL — there is no emptiness branch, and
	// that is the point (review round-4 H1). Gating this on "the log is
	// non-empty" was the bug: it let a caller-supplied zero ULID insert
	// verbatim into an empty store, making MAX(event_id) equal the zero
	// ULID — indistinguishable from storage.ZeroChangeID, so LatestEventID
	// would report "empty" for a log holding one real event, and the
	// empty-store sentinel would go out on the wire for a non-empty store.
	// selectLatestEventID already returns the zero ULID for a NULL MAX, so
	// an empty log IS a zero maximum: a proposed zero ID compares equal to
	// it, fails the strictly-greater test, and is re-minted like any other
	// non-advancing proposal, with no special case needed. Do not add a
	// `found bool` return to selectLatestEventID, and do not add a separate
	// `env.EventID == ulid.ULID{}` check — both are redundant against this
	// unconditional comparison, and a redundant branch here invites a future
	// "simplification" that keeps the branch and drops the comparison, which
	// is exactly how this defect was introduced the first time. This also
	// establishes a standing invariant two other things rest on: the zero
	// ULID is never a committed event ID, which is what keeps
	// storage.ZeroChangeID an unambiguous empty-store sentinel.
	//
	// Re-mint rather than reject: rejecting would turn a benign concurrent
	// race (T-1-51 — mint order need not equal commit order) into a
	// user-visible write failure on a perfectly legitimate AddHost, and
	// there is no retry loop above insertEvent that would absorb it.
	// Re-minting keeps the write successful while making the log maximum
	// advance, which is the property the change ID actually needs. The ID a
	// caller proposes is therefore advisory: the invariant enforced is "no
	// commit lands an ID at or below the log maximum", NOT "every ID is
	// minted monotonically", which is not achievable for an interface that
	// accepts caller-constructed envelopes (storage.go:51).
	//
	// The read is safe inside the transaction: every caller of insertEvent
	// holds a sqlitex.ImmediateTransaction, which takes SQLite's write lock
	// up front, so no other writer can commit between this read and this
	// insert; and within one transaction the MAX read sees this
	// transaction's own earlier inserts, which is what makes a multi-event
	// batch correct (AppendEventsBatch) without any extra bookkeeping.
	// event_id is TEXT PRIMARY KEY, so the extra read per insert is an
	// indexed seek, and ULID strings are fixed-length Crockford base-32, so
	// lexical string comparison is the same ordering as ulid.ULID.Compare.
	//
	// This is not the only INSERT INTO events statement in the tree
	// (review round-4 M1 — a naive `rg -c 'INSERT INTO events'` expecting 1
	// will fail; read this comment before loosening that gate).
	// legacy_migration.go:183 writes preserved Rust-era event IDs directly,
	// bypassing insertEvent and this guard entirely. That is safe, not by
	// accident: it runs inside Initialize's withConn body, behind
	// isMigrationApplied(conn, legacyMigrationVersion), which is strictly
	// before the eventid.Seed(LatestEventID) call sqlite.go's Initialize
	// adds at the end — so whatever IDs it inserted are already inside the
	// maximum that seeding reads, and the generator's floor lands above
	// them. It is one-shot (recordMigrationVersion marks it applied, so a
	// second Initialize skips it) and it skips entirely when events is
	// already non-empty (legacy_migration.go:43-49), so it can never
	// interleave with live appends. A preserved Rust-era ID whose embedded
	// timestamp is far in the future would pin MAX(event_id) above
	// wall-clock time; that is harmless for new mints precisely because the
	// seeding runs after the migration, so the floor inherits the future
	// value and next() carries past it — the ordering of those two steps is
	// not incidental and must not be swapped. DEBT-01
	// (.planning/REQUIREMENTS.md:89) removes legacy_migration.go outright
	// once all deployments are known-migrated, at which point the
	// single-funnel claim becomes unqualified and this note can go with it.
	max, err := selectLatestEventID(conn)
	if err != nil {
		return oops.Wrapf(err, "read latest event id for ordering guard")
	}
	if env.EventID.Compare(max) <= 0 {
		env.EventID = eventid.NewAfter(max)
	}

	eventData, err := json.Marshal(env.Event)
	if err != nil {
		return oops.Wrapf(err, "marshal event")
	}

	if err := sqlitex.Execute(conn,
		`INSERT INTO events (event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		&sqlitex.ExecOptions{
			Args: []any{
				env.EventID.String(),
				env.AggregateID.String(),
				env.Event.Type,
				string(eventData),
				env.Version,
				env.CreatedAt.UTC().Format(timeFormat),
				ptrToAny(env.CreatedBy),
			},
		}); err != nil {
		return oops.Wrapf(err, "insert event %s for aggregate %s", env.EventID, env.AggregateID)
	}
	return nil
}

// deleteEventsForAggregate removes all events for an aggregate. Caller must be
// inside a transaction.
func deleteEventsForAggregate(conn *sqlite.Conn, aggregateID ulid.ULID) error {
	return sqlitex.Execute(conn,
		`DELETE FROM events WHERE aggregate_id = ?`,
		&sqlitex.ExecOptions{Args: []any{aggregateID.String()}})
}

// scanEventEnvelope reads an EventEnvelope from a query result row.
func scanEventEnvelope(stmt *sqlite.Stmt) (domain.EventEnvelope, error) {
	var env domain.EventEnvelope

	eventID, err := ulid.Parse(stmt.ColumnText(0))
	if err != nil {
		return env, oops.Wrapf(err, "parse event_id")
	}
	env.EventID = eventID

	aggregateID, err := ulid.Parse(stmt.ColumnText(1))
	if err != nil {
		return env, oops.Wrapf(err, "parse aggregate_id")
	}
	env.AggregateID = aggregateID

	// Column 2 is event_type (used indirectly via event_data)
	eventDataStr := stmt.ColumnText(3)
	if err := json.Unmarshal([]byte(eventDataStr), &env.Event); err != nil {
		return env, oops.Wrapf(err, "unmarshal event_data")
	}

	env.Version = stmt.ColumnInt64(4)

	createdAt, err := parseTime(stmt.ColumnText(5))
	if err != nil {
		return env, oops.Wrapf(err, "parse created_at")
	}
	env.CreatedAt = createdAt

	env.CreatedBy = columnTextPtr(stmt, 6)

	return env, nil
}

// ptrToAny converts a *string to an any suitable for SQL parameters.
func ptrToAny(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// columnTextPtr reads a nullable TEXT column as *string.
func columnTextPtr(stmt *sqlite.Stmt, col int) *string {
	if stmt.ColumnType(col) == sqlite.TypeNull {
		return nil
	}
	v := stmt.ColumnText(col)
	return &v
}

// parseTime attempts multiple time formats for flexibility.
func parseTime(s string) (time.Time, error) {
	formats := []string{
		timeFormat,
		time.RFC3339,
		time.RFC3339Nano,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, oops.Errorf("cannot parse time %q", s)
}
