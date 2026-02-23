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
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

const timeFormat = "2006-01-02T15:04:05.000Z"

// AppendEvent appends a single event with optimistic concurrency control.
func (s *Storage) AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion int64) error {
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

	return nil
}

// AppendEvents appends multiple events atomically with optimistic concurrency control.
func (s *Storage) AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion int64) error {
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

	return nil
}

// AppendEventsBatch writes events for multiple aggregates atomically in a
// single SQLite transaction. If any individual write fails (including a
// version conflict), the entire transaction is rolled back.
func (s *Storage) AppendEventsBatch(ctx context.Context, batch []storage.AggregateEvents) error {
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

// checkVersion verifies optimistic concurrency by comparing expected vs actual version.
func checkVersion(conn *sqlite.Conn, aggregateID ulid.ULID, expectedVersion int64) error {
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
