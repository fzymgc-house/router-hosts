package sqlite

import (
	"context"
	"encoding/json"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// SaveSnapshot persists a snapshot, storing formatted hosts text in
// hosts_content and JSON-encoded entries in entries_json separately.
func (s *Storage) SaveSnapshot(ctx context.Context, snapshot domain.Snapshot) error {
	var entriesJSON any
	if snapshot.Entries != nil {
		data, marshalErr := json.Marshal(snapshot.Entries)
		if marshalErr != nil {
			return oops.Wrapf(marshalErr, "marshal entries")
		}
		entriesJSON = string(data)
	}

	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn,
			`INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger_type, name, event_log_position, entries_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			&sqlitex.ExecOptions{
				Args: []any{
					snapshot.SnapshotID.String(),
					snapshot.CreatedAt.UTC().Format(timeFormat),
					snapshot.HostsContent,
					snapshot.EntryCount,
					snapshot.Trigger,
					ptrToAny(snapshot.Name),
					int64PtrToAny(snapshot.EventLogPosition),
					entriesJSON,
				},
			})
	})
	if err != nil {
		return oops.Wrapf(err, "save snapshot %s", snapshot.SnapshotID)
	}
	return nil
}

// GetSnapshot retrieves a snapshot by ID, unmarshaling entries from JSON.
func (s *Storage) GetSnapshot(ctx context.Context, snapshotID ulid.ULID) (*domain.Snapshot, error) {
	var snap *domain.Snapshot
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn,
			`SELECT snapshot_id, created_at, hosts_content, entry_count, trigger_type, name, event_log_position, entries_json
			 FROM snapshots WHERE snapshot_id = ?`,
			&sqlitex.ExecOptions{
				Args: []any{snapshotID.String()},
				ResultFunc: func(stmt *sqlite.Stmt) error {
					var scanErr error
					snap, scanErr = scanSnapshot(stmt)
					return scanErr
				},
			})
	})
	if err != nil {
		return nil, oops.Wrapf(err, "get snapshot")
	}
	if snap == nil {
		return nil, domain.ErrNotFound("snapshot", snapshotID.String())
	}
	return snap, nil
}

// ListSnapshots returns snapshot metadata ordered by creation time (newest first).
func (s *Storage) ListSnapshots(ctx context.Context, limit, offset *uint32) ([]domain.SnapshotMetadata, error) {
	query := `SELECT snapshot_id, created_at, entry_count, trigger_type, name
			  FROM snapshots ORDER BY created_at DESC`

	var args []any
	if limit != nil {
		query += " LIMIT ?"
		args = append(args, *limit)
	}
	if offset != nil {
		if limit == nil {
			query += " LIMIT -1"
		}
		query += " OFFSET ?"
		args = append(args, *offset)
	}

	var metas []domain.SnapshotMetadata
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn, query, &sqlitex.ExecOptions{
			Args: args,
			ResultFunc: func(stmt *sqlite.Stmt) error {
				sid, parseErr := ulid.Parse(stmt.ColumnText(0))
				if parseErr != nil {
					return oops.Wrapf(parseErr, "parse snapshot_id %q", stmt.ColumnText(0))
				}
				createdAt, parseErr := parseTime(stmt.ColumnText(1))
				if parseErr != nil {
					return oops.Wrapf(parseErr, "parse created_at for snapshot %q", stmt.ColumnText(0))
				}
				metas = append(metas, domain.SnapshotMetadata{
					SnapshotID: sid,
					CreatedAt:  createdAt,
					EntryCount: int32(stmt.ColumnInt(2)),
					Trigger:    stmt.ColumnText(3),
					Name:       columnTextPtr(stmt, 4),
				})
				return nil
			},
		})
	})
	if err != nil {
		return nil, oops.Wrapf(err, "list snapshots")
	}
	return metas, nil
}

// DeleteSnapshot removes a snapshot by ID.
func (s *Storage) DeleteSnapshot(ctx context.Context, snapshotID ulid.ULID) error {
	return s.withConn(ctx, func(conn *sqlite.Conn) error {
		err := sqlitex.Execute(conn,
			`DELETE FROM snapshots WHERE snapshot_id = ?`,
			&sqlitex.ExecOptions{
				Args: []any{snapshotID.String()},
			})
		if err != nil {
			return oops.Wrapf(err, "delete snapshot")
		}
		if conn.Changes() == 0 {
			return domain.ErrNotFound("snapshot", snapshotID.String())
		}
		return nil
	})
}

// ApplyRetentionPolicy deletes snapshots exceeding count or age limits.
// Returns the total number of snapshots deleted.
func (s *Storage) ApplyRetentionPolicy(ctx context.Context, maxCount *int, maxAgeDays *int) (int, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return 0, oops.Wrapf(err, "take connection")
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return 0, oops.Wrapf(err, "begin transaction")
	}
	defer endFn(&err)

	var totalDeleted int

	if maxCount != nil {
		if *maxCount <= 0 {
			return 0, oops.Errorf("maxCount must be a positive integer, got %d", *maxCount)
		}
		err = sqlitex.Execute(conn,
			`DELETE FROM snapshots WHERE snapshot_id NOT IN (
				SELECT snapshot_id FROM snapshots ORDER BY created_at DESC LIMIT ?
			)`,
			&sqlitex.ExecOptions{
				Args: []any{*maxCount},
			})
		if err != nil {
			return 0, oops.Wrapf(err, "apply count retention")
		}
		totalDeleted += conn.Changes()
	}

	if maxAgeDays != nil {
		if *maxAgeDays <= 0 {
			return 0, oops.Errorf("maxAgeDays must be a positive integer, got %d", *maxAgeDays)
		}
		err = sqlitex.Execute(conn,
			`DELETE FROM snapshots WHERE created_at < datetime('now', '-' || CAST(? AS TEXT) || ' days')`,
			&sqlitex.ExecOptions{
				Args: []any{*maxAgeDays},
			})
		if err != nil {
			return 0, oops.Wrapf(err, "apply age retention")
		}
		totalDeleted += conn.Changes()
	}

	return totalDeleted, nil
}

// scanSnapshot reads a full Snapshot from a query result row.
// Columns: 0=snapshot_id, 1=created_at, 2=hosts_content, 3=entry_count,
//
//	4=trigger_type, 5=name, 6=event_log_position, 7=entries_json
//
// entries_json (col 7) is the canonical source for structured entries.
// For backward compatibility with rows written before the migration, if
// entries_json is NULL and hosts_content starts with '[', entries are
// parsed from hosts_content instead.
func scanSnapshot(stmt *sqlite.Stmt) (*domain.Snapshot, error) {
	snapshotID, err := ulid.Parse(stmt.ColumnText(0))
	if err != nil {
		return nil, oops.Wrapf(err, "parse snapshot_id %q", stmt.ColumnText(0))
	}

	createdAt, err := parseTime(stmt.ColumnText(1))
	if err != nil {
		return nil, oops.Wrapf(err, "parse created_at for snapshot %s", stmt.ColumnText(0))
	}

	hostsContent := stmt.ColumnText(2)

	var entries []domain.HostEntry
	if stmt.ColumnType(7) != sqlite.TypeNull {
		// New rows: entries_json holds the structured data.
		entriesJSON := stmt.ColumnText(7)
		if entriesJSON != "" {
			if unmarshalErr := json.Unmarshal([]byte(entriesJSON), &entries); unmarshalErr != nil {
				return nil, oops.Wrapf(unmarshalErr, "unmarshal snapshot entries_json")
			}
		}
	} else if hostsContent != "" && hostsContent[0] == '[' {
		// Legacy rows written before the migration: entries were stored in hosts_content.
		if unmarshalErr := json.Unmarshal([]byte(hostsContent), &entries); unmarshalErr != nil {
			return nil, oops.Wrapf(unmarshalErr, "unmarshal snapshot entries from hosts_content")
		}
		// hosts_content for legacy rows is JSON, not a formatted hosts file.
		hostsContent = ""
	}

	snap := &domain.Snapshot{
		SnapshotID:       snapshotID,
		CreatedAt:        createdAt,
		HostsContent:     hostsContent,
		Entries:          entries,
		EntryCount:       int32(stmt.ColumnInt(3)),
		Trigger:          stmt.ColumnText(4),
		Name:             columnTextPtr(stmt, 5),
		EventLogPosition: columnInt64Ptr(stmt, 6),
	}
	return snap, nil
}

// int64PtrToAny converts a *int64 to an any suitable for SQL parameters.
func int64PtrToAny(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// columnInt64Ptr reads a nullable INTEGER column as *int64.
func columnInt64Ptr(stmt *sqlite.Stmt, col int) *int64 {
	if stmt.ColumnType(col) == sqlite.TypeNull {
		return nil
	}
	v := stmt.ColumnInt64(col)
	return &v
}
