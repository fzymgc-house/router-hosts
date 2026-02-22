package sqlite

import (
	"context"
	"encoding/json"
	"fmt"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// SaveSnapshot persists a snapshot, marshaling entries to JSON.
func (s *Storage) SaveSnapshot(ctx context.Context, snapshot domain.Snapshot) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	hostsContent := snapshot.HostsContent
	if snapshot.Entries != nil {
		data, marshalErr := json.Marshal(snapshot.Entries)
		if marshalErr != nil {
			return fmt.Errorf("marshal entries: %w", marshalErr)
		}
		hostsContent = string(data)
	}

	return sqlitex.Execute(conn,
		`INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger_type, name, event_log_position)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		&sqlitex.ExecOptions{
			Args: []any{
				snapshot.SnapshotID,
				snapshot.CreatedAt.UTC().Format(timeFormat),
				hostsContent,
				snapshot.EntryCount,
				snapshot.Trigger,
				ptrToAny(snapshot.Name),
				int64PtrToAny(snapshot.EventLogPosition),
			},
		})
}

// GetSnapshot retrieves a snapshot by ID, unmarshaling entries from JSON.
func (s *Storage) GetSnapshot(ctx context.Context, snapshotID string) (*domain.Snapshot, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return nil, fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	var snap *domain.Snapshot
	err = sqlitex.Execute(conn,
		`SELECT snapshot_id, created_at, hosts_content, entry_count, trigger_type, name, event_log_position
		 FROM snapshots WHERE snapshot_id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{snapshotID},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				var scanErr error
				snap, scanErr = scanSnapshot(stmt)
				return scanErr
			},
		})
	if err != nil {
		return nil, fmt.Errorf("get snapshot: %w", err)
	}
	if snap == nil {
		return nil, domain.ErrNotFound("snapshot", snapshotID)
	}
	return snap, nil
}

// ListSnapshots returns snapshot metadata ordered by creation time (newest first).
func (s *Storage) ListSnapshots(ctx context.Context, limit, offset *uint32) ([]domain.SnapshotMetadata, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return nil, fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

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
	err = sqlitex.Execute(conn, query, &sqlitex.ExecOptions{
		Args: args,
		ResultFunc: func(stmt *sqlite.Stmt) error {
			createdAt, parseErr := parseTime(stmt.ColumnText(1))
			if parseErr != nil {
				return parseErr
			}
			metas = append(metas, domain.SnapshotMetadata{
				SnapshotID: stmt.ColumnText(0),
				CreatedAt:  createdAt,
				EntryCount: int32(stmt.ColumnInt(2)),
				Trigger:    stmt.ColumnText(3),
				Name:       columnTextPtr(stmt, 4),
			})
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	return metas, nil
}

// DeleteSnapshot removes a snapshot by ID.
func (s *Storage) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	err = sqlitex.Execute(conn,
		`DELETE FROM snapshots WHERE snapshot_id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{snapshotID},
		})
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}

	if conn.Changes() == 0 {
		return domain.ErrNotFound("snapshot", snapshotID)
	}
	return nil
}

// ApplyRetentionPolicy deletes snapshots exceeding count or age limits.
// Returns the total number of snapshots deleted.
func (s *Storage) ApplyRetentionPolicy(ctx context.Context, maxCount *int, maxAgeDays *int) (int, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return 0, fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer endFn(&err)

	var totalDeleted int

	if maxCount != nil {
		err = sqlitex.Execute(conn,
			`DELETE FROM snapshots WHERE snapshot_id NOT IN (
				SELECT snapshot_id FROM snapshots ORDER BY created_at DESC LIMIT ?
			)`,
			&sqlitex.ExecOptions{
				Args: []any{*maxCount},
			})
		if err != nil {
			return 0, fmt.Errorf("apply count retention: %w", err)
		}
		totalDeleted += conn.Changes()
	}

	if maxAgeDays != nil {
		err = sqlitex.Execute(conn,
			`DELETE FROM snapshots WHERE created_at < datetime('now', ? || ' days')`,
			&sqlitex.ExecOptions{
				Args: []any{fmt.Sprintf("-%d", *maxAgeDays)},
			})
		if err != nil {
			return 0, fmt.Errorf("apply age retention: %w", err)
		}
		totalDeleted += conn.Changes()
	}

	return totalDeleted, nil
}

// scanSnapshot reads a full Snapshot from a query result row.
func scanSnapshot(stmt *sqlite.Stmt) (*domain.Snapshot, error) {
	createdAt, err := parseTime(stmt.ColumnText(1))
	if err != nil {
		return nil, err
	}

	hostsContent := stmt.ColumnText(2)
	var entries []domain.HostEntry
	if hostsContent != "" {
		if unmarshalErr := json.Unmarshal([]byte(hostsContent), &entries); unmarshalErr != nil {
			// Not JSON array — keep as raw string, no entries
			entries = nil
		}
	}

	snap := &domain.Snapshot{
		SnapshotID:       stmt.ColumnText(0),
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
