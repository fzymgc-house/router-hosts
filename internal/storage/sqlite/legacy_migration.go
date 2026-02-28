package sqlite

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/samber/oops"
)

const legacyMigrationVersion = 3

// rustEventMetadata matches the Rust EventData struct stored in the metadata column.
type rustEventMetadata struct {
	Comment          *string  `json:"comment,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Aliases          []string `json:"aliases,omitempty"`
	PreviousIP       *string  `json:"previous_ip,omitempty"`
	PreviousHostname *string  `json:"previous_hostname,omitempty"`
	PreviousComment  *string  `json:"previous_comment,omitempty"`
	PreviousTags     []string `json:"previous_tags,omitempty"`
	PreviousAliases  []string `json:"previous_aliases,omitempty"`
	DeletedReason    *string  `json:"deleted_reason,omitempty"`
}

// migrateLegacyRustData migrates data from the Rust-era host_events table
// to the Go events table, and rebuilds the snapshots table with the correct
// schema. This is a no-op when the legacy table does not exist.
func migrateLegacyRustData(conn *sqlite.Conn, log *slog.Logger) error {
	if !tableExists(conn, "host_events") {
		return nil
	}

	// Guard: if events table already has data, skip.
	var eventCount int64
	if err := sqlitex.Execute(conn, `SELECT COUNT(*) FROM events`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			eventCount = stmt.ColumnInt64(0)
			return nil
		},
	}); err != nil {
		return oops.Wrapf(err, "count existing events")
	}
	if eventCount > 0 {
		log.Info("events table already populated, skipping legacy migration")
		return nil
	}

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return oops.Wrapf(err, "begin legacy migration transaction")
	}
	defer endFn(&err)

	migrated, err := migrateHostEvents(conn, log)
	if err != nil {
		return oops.Wrapf(err, "migrate host_events")
	}

	snapshotCount, err := migrateSnapshots(conn, log)
	if err != nil {
		return oops.Wrapf(err, "migrate snapshots")
	}

	if err := dropLegacyObjects(conn); err != nil {
		return oops.Wrapf(err, "drop legacy objects")
	}

	log.Info("legacy Rust data migration complete",
		"events_migrated", migrated,
		"snapshots_migrated", snapshotCount)

	return nil
}

// tableExists checks whether a table exists in the database.
func tableExists(conn *sqlite.Conn, name string) bool {
	var exists bool
	_ = sqlitex.Execute(conn,
		`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`,
		&sqlitex.ExecOptions{
			Args: []any{name},
			ResultFunc: func(*sqlite.Stmt) error {
				exists = true
				return nil
			},
		})
	return exists
}

// rawLegacyEvent holds one row from the Rust host_events table.
type rawLegacyEvent struct {
	eventID        string
	aggregateID    string
	eventType      string
	ipAddress      *string
	hostname       *string
	comment        *string
	tags           *string // JSON array
	aliases        *string // JSON array
	eventTimestamp int64   // epoch micros
	metadata       string  // JSON
	createdAt      int64   // epoch micros
	createdBy      *string
}

// migrateHostEvents reads all rows from host_events and inserts them into events.
func migrateHostEvents(conn *sqlite.Conn, log *slog.Logger) (int, error) {
	var events []rawLegacyEvent
	err := sqlitex.Execute(conn,
		`SELECT event_id, aggregate_id, event_type,
		        ip_address, hostname, comment, tags, aliases,
		        event_timestamp, metadata, created_at, created_by
		 FROM host_events ORDER BY aggregate_id, rowid`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				e := rawLegacyEvent{
					eventID:        stmt.ColumnText(0),
					aggregateID:    stmt.ColumnText(1),
					eventType:      stmt.ColumnText(2),
					eventTimestamp: stmt.ColumnInt64(8),
					metadata:       stmt.ColumnText(9),
					createdAt:      stmt.ColumnInt64(10),
				}
				if stmt.ColumnType(3) != sqlite.TypeNull {
					v := stmt.ColumnText(3)
					e.ipAddress = &v
				}
				if stmt.ColumnType(4) != sqlite.TypeNull {
					v := stmt.ColumnText(4)
					e.hostname = &v
				}
				if stmt.ColumnType(5) != sqlite.TypeNull {
					v := stmt.ColumnText(5)
					e.comment = &v
				}
				if stmt.ColumnType(6) != sqlite.TypeNull {
					v := stmt.ColumnText(6)
					e.tags = &v
				}
				if stmt.ColumnType(7) != sqlite.TypeNull {
					v := stmt.ColumnText(7)
					e.aliases = &v
				}
				if stmt.ColumnType(11) != sqlite.TypeNull {
					v := stmt.ColumnText(11)
					e.createdBy = &v
				}
				events = append(events, e)
				return nil
			},
		})
	if err != nil {
		return 0, oops.Wrapf(err, "read host_events")
	}

	versionCounters := make(map[string]int64)

	for _, e := range events {
		version := versionCounters[e.aggregateID] + 1
		versionCounters[e.aggregateID] = version

		var meta rustEventMetadata
		if e.metadata != "" {
			if unmarshalErr := json.Unmarshal([]byte(e.metadata), &meta); unmarshalErr != nil {
				log.Warn("failed to parse event metadata, using defaults",
					"event_id", e.eventID, "err", unmarshalErr)
			}
		}

		eventData, buildErr := buildGoEventData(e, &meta)
		if buildErr != nil {
			return 0, oops.Wrapf(buildErr, "build event data for %s", e.eventID)
		}

		createdAtStr := microsToTimeStr(e.createdAt)

		if insertErr := sqlitex.Execute(conn,
			`INSERT INTO events (event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			&sqlitex.ExecOptions{
				Args: []any{
					e.eventID,
					e.aggregateID,
					e.eventType,
					eventData,
					version,
					createdAtStr,
					ptrToAny(e.createdBy),
				},
			}); insertErr != nil {
			return 0, oops.Wrapf(insertErr, "insert event %s", e.eventID)
		}
	}

	return len(events), nil
}

// buildGoEventData constructs the Go-format event_data JSON blob from
// Rust-era column data and metadata.
func buildGoEventData(e rawLegacyEvent, meta *rustEventMetadata) (string, error) {
	ts := microsToTime(e.eventTimestamp)

	var event any
	switch e.eventType {
	case "HostCreated":
		event = hostCreatedJSON{
			Type:      "HostCreated",
			IPAddress: derefStr(e.ipAddress),
			Hostname:  derefStr(e.hostname),
			Aliases:   parseJSONStringArray(e.aliases),
			Comment:   e.comment,
			Tags:      parseJSONStringArray(e.tags),
			CreatedAt: ts,
		}
	case "IpAddressChanged":
		event = ipChangedJSON{
			Type:      "IpAddressChanged",
			OldIP:     derefStr(meta.PreviousIP),
			NewIP:     derefStr(e.ipAddress),
			ChangedAt: ts,
		}
	case "HostnameChanged":
		event = hostnameChangedJSON{
			Type:        "HostnameChanged",
			OldHostname: derefStr(meta.PreviousHostname),
			NewHostname: derefStr(e.hostname),
			ChangedAt:   ts,
		}
	case "CommentUpdated":
		event = commentUpdatedJSON{
			Type:       "CommentUpdated",
			OldComment: meta.PreviousComment,
			NewComment: e.comment,
			UpdatedAt:  ts,
		}
	case "TagsModified":
		event = tagsModifiedJSON{
			Type:       "TagsModified",
			OldTags:    coalesceSlice(meta.PreviousTags, nil),
			NewTags:    coalesceSlice(meta.Tags, parseJSONStringArray(e.tags)),
			ModifiedAt: ts,
		}
	case "AliasesModified":
		event = aliasesModifiedJSON{
			Type:       "AliasesModified",
			OldAliases: coalesceSlice(meta.PreviousAliases, nil),
			NewAliases: coalesceSlice(meta.Aliases, parseJSONStringArray(e.aliases)),
			ModifiedAt: ts,
		}
	case "HostDeleted":
		event = hostDeletedJSON{
			Type:      "HostDeleted",
			IPAddress: derefStr(e.ipAddress),
			Hostname:  derefStr(e.hostname),
			DeletedAt: ts,
			Reason:    meta.DeletedReason,
		}
	default:
		return "", fmt.Errorf("unknown legacy event type: %s", e.eventType)
	}

	data, err := json.Marshal(event)
	if err != nil {
		return "", oops.Wrapf(err, "marshal event data")
	}
	return string(data), nil
}

// migrateSnapshots rebuilds the snapshots table with the Go schema.
// The Rust table has column "trigger" (TEXT) and created_at as INTEGER (epoch
// micros), while Go expects "trigger_type" (TEXT) and created_at as TEXT (RFC3339).
func migrateSnapshots(conn *sqlite.Conn, log *slog.Logger) (int, error) {
	if !columnExists(conn, "snapshots", "trigger") {
		log.Info("snapshots table already has Go schema, skipping snapshot migration")
		return 0, nil
	}

	// Read legacy snapshots.
	type legacySnapshot struct {
		snapshotID       string
		createdAt        int64 // epoch micros
		hostsContent     string
		entryCount       int64
		trigger          string
		name             *string
		eventLogPosition *int64
		entriesJSON      *string
	}

	var snapshots []legacySnapshot
	err := sqlitex.Execute(conn,
		`SELECT snapshot_id, created_at, hosts_content, entry_count, trigger, name, event_log_position, entries_json
		 FROM snapshots ORDER BY rowid`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				s := legacySnapshot{
					snapshotID:   stmt.ColumnText(0),
					createdAt:    stmt.ColumnInt64(1),
					hostsContent: stmt.ColumnText(2),
					entryCount:   stmt.ColumnInt64(3),
					trigger:      stmt.ColumnText(4),
				}
				if stmt.ColumnType(5) != sqlite.TypeNull {
					v := stmt.ColumnText(5)
					s.name = &v
				}
				if stmt.ColumnType(6) != sqlite.TypeNull {
					v := stmt.ColumnInt64(6)
					s.eventLogPosition = &v
				}
				if stmt.ColumnType(7) != sqlite.TypeNull {
					v := stmt.ColumnText(7)
					s.entriesJSON = &v
				}
				snapshots = append(snapshots, s)
				return nil
			},
		})
	if err != nil {
		return 0, oops.Wrapf(err, "read legacy snapshots")
	}

	// Drop old table and index, create new with Go schema.
	ddl := `
		DROP INDEX IF EXISTS idx_snapshots_created;
		DROP TABLE snapshots;
		CREATE TABLE snapshots (
			snapshot_id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			hosts_content TEXT NOT NULL,
			entry_count INTEGER NOT NULL,
			trigger_type TEXT NOT NULL,
			name TEXT,
			event_log_position INTEGER,
			entries_json TEXT
		);
		CREATE INDEX idx_snapshots_created_at ON snapshots(created_at);
	`
	if err := sqlitex.ExecuteScript(conn, ddl, nil); err != nil {
		return 0, oops.Wrapf(err, "recreate snapshots table")
	}

	for _, s := range snapshots {
		createdAtStr := microsToTimeStr(s.createdAt)

		if insertErr := sqlitex.Execute(conn,
			`INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger_type, name, event_log_position, entries_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			&sqlitex.ExecOptions{
				Args: []any{
					s.snapshotID,
					createdAtStr,
					s.hostsContent,
					s.entryCount,
					s.trigger,
					ptrToAny(s.name),
					ptrToInt64Any(s.eventLogPosition),
					ptrToAny(s.entriesJSON),
				},
			}); insertErr != nil {
			return 0, oops.Wrapf(insertErr, "insert snapshot %s", s.snapshotID)
		}
	}

	return len(snapshots), nil
}

// dropLegacyObjects removes Rust-era tables, views, and migration tracking.
func dropLegacyObjects(conn *sqlite.Conn) error {
	ddl := `
		DROP VIEW IF EXISTS host_entries_current;
		DROP VIEW IF EXISTS host_entries_history;
		DROP TABLE IF EXISTS host_events;
		DROP TABLE IF EXISTS _sqlx_migrations;
	`
	return sqlitex.ExecuteScript(conn, ddl, nil)
}

// columnExists checks whether a column exists in a table.
func columnExists(conn *sqlite.Conn, table, column string) bool {
	var exists bool
	_ = sqlitex.Execute(conn,
		fmt.Sprintf(`SELECT 1 FROM pragma_table_info('%s') WHERE name=?`, table),
		&sqlitex.ExecOptions{
			Args: []any{column},
			ResultFunc: func(*sqlite.Stmt) error {
				exists = true
				return nil
			},
		})
	return exists
}

func microsToTime(micros int64) time.Time {
	return time.UnixMicro(micros).UTC()
}

func microsToTimeStr(micros int64) string {
	return microsToTime(micros).Format(timeFormat)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func parseJSONStringArray(s *string) []string {
	if s == nil {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(*s), &arr); err != nil {
		return nil
	}
	return arr
}

func coalesceSlice(a, b []string) []string {
	if a != nil {
		return a
	}
	return b
}

func ptrToInt64Any(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// JSON structs for building Go-format event_data payloads.
// These mirror the domain event types but are local to the migration
// to avoid coupling migration code to domain struct evolution.

type hostCreatedJSON struct {
	Type      string    `json:"type"`
	IPAddress string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	Aliases   []string  `json:"aliases"`
	Comment   *string   `json:"comment,omitempty"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

type ipChangedJSON struct {
	Type      string    `json:"type"`
	OldIP     string    `json:"old_ip"`
	NewIP     string    `json:"new_ip"`
	ChangedAt time.Time `json:"changed_at"`
}

type hostnameChangedJSON struct {
	Type        string    `json:"type"`
	OldHostname string    `json:"old_hostname"`
	NewHostname string    `json:"new_hostname"`
	ChangedAt   time.Time `json:"changed_at"`
}

type commentUpdatedJSON struct {
	Type       string    `json:"type"`
	OldComment *string   `json:"old_comment,omitempty"`
	NewComment *string   `json:"new_comment,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type tagsModifiedJSON struct {
	Type       string    `json:"type"`
	OldTags    []string  `json:"old_tags"`
	NewTags    []string  `json:"new_tags"`
	ModifiedAt time.Time `json:"modified_at"`
}

type aliasesModifiedJSON struct {
	Type       string    `json:"type"`
	OldAliases []string  `json:"old_aliases"`
	NewAliases []string  `json:"new_aliases"`
	ModifiedAt time.Time `json:"modified_at"`
}

type hostDeletedJSON struct {
	Type      string    `json:"type"`
	IPAddress string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	DeletedAt time.Time `json:"deleted_at"`
	Reason    *string   `json:"reason,omitempty"`
}
