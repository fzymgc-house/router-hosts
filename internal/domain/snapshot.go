package domain

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// Snapshot represents a point-in-time capture of the hosts file content.
type Snapshot struct {
	SnapshotID       ulid.ULID   `json:"snapshot_id"`
	CreatedAt        time.Time   `json:"created_at"`
	HostsContent     string      `json:"hosts_content"`
	Entries          []HostEntry `json:"entries,omitempty"`
	EntryCount       int32       `json:"entry_count"`
	Trigger          string      `json:"trigger"`
	Name             *string     `json:"name,omitempty"`
	EventLogPosition *int64      `json:"event_log_position,omitempty"`
}

// NewSnapshot constructs a Snapshot with computed fields.
// EntryCount is set to len(entries) and CreatedAt is set to time.Now().UTC().
func NewSnapshot(id ulid.ULID, hostsContent, trigger string, name *string, entries []HostEntry) *Snapshot {
	return &Snapshot{
		SnapshotID:   id,
		CreatedAt:    time.Now().UTC(),
		HostsContent: hostsContent,
		Entries:      entries,
		EntryCount:   int32(len(entries)),
		Trigger:      trigger,
		Name:         name,
	}
}

// SnapshotMetadata is a Snapshot without the hosts file content, used for listings.
type SnapshotMetadata struct {
	SnapshotID ulid.ULID `json:"snapshot_id"`
	CreatedAt  time.Time `json:"created_at"`
	EntryCount int32     `json:"entry_count"`
	Trigger    string    `json:"trigger"`
	Name       *string   `json:"name,omitempty"`
}

// Metadata returns a SnapshotMetadata projection of this Snapshot.
func (s *Snapshot) Metadata() SnapshotMetadata {
	return SnapshotMetadata{
		SnapshotID: s.SnapshotID,
		CreatedAt:  s.CreatedAt,
		EntryCount: s.EntryCount,
		Trigger:    s.Trigger,
		Name:       s.Name,
	}
}
