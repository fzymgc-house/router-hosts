package domain

import "time"

// Snapshot represents a point-in-time capture of the hosts file content.
type Snapshot struct {
	SnapshotID       string    `json:"snapshot_id"`
	CreatedAt        time.Time `json:"created_at"`
	HostsContent     string    `json:"hosts_content"`
	EntryCount       int32     `json:"entry_count"`
	Trigger          string    `json:"trigger"`
	Name             *string   `json:"name,omitempty"`
	EventLogPosition *int64    `json:"event_log_position,omitempty"`
}

// SnapshotMetadata is a Snapshot without the hosts file content, used for listings.
type SnapshotMetadata struct {
	SnapshotID string    `json:"snapshot_id"`
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
