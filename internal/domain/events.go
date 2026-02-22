package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Event type discriminators matching Rust's serde tag values.
const (
	EventTypeHostCreated        = "HostCreated"
	EventTypeIPAddressChanged   = "IpAddressChanged"
	EventTypeHostnameChanged    = "HostnameChanged"
	EventTypeCommentUpdated     = "CommentUpdated"
	EventTypeTagsModified       = "TagsModified"
	EventTypeAliasesModified    = "AliasesModified"
	EventTypeHostDeleted        = "HostDeleted"
	EventTypeHostImported       = "HostImported"
	EventTypeSnapshotCreated    = "SnapshotCreated"
	EventTypeSnapshotRolledBack = "SnapshotRolledBack"
	EventTypeSnapshotDeleted    = "SnapshotDeleted"
)

// HostEvent is a polymorphic domain event serialized with a "type" discriminator.
// The Payload field holds the type-specific data as raw JSON.
type HostEvent struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"-"`
}

// hostEventJSON is the wire format combining type + payload fields.
type hostEventJSON struct {
	Type string `json:"type"`
}

// MarshalJSON produces {"type":"...", ...payload_fields...}.
func (e HostEvent) MarshalJSON() ([]byte, error) {
	// Start with the payload object
	if len(e.Payload) == 0 {
		return json.Marshal(hostEventJSON{Type: e.Type})
	}

	// Merge type field into the payload object
	var m map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &m); err != nil {
		return nil, fmt.Errorf("event payload is not a JSON object: %w", err)
	}

	typeBytes, err := json.Marshal(e.Type)
	if err != nil {
		return nil, err
	}
	m["type"] = typeBytes

	return json.Marshal(m)
}

// UnmarshalJSON reads {"type":"...", ...fields...} and splits into Type + Payload.
func (e *HostEvent) UnmarshalJSON(data []byte) error {
	var h hostEventJSON
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	e.Type = h.Type
	e.Payload = json.RawMessage(data)
	return nil
}

// Decode returns the typed event payload. The caller should type-switch on the result.
func (e *HostEvent) Decode() (any, error) {
	switch e.Type {
	case EventTypeHostCreated:
		var v HostCreated
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeIPAddressChanged:
		var v IPAddressChanged
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeHostnameChanged:
		var v HostnameChanged
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeCommentUpdated:
		var v CommentUpdated
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeTagsModified:
		var v TagsModified
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeAliasesModified:
		var v AliasesModified
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeHostDeleted:
		var v HostDeleted
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeHostImported:
		var v HostImported
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeSnapshotCreated:
		var v SnapshotCreated
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeSnapshotRolledBack:
		var v SnapshotRolledBack
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case EventTypeSnapshotDeleted:
		var v SnapshotDeleted
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unknown event type: %s", e.Type)
	}
}

// OccurredAt returns the timestamp from the underlying event payload.
func (e *HostEvent) OccurredAt() (time.Time, error) {
	v, err := e.Decode()
	if err != nil {
		return time.Time{}, err
	}
	switch ev := v.(type) {
	case HostCreated:
		return ev.CreatedAt, nil
	case IPAddressChanged:
		return ev.ChangedAt, nil
	case HostnameChanged:
		return ev.ChangedAt, nil
	case CommentUpdated:
		return ev.UpdatedAt, nil
	case TagsModified:
		return ev.ModifiedAt, nil
	case AliasesModified:
		return ev.ModifiedAt, nil
	case HostDeleted:
		return ev.DeletedAt, nil
	case HostImported:
		return ev.OccurredAt, nil
	case SnapshotCreated:
		return ev.OccurredAt, nil
	case SnapshotRolledBack:
		return ev.OccurredAt, nil
	case SnapshotDeleted:
		return ev.OccurredAt, nil
	default:
		return time.Time{}, fmt.Errorf("unknown event type: %T", v)
	}
}

// NewHostEvent creates a HostEvent from a typed event struct.
func NewHostEvent(v any) (HostEvent, error) {
	var eventType string
	switch v.(type) {
	case HostCreated:
		eventType = EventTypeHostCreated
	case IPAddressChanged:
		eventType = EventTypeIPAddressChanged
	case HostnameChanged:
		eventType = EventTypeHostnameChanged
	case CommentUpdated:
		eventType = EventTypeCommentUpdated
	case TagsModified:
		eventType = EventTypeTagsModified
	case AliasesModified:
		eventType = EventTypeAliasesModified
	case HostDeleted:
		eventType = EventTypeHostDeleted
	case HostImported:
		eventType = EventTypeHostImported
	case SnapshotCreated:
		eventType = EventTypeSnapshotCreated
	case SnapshotRolledBack:
		eventType = EventTypeSnapshotRolledBack
	case SnapshotDeleted:
		eventType = EventTypeSnapshotDeleted
	default:
		return HostEvent{}, fmt.Errorf("unsupported event type: %T", v)
	}

	payload, err := json.Marshal(v)
	if err != nil {
		return HostEvent{}, err
	}

	return HostEvent{
		Type:    eventType,
		Payload: payload,
	}, nil
}

// HostCreated is emitted when a new host entry is created.
type HostCreated struct {
	IPAddress string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	Aliases   []string  `json:"aliases"`
	Comment   *string   `json:"comment,omitempty"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

// IPAddressChanged is emitted when a host's IP changes.
type IPAddressChanged struct {
	OldIP     string    `json:"old_ip"`
	NewIP     string    `json:"new_ip"`
	ChangedAt time.Time `json:"changed_at"`
}

// HostnameChanged is emitted when a host's primary hostname changes.
type HostnameChanged struct {
	OldHostname string    `json:"old_hostname"`
	NewHostname string    `json:"new_hostname"`
	ChangedAt   time.Time `json:"changed_at"`
}

// CommentUpdated is emitted when a host's comment is modified.
type CommentUpdated struct {
	OldComment *string   `json:"old_comment,omitempty"`
	NewComment *string   `json:"new_comment,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TagsModified is emitted when a host's tags are changed.
type TagsModified struct {
	OldTags    []string  `json:"old_tags"`
	NewTags    []string  `json:"new_tags"`
	ModifiedAt time.Time `json:"modified_at"`
}

// AliasesModified is emitted when a host's aliases are changed.
type AliasesModified struct {
	OldAliases []string  `json:"old_aliases"`
	NewAliases []string  `json:"new_aliases"`
	ModifiedAt time.Time `json:"modified_at"`
}

// HostDeleted is emitted when a host entry is deleted (tombstone).
type HostDeleted struct {
	IPAddress string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	DeletedAt time.Time `json:"deleted_at"`
	Reason    *string   `json:"reason,omitempty"`
}

// HostImported is emitted when a host entry is imported from an external source.
type HostImported struct {
	IPAddress  string    `json:"ip_address"`
	Hostname   string    `json:"hostname"`
	Comment    *string   `json:"comment,omitempty"`
	Tags       []string  `json:"tags"`
	Aliases    []string  `json:"aliases"`
	OccurredAt time.Time `json:"occurred_at"`
}

// SnapshotCreated is emitted when a new snapshot is created.
type SnapshotCreated struct {
	SnapshotID string    `json:"snapshot_id"`
	Name       string    `json:"name"`
	Trigger    string    `json:"trigger"`
	EntryCount int32     `json:"entry_count"`
	OccurredAt time.Time `json:"occurred_at"`
}

// SnapshotRolledBack is emitted when a snapshot is rolled back.
type SnapshotRolledBack struct {
	SnapshotID      string    `json:"snapshot_id"`
	RestoredEntries int32     `json:"restored_entries"`
	OccurredAt      time.Time `json:"occurred_at"`
}

// SnapshotDeleted is emitted when a snapshot is deleted.
type SnapshotDeleted struct {
	SnapshotID string    `json:"snapshot_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

// EventEnvelope wraps a domain event with metadata for persistence.
type EventEnvelope struct {
	EventID     ulid.ULID `json:"event_id"`
	AggregateID ulid.ULID `json:"aggregate_id"`
	Event       HostEvent `json:"event"`
	Version     string    `json:"event_version"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   *string   `json:"created_by,omitempty"`
}

// OccurredAt returns the envelope's CreatedAt timestamp.
// This aliases CreatedAt to satisfy the spec's OccurredAt naming convention.
func (e *EventEnvelope) OccurredAt() time.Time {
	return e.CreatedAt
}
