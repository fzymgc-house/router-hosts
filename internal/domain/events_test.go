package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr(s string) *string { return &s }

func TestNewHostEvent_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	comment := "web server"

	original := HostCreated{
		IPAddress: "192.168.1.10",
		Hostname:  "server.local",
		Aliases:   []string{"srv", "web"},
		Comment:   &comment,
		Tags:      []string{"prod", "web"},
		CreatedAt: now,
	}

	evt, err := NewHostEvent(original)
	require.NoError(t, err)
	assert.Equal(t, EventTypeHostCreated, evt.Type)

	decoded, err := evt.Decode()
	require.NoError(t, err)

	got, ok := decoded.(HostCreated)
	require.True(t, ok)
	assert.Equal(t, original.IPAddress, got.IPAddress)
	assert.Equal(t, original.Hostname, got.Hostname)
	assert.Equal(t, original.Aliases, got.Aliases)
	assert.Equal(t, *original.Comment, *got.Comment)
	assert.Equal(t, original.Tags, got.Tags)
	assert.True(t, original.CreatedAt.Equal(got.CreatedAt))
}

func TestNewHostEvent_AllTypes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	tests := []struct {
		name     string
		event    any
		wantType EventType
	}{
		{
			name: "HostCreated",
			event: HostCreated{
				IPAddress: "10.0.0.1",
				Hostname:  "host.local",
				Aliases:   []string{},
				Tags:      []string{},
				CreatedAt: now,
			},
			wantType: EventTypeHostCreated,
		},
		{
			name: "IPAddressChanged",
			event: IPAddressChanged{
				OldIP:     "10.0.0.1",
				NewIP:     "10.0.0.2",
				ChangedAt: now,
			},
			wantType: EventTypeIPAddressChanged,
		},
		{
			name: "HostnameChanged",
			event: HostnameChanged{
				OldHostname: "old.local",
				NewHostname: "new.local",
				ChangedAt:   now,
			},
			wantType: EventTypeHostnameChanged,
		},
		{
			name: "CommentUpdated",
			event: CommentUpdated{
				OldComment: nil,
				NewComment: ptr("updated"),
				UpdatedAt:  now,
			},
			wantType: EventTypeCommentUpdated,
		},
		{
			name: "TagsModified",
			event: TagsModified{
				OldTags:    []string{},
				NewTags:    []string{"prod"},
				ModifiedAt: now,
			},
			wantType: EventTypeTagsModified,
		},
		{
			name: "AliasesModified",
			event: AliasesModified{
				OldAliases: []string{"a"},
				NewAliases: []string{"a", "b"},
				ModifiedAt: now,
			},
			wantType: EventTypeAliasesModified,
		},
		{
			name: "HostDeleted",
			event: HostDeleted{
				IPAddress: "10.0.0.1",
				Hostname:  "host.local",
				DeletedAt: now,
				Reason:    ptr("decommissioned"),
			},
			wantType: EventTypeHostDeleted,
		},
		{
			name: "HostImported",
			event: HostImported{
				IPAddress:  "10.0.0.5",
				Hostname:   "imported.local",
				Comment:    ptr("from file"),
				Tags:       []string{"imported"},
				Aliases:    []string{"imp"},
				OccurredAt: now,
			},
			wantType: EventTypeHostImported,
		},
		{
			name: "SnapshotCreated",
			event: SnapshotCreated{
				SnapshotID: ulid.Make(),
				Name:       "pre-deploy",
				Trigger:    "manual",
				EntryCount: 42,
				OccurredAt: now,
			},
			wantType: EventTypeSnapshotCreated,
		},
		{
			name: "SnapshotRolledBack",
			event: SnapshotRolledBack{
				SnapshotID:      ulid.Make(),
				RestoredEntries: 42,
				OccurredAt:      now,
			},
			wantType: EventTypeSnapshotRolledBack,
		},
		{
			name: "SnapshotDeleted",
			event: SnapshotDeleted{
				SnapshotID: ulid.Make(),
				OccurredAt: now,
			},
			wantType: EventTypeSnapshotDeleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, err := NewHostEvent(tt.event)
			require.NoError(t, err)
			assert.Equal(t, tt.wantType, evt.Type)

			data, err := json.Marshal(evt)
			require.NoError(t, err)

			var m map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &m))
			assert.Contains(t, m, "type", "JSON should contain type discriminator")
		})
	}
}

func TestNewHostEvent_ValidationErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	tests := []struct {
		name        string
		event       any
		wantErrCode string
	}{
		{
			name: "HostCreated_invalid_ip",
			event: HostCreated{
				IPAddress: "not-an-ip",
				Hostname:  "host.local",
				Aliases:   []string{},
				Tags:      []string{},
				CreatedAt: now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "HostCreated_invalid_hostname",
			event: HostCreated{
				IPAddress: "10.0.0.1",
				Hostname:  "-bad-hostname",
				Aliases:   []string{},
				Tags:      []string{},
				CreatedAt: now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "IPAddressChanged_invalid_new_ip",
			event: IPAddressChanged{
				OldIP:     "10.0.0.1",
				NewIP:     "not-an-ip",
				ChangedAt: now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "HostnameChanged_invalid_new_hostname",
			event: HostnameChanged{
				OldHostname: "old.local",
				NewHostname: "-bad",
				ChangedAt:   now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "AliasesModified_ip_address_as_alias",
			event: AliasesModified{
				OldAliases: []string{},
				NewAliases: []string{"192.168.1.1"},
				ModifiedAt: now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "AliasesModified_invalid_alias_hostname",
			event: AliasesModified{
				OldAliases: []string{},
				NewAliases: []string{"-bad-alias"},
				ModifiedAt: now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "AliasesModified_duplicate_alias",
			event: AliasesModified{
				OldAliases: []string{},
				NewAliases: []string{"alias.local", "alias.local"},
				ModifiedAt: now,
			},
			wantErrCode: CodeValidation,
		},
		{
			name: "AliasesModified_ipv6_as_alias",
			event: AliasesModified{
				OldAliases: []string{},
				NewAliases: []string{"::1"},
				ModifiedAt: now,
			},
			wantErrCode: CodeValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHostEvent(tt.event)
			require.Error(t, err)

			oopsErr, ok := oops.AsOops(err)
			require.True(t, ok, "expected oops error")
			code, _ := oopsErr.Code().(string)
			require.Equal(t, tt.wantErrCode, code)
		})
	}
}

func TestHostEvent_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	comment := "test host"

	original := HostCreated{
		IPAddress: "192.168.1.100",
		Hostname:  "roundtrip.local",
		Aliases:   []string{"rt"},
		Comment:   &comment,
		Tags:      []string{"test"},
		CreatedAt: now,
	}

	evt, err := NewHostEvent(original)
	require.NoError(t, err)

	// Marshal to JSON
	data, err := json.Marshal(evt)
	require.NoError(t, err)

	// Unmarshal back
	var restored HostEvent
	require.NoError(t, json.Unmarshal(data, &restored))

	assert.Equal(t, evt.Type, restored.Type)

	// Decode and compare payload
	decoded, err := restored.Decode()
	require.NoError(t, err)

	got, ok := decoded.(HostCreated)
	require.True(t, ok)
	assert.Equal(t, original.IPAddress, got.IPAddress)
	assert.Equal(t, original.Hostname, got.Hostname)
	assert.Equal(t, original.Aliases, got.Aliases)
	assert.Equal(t, *original.Comment, *got.Comment)
	assert.Equal(t, original.Tags, got.Tags)
	assert.True(t, original.CreatedAt.Equal(got.CreatedAt))
}

func TestHostEvent_BackwardCompat_MissingAliases(t *testing.T) {
	// Simulate old JSON without the "aliases" field, matching the Rust backward-compat test.
	oldJSON := `{
		"type": "HostCreated",
		"ip_address": "192.168.1.1",
		"hostname": "test.local",
		"comment": null,
		"tags": [],
		"created_at": "2025-01-01T00:00:00Z"
	}`

	var evt HostEvent
	require.NoError(t, json.Unmarshal([]byte(oldJSON), &evt))
	assert.Equal(t, EventTypeHostCreated, evt.Type)

	decoded, err := evt.Decode()
	require.NoError(t, err)

	got, ok := decoded.(HostCreated)
	require.True(t, ok)
	assert.Empty(t, got.Aliases, "old events without aliases should deserialize with nil/empty aliases")
	assert.Equal(t, "192.168.1.1", got.IPAddress)
	assert.Equal(t, "test.local", got.Hostname)
	assert.Nil(t, got.Comment)
	assert.Empty(t, got.Tags)
}

func TestHostEvent_OccurredAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	tests := []struct {
		name  string
		event any
	}{
		{"HostCreated", HostCreated{IPAddress: "1.1.1.1", Hostname: "h", Aliases: []string{}, Tags: []string{}, CreatedAt: now}},
		{"IPAddressChanged", IPAddressChanged{OldIP: "1.1.1.1", NewIP: "2.2.2.2", ChangedAt: now}},
		{"HostnameChanged", HostnameChanged{OldHostname: "a", NewHostname: "b", ChangedAt: now}},
		{"CommentUpdated", CommentUpdated{UpdatedAt: now}},
		{"TagsModified", TagsModified{OldTags: []string{}, NewTags: []string{}, ModifiedAt: now}},
		{"AliasesModified", AliasesModified{OldAliases: []string{}, NewAliases: []string{}, ModifiedAt: now}},
		{"HostDeleted", HostDeleted{IPAddress: "1.1.1.1", Hostname: "h", DeletedAt: now}},
		{"HostImported", HostImported{IPAddress: "1.1.1.1", Hostname: "h", Tags: []string{}, Aliases: []string{}, OccurredAt: now}},
		{"SnapshotCreated", SnapshotCreated{SnapshotID: ulid.Make(), Name: "n", Trigger: "manual", EntryCount: 1, OccurredAt: now}},
		{"SnapshotRolledBack", SnapshotRolledBack{SnapshotID: ulid.Make(), RestoredEntries: 1, OccurredAt: now}},
		{"SnapshotDeleted", SnapshotDeleted{SnapshotID: ulid.Make(), OccurredAt: now}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, err := NewHostEvent(tt.event)
			require.NoError(t, err)

			occurred, err := evt.OccurredAt()
			require.NoError(t, err)
			assert.True(t, now.Equal(occurred), "expected %v, got %v", now, occurred)
		})
	}
}

func TestHostImported_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	comment := "imported host"

	original := HostImported{
		IPAddress:  "10.0.0.50",
		Hostname:   "imported.local",
		Comment:    &comment,
		Tags:       []string{"imported", "dns"},
		Aliases:    []string{"imp", "imp2"},
		OccurredAt: now,
	}

	evt, err := NewHostEvent(original)
	require.NoError(t, err)
	assert.Equal(t, EventTypeHostImported, evt.Type)

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var restored HostEvent
	require.NoError(t, json.Unmarshal(data, &restored))

	decoded, err := restored.Decode()
	require.NoError(t, err)

	got, ok := decoded.(HostImported)
	require.True(t, ok)
	assert.Equal(t, original.IPAddress, got.IPAddress)
	assert.Equal(t, original.Hostname, got.Hostname)
	assert.Equal(t, *original.Comment, *got.Comment)
	assert.Equal(t, original.Tags, got.Tags)
	assert.Equal(t, original.Aliases, got.Aliases)
	assert.True(t, original.OccurredAt.Equal(got.OccurredAt))
}

func TestSnapshotCreated_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	original := SnapshotCreated{
		SnapshotID: ulid.Make(),
		Name:       "pre-deploy-v2",
		Trigger:    "manual",
		EntryCount: 150,
		OccurredAt: now,
	}

	evt, err := NewHostEvent(original)
	require.NoError(t, err)
	assert.Equal(t, EventTypeSnapshotCreated, evt.Type)

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var restored HostEvent
	require.NoError(t, json.Unmarshal(data, &restored))

	decoded, err := restored.Decode()
	require.NoError(t, err)

	got, ok := decoded.(SnapshotCreated)
	require.True(t, ok)
	assert.Equal(t, original.SnapshotID, got.SnapshotID)
	assert.Equal(t, original.Name, got.Name)
	assert.Equal(t, original.Trigger, got.Trigger)
	assert.Equal(t, original.EntryCount, got.EntryCount)
	assert.True(t, original.OccurredAt.Equal(got.OccurredAt))
}

func TestSnapshotRolledBack_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	original := SnapshotRolledBack{
		SnapshotID:      ulid.Make(),
		RestoredEntries: 42,
		OccurredAt:      now,
	}

	evt, err := NewHostEvent(original)
	require.NoError(t, err)
	assert.Equal(t, EventTypeSnapshotRolledBack, evt.Type)

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var restored HostEvent
	require.NoError(t, json.Unmarshal(data, &restored))

	decoded, err := restored.Decode()
	require.NoError(t, err)

	got, ok := decoded.(SnapshotRolledBack)
	require.True(t, ok)
	assert.Equal(t, original.SnapshotID, got.SnapshotID)
	assert.Equal(t, original.RestoredEntries, got.RestoredEntries)
	assert.True(t, original.OccurredAt.Equal(got.OccurredAt))
}

func TestSnapshotDeleted_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	original := SnapshotDeleted{
		SnapshotID: ulid.Make(),
		OccurredAt: now,
	}

	evt, err := NewHostEvent(original)
	require.NoError(t, err)
	assert.Equal(t, EventTypeSnapshotDeleted, evt.Type)

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var restored HostEvent
	require.NoError(t, json.Unmarshal(data, &restored))

	decoded, err := restored.Decode()
	require.NoError(t, err)

	got, ok := decoded.(SnapshotDeleted)
	require.True(t, ok)
	assert.Equal(t, original.SnapshotID, got.SnapshotID)
	assert.True(t, original.OccurredAt.Equal(got.OccurredAt))
}

func TestEventEnvelope_OccurredAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := EventEnvelope{
		CreatedAt: now,
	}

	assert.True(t, now.Equal(env.OccurredAt()), "OccurredAt should return CreatedAt")
}

func TestHostEvent_MarshalJSON_EmptyPayload(t *testing.T) {
	evt := HostEvent{
		Type:    EventTypeHostCreated,
		Payload: nil,
	}

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Contains(t, m, "type")
}

func TestHostEvent_MarshalJSON_InvalidPayload(t *testing.T) {
	evt := HostEvent{
		Type:    EventTypeHostCreated,
		Payload: json.RawMessage(`"not an object"`),
	}

	_, err := json.Marshal(evt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "event payload is not a JSON object")
}

func TestHostEvent_Decode_UnknownType(t *testing.T) {
	evt := HostEvent{
		Type:    "UnknownEventType",
		Payload: json.RawMessage(`{}`),
	}

	_, err := evt.Decode()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type: UnknownEventType")
}

func TestHostEvent_OccurredAt_UnknownType(t *testing.T) {
	evt := HostEvent{
		Type:    "UnknownEventType",
		Payload: json.RawMessage(`{}`),
	}

	_, err := evt.OccurredAt()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
}

func TestNewHostEvent_UnsupportedType(t *testing.T) {
	_, err := NewHostEvent("not a valid event struct")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported event type")
}

func TestHostEvent_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var evt HostEvent
	err := json.Unmarshal([]byte(`{invalid`), &evt)
	require.Error(t, err)
}

func TestHostEvent_Decode_InvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		evtType EventType
	}{
		{"HostCreated", EventTypeHostCreated},
		{"IPAddressChanged", EventTypeIPAddressChanged},
		{"HostnameChanged", EventTypeHostnameChanged},
		{"CommentUpdated", EventTypeCommentUpdated},
		{"TagsModified", EventTypeTagsModified},
		{"AliasesModified", EventTypeAliasesModified},
		{"HostDeleted", EventTypeHostDeleted},
		{"HostImported", EventTypeHostImported},
		{"SnapshotCreated", EventTypeSnapshotCreated},
		{"SnapshotRolledBack", EventTypeSnapshotRolledBack},
		{"SnapshotDeleted", EventTypeSnapshotDeleted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := HostEvent{
				Type:    tt.evtType,
				Payload: json.RawMessage(`{invalid json`),
			}
			_, err := evt.Decode()
			require.Error(t, err)
		})
	}
}
