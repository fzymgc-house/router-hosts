package domain

import (
	"encoding/json"
	"testing"
	"time"

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
		wantType string
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
