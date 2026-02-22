package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSnapshot_Metadata(t *testing.T) {
	name := "pre-deploy"
	snap := &Snapshot{
		SnapshotID:   "snap-001",
		CreatedAt:    time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
		HostsContent: "192.168.1.1\tserver.local\n",
		Entries: []HostEntry{
			{IP: "192.168.1.1", Hostname: "server.local"},
		},
		EntryCount: 1,
		Trigger:    "manual",
		Name:       &name,
	}

	meta := snap.Metadata()

	assert.Equal(t, snap.SnapshotID, meta.SnapshotID)
	assert.Equal(t, snap.CreatedAt, meta.CreatedAt)
	assert.Equal(t, snap.EntryCount, meta.EntryCount)
	assert.Equal(t, snap.Trigger, meta.Trigger)
	assert.Equal(t, snap.Name, meta.Name)
}

func TestSnapshot_Metadata_NilName(t *testing.T) {
	snap := &Snapshot{
		SnapshotID: "snap-002",
		CreatedAt:  time.Now().UTC(),
		EntryCount: 0,
		Trigger:    "automatic",
		Name:       nil,
	}

	meta := snap.Metadata()

	assert.Equal(t, snap.SnapshotID, meta.SnapshotID)
	assert.Nil(t, meta.Name)
}
