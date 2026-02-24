package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// errWriter is an io.Writer that always returns an error.
type errWriter struct{ err error }

func (e *errWriter) Write(_ []byte) (int, error) { return 0, e.err }

func sampleEntries() []*hostsv1.HostEntry {
	comment := "test comment"
	return []*hostsv1.HostEntry{
		{
			Id:        "01HX1234567890ABCDEF",
			IpAddress: "192.168.1.1",
			Hostname:  "router.local",
			Aliases:   []string{"gw.local"},
			Comment:   &comment,
			Tags:      []string{"homelab", "router"},
			Version:   "v1abc123def",
		},
		{
			Id:        "01HX1234567890GHIJKL",
			IpAddress: "10.0.0.1",
			Hostname:  "server.local",
			Tags:      []string{"prod"},
			Version:   "v2",
		},
	}
}

func sampleSnapshots() []*hostsv1.Snapshot {
	return []*hostsv1.Snapshot{
		{
			SnapshotId: "snap-001",
			Name:       "before-migration",
			Trigger:    "manual",
			EntryCount: 42,
			CreatedAt:  timestamppb.Now(),
		},
	}
}

// --- JSON tests ---

func TestRenderJSON_Hosts(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderHosts(buf, "json", sampleEntries())
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Len(t, result, 2)
	// Proto json tags use snake_case: ip_address
	assert.Equal(t, "192.168.1.1", result[0]["ip_address"])
}

func TestRenderJSON_Empty(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderHosts(buf, "json", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "null")
}

func TestRenderJSON_Snapshots(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderSnapshots(buf, "json", sampleSnapshots())
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Len(t, result, 1)
	// Proto JSON tags use snake_case: snapshot_id
	assert.Equal(t, "snap-001", result[0]["snapshot_id"])
}

// --- CSV tests ---

func TestRenderCSV_Hosts(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderHosts(buf, "csv", sampleEntries())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 3) // header + 2 rows
	assert.Contains(t, lines[0], "id")
	assert.Contains(t, lines[0], "ip_address")
	assert.Contains(t, lines[1], "192.168.1.1")
	assert.Contains(t, lines[1], "router.local")
	assert.Contains(t, lines[1], "test comment")
}

func TestRenderCSV_Snapshots(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderSnapshots(buf, "csv", sampleSnapshots())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 2) // header + 1 row
	assert.Contains(t, lines[0], "snapshot_id")
	assert.Contains(t, lines[1], "snap-001")
}

// --- Table tests ---

func TestRenderTable_Hosts(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderHosts(buf, "table", sampleEntries())
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "192.168.1.1")
	assert.Contains(t, out, "router.local")
}

func TestRenderTable_Empty(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderHosts(buf, "table", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No host entries found")
}

func TestRenderTable_Snapshots(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderSnapshots(buf, "table", sampleSnapshots())
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "snap-001")
	assert.Contains(t, buf.String(), "before-migration")
}

func TestRenderTable_SnapshotsEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderSnapshots(buf, "table", nil)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No snapshots found")
}

// --- Format selection ---

func TestRenderHosts_UnknownFormatFallsToTable(t *testing.T) {
	buf := new(bytes.Buffer)
	err := RenderHosts(buf, "yaml", sampleEntries())
	require.NoError(t, err)
	// Should fall through to table format
	assert.Contains(t, buf.String(), "192.168.1.1")
}

// --- Helper tests ---

func TestTruncateVersion(t *testing.T) {
	assert.Equal(t, "v1abc123", truncateVersion("v1abc123def"))
	assert.Equal(t, "short", truncateVersion("short"))
	assert.Equal(t, "", truncateVersion(""))
}

func TestDetectFormat_NonTTY(t *testing.T) {
	// In test environments stdout is not a TTY
	assert.Equal(t, "json", DetectFormat())
}

// --- Error propagation tests ---

func TestRenderTable_WriterError(t *testing.T) {
	writeErr := errors.New("disk full")
	w := &errWriter{err: writeErr}
	err := renderTable(w, sampleEntries())
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
}

func TestRenderTable_EmptyWriterError(t *testing.T) {
	writeErr := errors.New("disk full")
	w := &errWriter{err: writeErr}
	err := renderTable(w, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
}

func TestRenderSnapshotsTable_WriterError(t *testing.T) {
	writeErr := errors.New("disk full")
	w := &errWriter{err: writeErr}
	err := renderSnapshotsTable(w, sampleSnapshots())
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
}

func TestRenderSnapshotsTable_EmptyWriterError(t *testing.T) {
	writeErr := errors.New("disk full")
	w := &errWriter{err: writeErr}
	err := renderSnapshotsTable(w, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
}
