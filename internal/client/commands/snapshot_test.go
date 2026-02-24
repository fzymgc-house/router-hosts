package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotCmd_HasSubcommands(t *testing.T) {
	root := NewRootCmd()

	var snapCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "snapshot" {
			snapCmd = c
			break
		}
	}
	require.NotNil(t, snapCmd, "snapshot command not found")

	names := make([]string, 0, len(snapCmd.Commands()))
	for _, c := range snapCmd.Commands() {
		names = append(names, c.Name())
	}

	expected := []string{"create", "list", "rollback", "delete"}
	for _, exp := range expected {
		assert.Contains(t, names, exp, "expected snapshot subcommand %q", exp)
	}
}

func TestSnapshotCreateCmd_Flags(t *testing.T) {
	cmd := newSnapshotCreateCmd()
	assert.Equal(t, "create", cmd.Use)

	for _, name := range []string{"name", "trigger"} {
		f := cmd.Flags().Lookup(name)
		assert.NotNil(t, f, "missing flag --%s", name)
	}

	trigger := cmd.Flags().Lookup("trigger")
	assert.Equal(t, "manual", trigger.DefValue)
}

func TestSnapshotListCmd_Flags(t *testing.T) {
	cmd := newSnapshotListCmd()
	assert.Equal(t, "list", cmd.Use)

	for _, name := range []string{"limit", "offset"} {
		f := cmd.Flags().Lookup(name)
		assert.NotNil(t, f, "missing flag --%s", name)
	}
}

func TestSnapshotRollbackCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"snapshot", "rollback"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestSnapshotDeleteCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"snapshot", "delete"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestSuccessStr(t *testing.T) {
	assert.Equal(t, "succeeded", successStr(true))
	assert.Equal(t, "failed", successStr(false))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// createSnapshotQuiet creates a snapshot and returns its ID.
func createSnapshotQuiet(t *testing.T, name string) string {
	t.Helper()
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--quiet", "snapshot", "create", "--name", name})
	require.NoError(t, root.Execute())
	return strings.TrimSpace(buf.String())
}

// ---------------------------------------------------------------------------
// Snapshot CRUD integration via bufconn
// ---------------------------------------------------------------------------

func TestSnapshotCreate_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"snapshot", "create", "--name", "test-snap"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Snapshot created:")
	assert.Contains(t, buf.String(), "entries:")
}

func TestSnapshotCreate_QuietMode(t *testing.T) {
	setupCmdTest(t)

	id := createSnapshotQuiet(t, "quiet-snap")
	assert.NotEmpty(t, id)
}

func TestSnapshotList_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	for _, name := range []string{"snap1", "snap2"} {
		createSnapshotQuiet(t, name)
	}

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "snapshot", "list"})
	require.NoError(t, root.Execute())

	var snapshots []json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &snapshots))
	assert.Len(t, snapshots, 2)
}

func TestSnapshotList_TableFormat(t *testing.T) {
	setupCmdTest(t)
	createSnapshotQuiet(t, "tbl-snap")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "table", "snapshot", "list"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "tbl-snap")
}

func TestSnapshotList_Empty(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "snapshot", "list"})
	require.NoError(t, root.Execute())

	var snapshots []json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &snapshots))
	assert.Empty(t, snapshots)
}

func TestSnapshotDelete_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	snapID := createSnapshotQuiet(t, "to-delete")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"snapshot", "delete", snapID})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "Snapshot deleted successfully")
}

func TestSnapshotDelete_QuietMode(t *testing.T) {
	setupCmdTest(t)

	snapID := createSnapshotQuiet(t, "del-quiet")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--quiet", "snapshot", "delete", snapID})
	require.NoError(t, root.Execute())

	assert.Empty(t, buf.String())
}

func TestSnapshotRollback_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	// Add a host entry
	addHostQuiet(t, "10.0.0.1", "before.local")

	// Create snapshot
	snapID := createSnapshotQuiet(t, "baseline")

	// Add another entry
	addHostQuiet(t, "10.0.0.2", "after.local")

	// Rollback
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"snapshot", "rollback", snapID})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "Rollback succeeded")
	assert.Contains(t, out, "restored 1 entries")
}

func TestSnapshotRollback_QuietMode(t *testing.T) {
	setupCmdTest(t)

	snapID := createSnapshotQuiet(t, "empty-rollback")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--quiet", "snapshot", "rollback", snapID})
	require.NoError(t, root.Execute())

	assert.Empty(t, buf.String())
}

func TestSnapshotCreate_WithTrigger(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"snapshot", "create", "--name", "triggered", "--trigger", "pre-import"})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "Snapshot created:")
}
