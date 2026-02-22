package commands

import (
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

func TestSnapshotRollbackCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"snapshot", "rollback"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestSnapshotDeleteCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"snapshot", "delete"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestSuccessStr(t *testing.T) {
	assert.Equal(t, "succeeded", successStr(true))
	assert.Equal(t, "failed", successStr(false))
}
