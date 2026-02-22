package commands

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostCmd_HasImportExport(t *testing.T) {
	root := NewRootCmd()

	var hostCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "host" {
			hostCmd = c
			break
		}
	}
	require.NotNil(t, hostCmd)

	names := make([]string, 0, len(hostCmd.Commands()))
	for _, c := range hostCmd.Commands() {
		names = append(names, c.Name())
	}

	assert.Contains(t, names, "import")
	assert.Contains(t, names, "export")
}

func TestHostImportCmd_RequiresFileArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"host", "import"})
	err := root.Execute()
	assert.Error(t, err)
}
