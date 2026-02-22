package commands

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostCmd_HasCRUDSubcommands(t *testing.T) {
	root := NewRootCmd()

	var hostCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "host" {
			hostCmd = c
			break
		}
	}
	require.NotNil(t, hostCmd, "host command not found")

	names := make([]string, 0, len(hostCmd.Commands()))
	for _, c := range hostCmd.Commands() {
		names = append(names, c.Name())
	}

	expected := []string{"add", "get", "update", "delete", "list", "search"}
	for _, exp := range expected {
		assert.Contains(t, names, exp, "expected host subcommand %q", exp)
	}
}

func TestHostAddCmd_RequiredFlags(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"host", "add"})
	err := root.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag")
}

func TestHostGetCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"host", "get"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostUpdateCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"host", "update"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostDeleteCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"host", "delete"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostSearchCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"host", "search"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestResolveFormat_DefaultEmpty(t *testing.T) {
	Flags.Format = ""
	f := resolveFormat()
	// In test env (non-TTY), should return "json"
	assert.Equal(t, "json", f)
}

func TestResolveFormat_ExplicitOverride(t *testing.T) {
	Flags.Format = "CSV"
	f := resolveFormat()
	assert.Equal(t, "csv", f)
	Flags.Format = ""
}
