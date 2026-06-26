package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompactCmd_FlagRegistration(t *testing.T) {
	cmd := newCompactCmd()
	assert.Equal(t, "compact [aggregate-id]", cmd.Use)

	require.NotNil(t, cmd.Flags().Lookup("over"), "missing flag --over")
	require.NotNil(t, cmd.Flags().Lookup("dry-run"), "missing flag --dry-run")
}

func TestCompactCmd_NoArgsNoOver_ReturnsError(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"compact"})
	err := root.Execute()
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "aggregate-id") || strings.Contains(err.Error(), "--over"),
		"error should mention aggregate-id or --over, got: %s", err.Error())
}

func TestCompactCmd_ArgAndOver_ReturnsError(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"compact", "some-id", "--over", "10"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not both")
}

func TestCompactCmd_IsRegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "compact" {
			found = true
			break
		}
	}
	assert.True(t, found, "compact command not registered on root")
}
