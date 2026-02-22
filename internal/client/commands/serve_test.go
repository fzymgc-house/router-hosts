package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServeCmd_Exists(t *testing.T) {
	cmd := newServeCmd()
	assert.Equal(t, "serve", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestNewServeCmd_HasConfigFlag(t *testing.T) {
	cmd := newServeCmd()
	f := cmd.Flags().Lookup("config")
	require.NotNil(t, f, "serve command must have --config flag")
	assert.Equal(t, "string", f.Value.Type())
}

func TestNewServeCmd_ConfigFlagRequired(t *testing.T) {
	cmd := newServeCmd()

	// Executing without --config should fail
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err, "serve should fail without required --config flag")
}

func TestNewServeCmd_RegisteredInRoot(t *testing.T) {
	root := NewRootCmd()
	found := false
	for _, sub := range root.Commands() {
		if sub.Use == "serve" {
			found = true
			break
		}
	}
	assert.True(t, found, "serve command must be registered on root")
}
