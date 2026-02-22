package commands

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRootCmd_HasSubcommands(t *testing.T) {
	root := NewRootCmd()

	names := make([]string, 0, len(root.Commands()))
	for _, c := range root.Commands() {
		names = append(names, c.Name())
	}

	assert.Contains(t, names, "host")
	assert.Contains(t, names, "snapshot")
	assert.Contains(t, names, "server")
}

func TestNewRootCmd_GlobalFlags(t *testing.T) {
	root := NewRootCmd()
	pf := root.PersistentFlags()

	tests := []struct {
		flag string
	}{
		{"server"},
		{"cert"},
		{"key"},
		{"ca"},
		{"config"},
		{"format"},
		{"quiet"},
		{"verbose"},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			f := pf.Lookup(tt.flag)
			require.NotNil(t, f, "expected persistent flag %q", tt.flag)
		})
	}
}

func TestNewRootCmd_FormatShorthand(t *testing.T) {
	root := NewRootCmd()
	f := root.PersistentFlags().ShorthandLookup("f")
	require.NotNil(t, f)
	assert.Equal(t, "format", f.Name)
}

func TestNewRootCmd_HelpOutput(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"--help"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "router-hosts")
	assert.Contains(t, buf.String(), "host")
	assert.Contains(t, buf.String(), "snapshot")
	assert.Contains(t, buf.String(), "server")
}

func TestNewRootCmd_FlagParsing(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{
		"--server", "localhost:9090",
		"--cert", "/tmp/cert.pem",
		"--key", "/tmp/key.pem",
		"--ca", "/tmp/ca.pem",
		"--format", "json",
		"--quiet",
		"--verbose",
		"--help",
	})

	err := root.Execute()
	require.NoError(t, err)

	assert.Equal(t, "localhost:9090", Flags.Server)
	assert.Equal(t, "/tmp/cert.pem", Flags.Cert)
	assert.Equal(t, "/tmp/key.pem", Flags.Key)
	assert.Equal(t, "/tmp/ca.pem", Flags.CA)
	assert.Equal(t, "json", Flags.Format)
	assert.True(t, Flags.Quiet)
	assert.True(t, Flags.Verbose)
}

func TestHostCmd_HasAliases(t *testing.T) {
	root := NewRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "host" {
			assert.Contains(t, c.Aliases, "h")
			return
		}
	}
	t.Fatal("host command not found")
}

func TestSnapshotCmd_HasAliases(t *testing.T) {
	root := NewRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "snapshot" {
			assert.Contains(t, c.Aliases, "snap")
			assert.Contains(t, c.Aliases, "s")
			return
		}
	}
	t.Fatal("snapshot command not found")
}

func TestServerCmd_HasSubcommands(t *testing.T) {
	root := NewRootCmd()
	var serverCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "server" {
			serverCmd = c
			break
		}
	}
	require.NotNil(t, serverCmd)

	names := make([]string, 0, len(serverCmd.Commands()))
	for _, c := range serverCmd.Commands() {
		names = append(names, c.Name())
	}

	assert.Contains(t, names, "health")
	assert.Contains(t, names, "liveness")
	assert.Contains(t, names, "readiness")
}
