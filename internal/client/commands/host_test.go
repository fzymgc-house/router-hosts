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
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "add"})
	err := root.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag")
}

func TestHostAddCmd_Flags(t *testing.T) {
	cmd := newHostAddCmd()
	assert.Equal(t, "add", cmd.Use)

	tests := []struct {
		flag     string
		flagType string
	}{
		{"ip", "string"},
		{"hostname", "string"},
		{"comment", "string"},
		{"tags", "stringSlice"},
		{"aliases", "stringSlice"},
	}
	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			f := cmd.Flags().Lookup(tt.flag)
			require.NotNil(t, f, "missing flag --%s", tt.flag)
			assert.Equal(t, tt.flagType, f.Value.Type())
		})
	}
}

func TestHostGetCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "get"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostUpdateCmd_Flags(t *testing.T) {
	cmd := newHostUpdateCmd()
	assert.Equal(t, "update <id>", cmd.Use)

	flags := []string{"ip", "hostname", "comment", "version", "tags", "aliases"}
	for _, name := range flags {
		f := cmd.Flags().Lookup(name)
		assert.NotNil(t, f, "missing flag --%s", name)
	}
}

func TestHostUpdateCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "update"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostDeleteCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "delete"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostListCmd_Flags(t *testing.T) {
	cmd := newHostListCmd()
	assert.Equal(t, "list", cmd.Use)

	for _, name := range []string{"filter", "limit", "offset"} {
		f := cmd.Flags().Lookup(name)
		assert.NotNil(t, f, "missing flag --%s", name)
	}
}

func TestHostSearchCmd_RequiresArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "search"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestResolveFormat_DefaultEmpty(t *testing.T) {
	origFlags := Flags
	t.Cleanup(func() { Flags = origFlags })

	Flags.Format = ""
	f := resolveFormat()
	// In test env (non-TTY), should return "json"
	assert.Equal(t, "json", f)
}

func TestResolveFormat_ExplicitOverride(t *testing.T) {
	origFlags := Flags
	t.Cleanup(func() { Flags = origFlags })

	Flags.Format = "CSV"
	f := resolveFormat()
	assert.Equal(t, "csv", f)
}

// ---------------------------------------------------------------------------
// Host CRUD integration via bufconn
// ---------------------------------------------------------------------------

// addHostQuiet adds a host and returns its ULID. Uses --quiet flag in args.
func addHostQuiet(t *testing.T, ip, hostname string) string {
	t.Helper()
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", ip, "--hostname", hostname})
	require.NoError(t, root.Execute())
	return strings.TrimSpace(buf.String())
}

func TestHostAdd_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{
		"--format", "json",
		"host", "add",
		"--ip", "192.168.1.10",
		"--hostname", "server.local",
		"--comment", "web server",
		"--tags", "web,prod",
		"--aliases", "srv.local",
	})

	err := root.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "192.168.1.10")
	assert.Contains(t, out, "server.local")
}

func TestHostAdd_QuietMode(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "quiet.local")
	assert.NotEmpty(t, id)
	assert.Len(t, id, 26) // ULID is 26 chars
}

func TestHostGet_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "test.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "get", id})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "10.0.0.1")
	assert.Contains(t, buf.String(), "test.local")
}

func TestHostGet_NotFound(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "get", "01ARZ3NDEKTSV4RRFFQ69G5FAV"})

	err := root.Execute()
	assert.Error(t, err)
}

func TestHostUpdate_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "update.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "update", id, "--ip", "10.0.0.99", "--version", "1"})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "10.0.0.99")
}

func TestHostUpdate_WithTags(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "tags.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "update", id, "--tags", "new,tags", "--aliases", "alias1", "--version", "1"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "new")
	assert.Contains(t, out, "tags")
}

func TestHostUpdate_WithComment(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "comment.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "update", id, "--comment", "updated comment", "--hostname", "newcomment.local", "--version", "1"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "updated comment")
	assert.Contains(t, out, "newcomment.local")
}

func TestHostDelete_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "delete.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "delete", id})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "Deleted successfully")
}

func TestHostDelete_QuietMode(t *testing.T) {
	setupCmdTest(t)

	id := addHostQuiet(t, "10.0.0.1", "delq.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--quiet", "host", "delete", id})
	require.NoError(t, root.Execute())

	assert.Empty(t, buf.String())
}

func TestHostList_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	for _, h := range []string{"a.local", "b.local"} {
		addHostQuiet(t, "10.0.0.1", h)
	}

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "list"})
	require.NoError(t, root.Execute())

	var entries []json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entries))
	assert.Len(t, entries, 2)
}

func TestHostList_WithLimitFlag(t *testing.T) {
	setupCmdTest(t)

	for _, h := range []string{"x.local", "y.local", "z.local"} {
		addHostQuiet(t, "10.0.0.1", h)
	}

	// Verify the --limit flag is accepted and the command executes
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "list", "--limit", "100"})
	require.NoError(t, root.Execute())

	var entries []json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entries))
	assert.Len(t, entries, 3)
}

func TestHostSearch_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "192.168.1.1", "webserver.local")
	addHostQuiet(t, "192.168.1.2", "dbserver.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "search", "webserver"})
	require.NoError(t, root.Execute())

	var entries []json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entries))
	assert.Len(t, entries, 1)
}

// ---------------------------------------------------------------------------
// Output format tests
// ---------------------------------------------------------------------------

func TestHostList_TableFormat(t *testing.T) {
	setupCmdTest(t)
	addHostQuiet(t, "10.0.0.1", "tbl.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "table", "host", "list"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "tbl.local")
}

func TestHostList_CSVFormat(t *testing.T) {
	setupCmdTest(t)
	addHostQuiet(t, "10.0.0.1", "csv.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "csv", "host", "list"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "csv.local")
}

func TestHostList_EmptyResult(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--format", "json", "host", "list"})
	require.NoError(t, root.Execute())

	var entries []json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entries))
	assert.Empty(t, entries)
}
