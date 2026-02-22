package commands

import (
	"bytes"
	"os"
	"path/filepath"
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
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "import"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestHostImportCmd_Flags(t *testing.T) {
	cmd := newHostImportCmd()
	assert.Equal(t, "import <file>", cmd.Use)

	for _, name := range []string{"format", "conflict-mode", "force"} {
		f := cmd.Flags().Lookup(name)
		assert.NotNil(t, f, "missing flag --%s", name)
	}
}

func TestHostExportCmd_Flags(t *testing.T) {
	cmd := newHostExportCmd()
	assert.Equal(t, "export", cmd.Use)

	for _, name := range []string{"format", "output"} {
		f := cmd.Flags().Lookup(name)
		assert.NotNil(t, f, "missing flag --%s", name)
	}

	fmtFlag := cmd.Flags().Lookup("format")
	assert.Equal(t, "hosts", fmtFlag.DefValue)

	outFlag := cmd.Flags().ShorthandLookup("o")
	require.NotNil(t, outFlag)
	assert.Equal(t, "output", outFlag.Name)
}

func TestImportChunkSize(t *testing.T) {
	assert.Equal(t, 64*1024, importChunkSize)
}

// ---------------------------------------------------------------------------
// Import integration via bufconn
// ---------------------------------------------------------------------------

func TestHostImport_HostsFormat_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	hostsData := "192.168.1.10\tserver.local srv.local\t# web server [web, prod]\n" +
		"10.0.0.1\tdb.local\t# database\n" +
		"# comment line\n" +
		"\n" +
		"172.16.0.1\tproxy.local\n"

	tmpFile := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte(hostsData), 0o644))

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "import", tmpFile, "--format", "hosts"})

	err := root.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Import complete")
	assert.Contains(t, out, "3 processed")
	assert.Contains(t, out, "3 created")
}

func TestHostImport_SkipConflict_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	// Pre-create an entry
	addHostQuiet(t, "192.168.1.10", "server.local")

	hostsData := "192.168.1.10\tserver.local\n10.0.0.1\tnew.local\n"
	tmpFile := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte(hostsData), 0o644))

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "import", tmpFile, "--format", "hosts", "--conflict-mode", "skip"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "1 created")
	assert.Contains(t, out, "1 skipped")
}

func TestHostImport_ReplaceConflict_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "192.168.1.10", "server.local")

	hostsData := "192.168.1.10\tserver.local\t# updated [new]\n"
	tmpFile := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte(hostsData), 0o644))

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "import", tmpFile, "--format", "hosts", "--conflict-mode", "replace"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "1 updated")
}

func TestHostImport_QuietMode_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	hostsData := "10.0.0.1\tquiet.local\n"
	tmpFile := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte(hostsData), 0o644))

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--quiet", "host", "import", tmpFile, "--format", "hosts"})
	require.NoError(t, root.Execute())

	assert.Empty(t, buf.String())
}

func TestHostImport_NonexistentFile(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "import", "/nonexistent/file.txt"})

	err := root.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "opening import file")
}

func TestHostImport_WithForce_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	hostsData := "10.0.0.1\tforce.local\n"
	tmpFile := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte(hostsData), 0o644))

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "import", tmpFile, "--format", "hosts", "--force"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "Import complete")
	assert.Contains(t, out, "1 created")
}

// ---------------------------------------------------------------------------
// Export integration via bufconn
// ---------------------------------------------------------------------------

func TestHostExport_HostsFormat_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "192.168.1.10", "server.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "export", "--format", "hosts"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "192.168.1.10")
	assert.Contains(t, out, "server.local")
}

func TestHostExport_JSONFormat_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "10.0.0.1", "json.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "export", "--format", "json"})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "10.0.0.1")
	assert.Contains(t, buf.String(), "json.local")
}

func TestHostExport_CSVFormat_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "10.0.0.1", "csv.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "export", "--format", "csv"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "10.0.0.1")
	assert.Contains(t, out, "csv.local")
}

func TestHostExport_ToFile_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "10.0.0.1", "file.local")

	outFile := filepath.Join(t.TempDir(), "export.txt")
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetArgs([]string{"host", "export", "--format", "hosts", "-o", outFile})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "10.0.0.1")
	assert.Contains(t, string(data), "file.local")
}

func TestHostExport_ToStdout_DashArg(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "10.0.0.1", "dash.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "export", "--format", "hosts", "-o", "-"})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "dash.local")
}

func TestHostExport_DefaultFormat(t *testing.T) {
	setupCmdTest(t)

	addHostQuiet(t, "10.0.0.1", "default.local")

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "export"})
	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "default.local")
}

// ---------------------------------------------------------------------------
// Large import (multi-chunk)
// ---------------------------------------------------------------------------

func TestHostImport_LargeFile_ViaGRPC(t *testing.T) {
	setupCmdTest(t)

	var sb bytes.Buffer
	for i := 0; i < 100; i++ {
		sb.WriteString("10.0.0.1\thost" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + ".local\n")
	}

	tmpFile := filepath.Join(t.TempDir(), "large.txt")
	require.NoError(t, os.WriteFile(tmpFile, sb.Bytes(), 0o644))

	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"host", "import", tmpFile, "--format", "hosts"})
	require.NoError(t, root.Execute())

	assert.Contains(t, buf.String(), "Import complete")
}
