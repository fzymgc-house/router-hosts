package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender_TemplateEndToEnd(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "server.local"})
	require.NoError(t, root.Execute())

	tmplPath := filepath.Join(t.TempDir(), "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`), 0o644))

	root = NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"render", "--template", tmplPath})
	require.NoError(t, root.Execute())

	assert.Equal(t, "192.168.1.10 server.local\n", out.String())
}

func TestRender_DrainLimitRefusesSnapshot(t *testing.T) {
	setupCmdTest(t)

	orig := renderDrainLimit
	renderDrainLimit = 1
	t.Cleanup(func() { renderDrainLimit = orig })

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "one.local"})
	require.NoError(t, root.Execute())

	root = NewRootCmd()
	addOut.Reset()
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.11", "--hostname", "two.local"})
	require.NoError(t, root.Execute())

	tmplPath := filepath.Join(t.TempDir(), "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{{.Count}}`), 0o644))

	root = NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"render", "--template", tmplPath})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1")
	assert.Empty(t, out.String())
}

func TestRender_WritesArtifactToOut(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "server.local"})
	require.NoError(t, root.Execute())

	tmplPath := filepath.Join(t.TempDir(), "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`), 0o644))
	outPath := filepath.Join(t.TempDir(), "out.txt")

	root = NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"render", "--template", tmplPath, "--out", outPath})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.10 server.local\n", string(data))
}

func TestRender_FailurePreservesArtifact(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "server.local"})
	require.NoError(t, root.Execute())

	tmplPath := filepath.Join(t.TempDir(), "bad.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{{.NoSuchField}}`), 0o644))
	outPath := filepath.Join(t.TempDir(), "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("pre-existing artifact"), 0o644))

	root = NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"render", "--template", tmplPath, "--out", outPath})
	err := root.Execute()
	require.Error(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing artifact", string(data))
}
