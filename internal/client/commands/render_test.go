package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/contract"
)

// testContractVersionBlock declares the current contract version so a
// fixture template passes the DeclaredVersion/RequireVersion gates. Every
// fixture in this file must carry it now that render refuses undeclared and
// mismatched templates before rendering.
const testContractVersionBlock = `{{define "contract_version"}}` + contract.TemplateVersion + `{{end}}`

func TestRender_TemplateEndToEnd(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "server.local"})
	require.NoError(t, root.Execute())

	tmplPath := filepath.Join(t.TempDir(), "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`), 0o644))

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
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.Count}}`), 0o644))

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
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`), 0o644))
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
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.NoSuchField}}`), 0o644))
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

func TestRender_RefusesUndeclaredVersion(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "server.local"})
	require.NoError(t, root.Execute())

	// No contract_version block declared — the parse-time gate must refuse
	// this before newClientFromFlags is ever called.
	tmplPath := filepath.Join(t.TempDir(), "undeclared.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{{range .Entries}}{{.IPAddress}}{{end}}`), 0o644))

	root = NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"render", "--template", tmplPath})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "contract_version")
	assert.Empty(t, out.String())
}

func TestRender_RefusesVersionMismatch(t *testing.T) {
	setupCmdTest(t)

	root := NewRootCmd()
	var addOut bytes.Buffer
	root.SetOut(&addOut)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", "192.168.1.10", "--hostname", "server.local"})
	require.NoError(t, root.Execute())

	// Declares a version one step above the served contract.TemplateVersion.
	tmplPath := filepath.Join(t.TempDir(), "mismatch.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{{define "contract_version"}}999{{end}}{{range .Entries}}{{.IPAddress}}{{end}}`), 0o644))
	outPath := filepath.Join(t.TempDir(), "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("pre-existing artifact"), 0o644))

	root = NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"render", "--template", tmplPath, "--out", outPath})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "999")
	assert.Contains(t, err.Error(), contract.TemplateVersion)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing artifact", string(data))
}
