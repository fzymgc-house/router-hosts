package commands

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultNewClientFromFlags_WithServerAddress_NoTLS(t *testing.T) {
	origFlags := Flags
	t.Cleanup(func() { Flags = origFlags })

	// Isolate from real config files on the developer's machine.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	Flags = GlobalFlags{
		Server: "localhost:50051",
	}

	// Without TLS config, connection should fail with a TLS required error.
	_, err := defaultNewClientFromFlags()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS configuration required")
}

func TestDefaultNewClientFromFlags_WithAllFlags(t *testing.T) {
	origFlags := Flags
	t.Cleanup(func() { Flags = origFlags })

	Flags = GlobalFlags{
		Server: "localhost:50051",
		Cert:   "/nonexistent/cert.pem",
		Key:    "/nonexistent/key.pem",
		CA:     "/nonexistent/ca.pem",
	}

	// This will fail because the cert/key/ca files don't exist
	_, err := defaultNewClientFromFlags()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connecting to server")
}

func TestDefaultNewClientFromFlags_NoServerAddress(t *testing.T) {
	origFlags := Flags
	t.Cleanup(func() { Flags = origFlags })

	// Unset env vars so config loading fails
	t.Setenv("ROUTER_HOSTS_SERVER", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no config file here

	Flags = GlobalFlags{}

	_, err := defaultNewClientFromFlags()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "loading client config")
}

// ---------------------------------------------------------------------------
// Explicit --config path resolution (gap G-01-1).
// ---------------------------------------------------------------------------

func TestDefaultNewClientFromFlags_ConfigFlagSelectsFile(t *testing.T) {
	origFlags := Flags
	t.Cleanup(func() { Flags = origFlags })

	xdgDir := t.TempDir()
	cfgDir := xdgDir + "/router-hosts"
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.WriteFile(cfgDir+"/client.toml", []byte("[server]\naddress = \"decoy.invalid:59999\"\n"), 0o600))
	t.Setenv("XDG_CONFIG_HOME", xdgDir)
	t.Setenv("ROUTER_HOSTS_SERVER", "")
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	// The dial is lazy, so an unroutable address alone would not prove which
	// file was loaded. Point the explicit file at an empty server address
	// instead: only the "server address is required" validation error is
	// reachable if the explicit file (not the decoy) was the one loaded.
	explicitDir := t.TempDir()
	explicitPath := explicitDir + "/explicit.toml"
	require.NoError(t, os.WriteFile(explicitPath, []byte("[server]\naddress = \"\"\n"), 0o600))

	Flags = GlobalFlags{Config: explicitPath}

	_, err := defaultNewClientFromFlags()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server address is required")
}

// ---------------------------------------------------------------------------
// Client factory error propagation tests
// ---------------------------------------------------------------------------

var errFakeClient = errors.New("fake client error")

// setupFailingClient replaces newClientFromFlags with one that always returns
// an error, then restores it on cleanup.
func setupFailingClient(t *testing.T) {
	t.Helper()
	origFactory := newClientFromFlags
	origFlags := Flags
	t.Cleanup(func() {
		newClientFromFlags = origFactory
		Flags = origFlags
	})
	newClientFromFlags = func() (*client.Client, error) {
		return nil, errFakeClient
	}
	Flags = GlobalFlags{}
}

func TestHostAdd_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "add", "--ip", "10.0.0.1", "--hostname", "err.local"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostGet_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "get", "01ARZ3NDEKTSV4RRFFQ69G5FAV"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostUpdate_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "update", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "--ip", "10.0.0.1"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostDelete_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "delete", "01ARZ3NDEKTSV4RRFFQ69G5FAV"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostList_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "list"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostSearch_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "search", "query"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostImport_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "import", "/dev/null"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestHostExport_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"host", "export"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestSnapshotCreate_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"snapshot", "create"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestSnapshotList_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"snapshot", "list"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestSnapshotRollback_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"snapshot", "rollback", "snap-id"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestSnapshotDelete_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"snapshot", "delete", "snap-id"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestServerHealth_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"server", "health"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestServerLiveness_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"server", "liveness"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}

func TestServerReadiness_ClientError(t *testing.T) {
	setupFailingClient(t)

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"server", "readiness"})

	err := root.Execute()
	assert.ErrorIs(t, err, errFakeClient)
}
