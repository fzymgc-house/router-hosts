package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAtomicWrite_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")

	err := Write(path, []byte("test content\n"))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "test content\n", string(data))

	// No temp files should remain after successful write
	matches, _ := filepath.Glob(filepath.Join(dir, "hosts.tmp.*"))
	assert.Empty(t, matches, "temp files should be cleaned up after atomicWrite")
}

func TestAtomicWrite_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")

	require.NoError(t, os.WriteFile(path, []byte("old content"), 0o644))

	err := Write(path, []byte("new content\n"))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new content\n", string(data))
}

func TestAtomicWrite_CleansUpTmp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")

	err := Write(path, []byte("content\n"))
	require.NoError(t, err)

	// No temp files should remain after successful write
	matches, _ := filepath.Glob(filepath.Join(dir, "hosts.tmp.*"))
	assert.Empty(t, matches, "temp files should be cleaned up after atomicWrite")
}

func TestAtomicWrite_InvalidPath(t *testing.T) {
	err := Write("/nonexistent/dir/hosts", []byte("content\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temp file")
}
