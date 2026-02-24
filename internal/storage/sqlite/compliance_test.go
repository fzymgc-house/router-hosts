package sqlite_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/storage"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
	"github.com/fzymgc-house/router-hosts/internal/storage/storagetest"
)

// TestCompliance runs the shared storage compliance suite against the SQLite
// backend. Each sub-test receives its own in-memory database so tests are
// fully hermetic.
func TestCompliance(t *testing.T) {
	storagetest.RunAll(t, func(t *testing.T) storage.Storage {
		t.Helper()
		store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
		require.NoError(t, err)
		require.NoError(t, store.Initialize(context.Background()))
		t.Cleanup(func() { _ = store.Close() })
		return store
	})
}
