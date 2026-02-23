package sqlite

import (
	"context"
	"embed"
	"log/slog"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/storage"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Storage implements storage.Storage backed by SQLite (pure Go, no CGo).
type Storage struct {
	pool *sqlitex.Pool
	log  *slog.Logger
}

// Compile-time check that Storage implements storage.Storage.
var _ storage.Storage = (*Storage)(nil)

// New creates a new SQLite storage instance.
func New(dbPath string, logger *slog.Logger) (*Storage, error) {
	pool, err := sqlitex.NewPool(dbPath, sqlitex.PoolOptions{
		PoolSize: 10,
	})
	if err != nil {
		return nil, oops.Wrapf(err, "open sqlite pool")
	}
	return &Storage{pool: pool, log: logger}, nil
}

// BackendName returns the storage backend identifier.
func (s *Storage) BackendName() string { return "sqlite" }

// migrationFiles lists migration SQL files in order. Each file is applied
// only when the schema_version table does not yet contain that version number.
var migrationFiles = []struct {
	version int
	path    string
}{
	{1, "migrations/001_initial.sql"},
	{2, "migrations/002_snapshot_entries_json.sql"},
}

// Initialize applies database migrations in order, skipping already-applied ones.
func (s *Storage) Initialize(ctx context.Context) error {
	return s.withConn(ctx, func(conn *sqlite.Conn) error {
		for _, m := range migrationFiles {
			sql, err := migrations.ReadFile(m.path)
			if err != nil {
				return oops.Wrapf(err, "read migration %s", m.path)
			}
			// Migration 1 creates schema_version; for later migrations check it.
			if m.version > 1 {
				var applied bool
				checkErr := sqlitex.Execute(conn,
					`SELECT 1 FROM schema_version WHERE version = ?`,
					&sqlitex.ExecOptions{
						Args: []any{m.version},
						ResultFunc: func(*sqlite.Stmt) error {
							applied = true
							return nil
						},
					})
				if checkErr != nil {
					return oops.Wrapf(checkErr, "check schema_version for migration %d", m.version)
				}
				if applied {
					continue
				}
			}
			if err := sqlitex.ExecuteScript(conn, string(sql), nil); err != nil {
				return oops.Wrapf(err, "apply migration %s", m.path)
			}
		}
		return nil
	})
}

// HealthCheck verifies the database connection is alive.
func (s *Storage) HealthCheck(ctx context.Context) error {
	return s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.ExecuteTransient(conn, "SELECT 1", nil)
	})
}

// Close releases the connection pool.
func (s *Storage) Close() error {
	return s.pool.Close()
}

// withConn acquires a connection from the pool, calls fn with it, and
// returns the connection when done. Transaction management is the caller's
// responsibility.
func (s *Storage) withConn(ctx context.Context, fn func(*sqlite.Conn) error) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return oops.Wrapf(err, "take connection")
	}
	defer s.pool.Put(conn)
	return fn(conn)
}
