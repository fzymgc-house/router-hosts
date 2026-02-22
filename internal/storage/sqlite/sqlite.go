package sqlite

import (
	"context"
	"embed"
	"fmt"
	"log/slog"

	"zombiezen.com/go/sqlite/sqlitex"

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
		return nil, fmt.Errorf("open sqlite pool: %w", err)
	}
	return &Storage{pool: pool, log: logger}, nil
}

// BackendName returns the storage backend identifier.
func (s *Storage) BackendName() string { return "sqlite" }

// Initialize applies database migrations.
func (s *Storage) Initialize(ctx context.Context) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	migrationSQL, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}

	if err := sqlitex.ExecuteScript(conn, string(migrationSQL), nil); err != nil {
		return fmt.Errorf("apply migration: %w", err)
	}
	return nil
}

// HealthCheck verifies the database connection is alive.
func (s *Storage) HealthCheck(ctx context.Context) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	defer s.pool.Put(conn)
	return sqlitex.ExecuteTransient(conn, "SELECT 1", nil)
}

// Close releases the connection pool.
func (s *Storage) Close() error {
	return s.pool.Close()
}
