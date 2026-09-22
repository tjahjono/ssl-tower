package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrate applies every embedded .sql migration exactly once, in filename order.
// Each migration runs inside its own transaction alongside the bookkeeping insert,
// so a failed migration leaves no partial state behind.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     TEXT PRIMARY KEY,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("migrate: ensure schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("migrate: load applied: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("migrate: scan applied: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrate: iterate applied: %w", err)
	}

	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("migrate: glob: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		if applied[name] {
			continue
		}
		body, err := migrationFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("migrate: read %s: %w", name, err)
		}
		err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migrate: apply %s: %w", name, err)
		}
		log.Info("migration applied", "version", name)
	}
	return nil
}
