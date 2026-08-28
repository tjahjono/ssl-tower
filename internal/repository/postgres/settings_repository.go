package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// SettingsRepository persists admin-editable operational settings as a
// plain key/value table — see internal/database/migrations/0014_app_settings.sql.
type SettingsRepository struct {
	pool *pgxpool.Pool
}

// NewSettingsRepository wires the repository to a pool.
func NewSettingsRepository(pool *pgxpool.Pool) *SettingsRepository {
	return &SettingsRepository{pool: pool}
}

var _ domain.SettingsRepository = (*SettingsRepository)(nil)

// Get returns one key's value. found is false, not an error, when no row
// exists for key yet.
func (r *SettingsRepository) Get(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := r.pool.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("settings repo: get %s: %w", key, err)
	}
	return value, true, nil
}

// GetAll returns every stored key/value pair.
func (r *SettingsRepository) GetAll(ctx context.Context) (map[string]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, fmt.Errorf("settings repo: get all: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("settings repo: scan: %w", err)
		}
		out[key] = value
	}
	return out, rows.Err()
}

// SetMany upserts every key in values within a single transaction — a
// partial write (some keys updated, others not) is never observable, even
// if the process crashes mid-save.
func (r *SettingsRepository) SetMany(ctx context.Context, values map[string]string, updatedBy string) error {
	if len(values) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("settings repo: set many: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `INSERT INTO app_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (key) DO UPDATE SET
			value = EXCLUDED.value,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()`
	for key, value := range values {
		if _, err := tx.Exec(ctx, q, key, value, updatedBy); err != nil {
			return fmt.Errorf("settings repo: set %s: %w", key, err)
		}
	}
	return tx.Commit(ctx)
}
