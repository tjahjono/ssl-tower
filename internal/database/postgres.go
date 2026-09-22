// Package database owns the Postgres connection pool and schema migrations.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect opens a pgx pool and verifies connectivity with a ping.
func Connect(ctx context.Context, dsn string, maxConns int32, timeout time.Duration) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parse dsn: %w", err)
	}
	if maxConns > 0 {
		poolCfg.MaxConns = maxConns
	}
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(dialCtx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database: create pool: %w", err)
	}
	if err := pool.Ping(dialCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return pool, nil
}
