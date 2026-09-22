package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// AuditRepository persists the admin-facing audit trail.
type AuditRepository struct {
	pool *pgxpool.Pool
}

// NewAuditRepository wires the repository to a pool.
func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{pool: pool}
}

var _ domain.AuditRepository = (*AuditRepository)(nil)

// RecordAudit appends one row to the trail.
func (r *AuditRepository) RecordAudit(ctx context.Context, e *domain.AuditEntry) error {
	const q = `INSERT INTO audit_log (actor_id, actor_email, action, target_type, target_id, detail, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`
	err := r.pool.QueryRow(ctx, q, e.ActorID, e.ActorEmail, e.Action, e.TargetType, e.TargetID, e.Detail, e.IP).
		Scan(&e.ID, &e.CreatedAt)
	if err != nil {
		return fmt.Errorf("audit repo: record: %w", err)
	}
	return nil
}

// ListAudit returns entries newest first, narrowed by whichever filter
// fields are set. Limit defaults to 200 and is capped at 1000 so an
// unfiltered view can never accidentally pull the entire table.
func (r *AuditRepository) ListAudit(ctx context.Context, filter domain.AuditFilter) ([]*domain.AuditEntry, error) {
	q := `SELECT id, actor_id, actor_email, action, target_type, target_id, detail, ip, created_at
		FROM audit_log WHERE 1 = 1`
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if strings.TrimSpace(filter.ActorEmail) != "" {
		q += ` AND lower(actor_email) = lower(` + arg(filter.ActorEmail) + `)`
	}
	if strings.TrimSpace(filter.Action) != "" {
		q += ` AND action = ` + arg(filter.Action)
	}
	if !filter.Since.IsZero() {
		q += ` AND created_at >= ` + arg(filter.Since)
	}
	if !filter.Until.IsZero() {
		q += ` AND created_at <= ` + arg(filter.Until)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	q += ` ORDER BY created_at DESC LIMIT ` + arg(limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit repo: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.AuditEntry
	for rows.Next() {
		var e domain.AuditEntry
		if err := rows.Scan(&e.ID, &e.ActorID, &e.ActorEmail, &e.Action, &e.TargetType,
			&e.TargetID, &e.Detail, &e.IP, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit repo: scan: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// DistinctAuditActions lists every action that has ever been recorded, for
// the filter dropdown — it only ever grows, so a plain distinct query is
// cheap enough not to need caching.
func (r *AuditRepository) DistinctAuditActions(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, fmt.Errorf("audit repo: distinct actions: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, fmt.Errorf("audit repo: scan action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
