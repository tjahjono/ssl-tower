package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// SiteContentRepository persists admin-editable rich-text page content.
type SiteContentRepository struct {
	pool *pgxpool.Pool
}

// NewSiteContentRepository wires the repository to a pool.
func NewSiteContentRepository(pool *pgxpool.Pool) *SiteContentRepository {
	return &SiteContentRepository{pool: pool}
}

var _ domain.SiteContentRepository = (*SiteContentRepository)(nil)

// GetSiteContent returns (nil, nil) when no row exists for key yet — that's
// the normal, expected state until an admin saves their first edit.
func (r *SiteContentRepository) GetSiteContent(ctx context.Context, key string) (*domain.SiteContent, error) {
	const q = `SELECT key, content, updated_at, updated_by FROM site_content WHERE key = $1`
	var c domain.SiteContent
	err := r.pool.QueryRow(ctx, q, key).Scan(&c.Key, &c.Content, &c.UpdatedAt, &c.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("site content repo: get: %w", err)
	}
	return &c, nil
}

// SetSiteContent upserts the content for key.
func (r *SiteContentRepository) SetSiteContent(ctx context.Context, key, content, updatedBy string) (*domain.SiteContent, error) {
	const q = `INSERT INTO site_content (key, content, updated_by, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (key) DO UPDATE SET
			content = EXCLUDED.content,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()
		RETURNING key, content, updated_at, updated_by`
	var c domain.SiteContent
	if err := r.pool.QueryRow(ctx, q, key, content, updatedBy).Scan(&c.Key, &c.Content, &c.UpdatedAt, &c.UpdatedBy); err != nil {
		return nil, fmt.Errorf("site content repo: set: %w", err)
	}
	return &c, nil
}
