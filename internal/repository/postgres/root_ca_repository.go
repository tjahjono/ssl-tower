package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// RootCARepository persists uploaded internal certificate authorities.
type RootCARepository struct {
	pool *pgxpool.Pool
}

// NewRootCARepository wires the repository to a pool.
func NewRootCARepository(pool *pgxpool.Pool) *RootCARepository {
	return &RootCARepository{pool: pool}
}

var _ domain.RootCARepository = (*RootCARepository)(nil)

const rootCAColumns = `id, name, certificate_pem, private_key_pem, private_key_encrypted,
	subject, signature_algorithm, public_key_algorithm, key_size, fingerprint_sha256,
	not_before, not_after, created_at, updated_at`

// Create inserts a newly uploaded Root CA.
func (r *RootCARepository) Create(ctx context.Context, c *domain.RootCA) error {
	const q = `
		INSERT INTO root_cas (
			name, certificate_pem, private_key_pem, private_key_encrypted,
			subject, signature_algorithm, public_key_algorithm, key_size,
			fingerprint_sha256, not_before, not_after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q,
		c.Name, c.CertificatePEM, c.PrivateKeyPEM, c.PrivateKeyEncrypted,
		c.Subject, c.SignatureAlgorithm, c.PublicKeyAlgorithm, c.KeySize,
		c.FingerprintSHA256, c.NotBefore, c.NotAfter,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%s: %w", c.Name, domain.ErrConflict)
		}
		return fmt.Errorf("root ca repo: create: %w", err)
	}
	return nil
}

// Delete removes a Root CA record and its key material. Certificates it
// already signed are untouched — see the migration's ON DELETE SET NULL.
func (r *RootCARepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM root_cas WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("root ca repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// GetByID loads one Root CA.
func (r *RootCARepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.RootCA, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+rootCAColumns+` FROM root_cas WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("root ca repo: get: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("root ca repo: get: %w", err)
		}
		return nil, domain.ErrNotFound
	}
	return scanRootCA(rows)
}

// List returns every uploaded Root CA, newest first.
func (r *RootCARepository) List(ctx context.Context) ([]*domain.RootCA, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+rootCAColumns+` FROM root_cas ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("root ca repo: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.RootCA
	for rows.Next() {
		c, err := scanRootCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanRootCA(rows pgx.Rows) (*domain.RootCA, error) {
	var c domain.RootCA
	err := rows.Scan(&c.ID, &c.Name, &c.CertificatePEM, &c.PrivateKeyPEM, &c.PrivateKeyEncrypted,
		&c.Subject, &c.SignatureAlgorithm, &c.PublicKeyAlgorithm, &c.KeySize, &c.FingerprintSHA256,
		&c.NotBefore, &c.NotAfter, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("root ca repo: scan: %w", err)
	}
	return &c, nil
}
