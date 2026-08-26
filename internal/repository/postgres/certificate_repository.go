package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// CertificateRepository persists the certificate vault: signing requests
// generated in-app and certificates uploaded directly, unified into one
// table since Phase 10.
type CertificateRepository struct {
	pool *pgxpool.Pool
}

// NewCertificateRepository wires the repository to a pool.
func NewCertificateRepository(pool *pgxpool.Pool) *CertificateRepository {
	return &CertificateRepository{pool: pool}
}

var _ domain.CertificateRepository = (*CertificateRepository)(nil)

const certificateColumns = `id, common_name, organization, organizational_unit, country, province,
	locality, email, dns_names, ip_addresses, origin, owner, key_algorithm, key_bits, key_curve,
	csr_pem, private_key_pem, private_key_encrypted, certificate_pem, chain_pem, self_signed,
	signed_by_root_ca_id, subject, issuer, signature_algorithm, public_key_algorithm, key_size,
	chain_length, fingerprint_sha256, ext_key_usage, not_before, not_after, status, notes,
	created_at, updated_at`

// Create inserts a new certificate record.
func (r *CertificateRepository) Create(ctx context.Context, c *domain.Certificate) error {
	const q = `
		INSERT INTO certificates (
			common_name, organization, organizational_unit, country, province, locality,
			email, dns_names, ip_addresses, origin, owner, key_algorithm, key_bits, key_curve,
			csr_pem, private_key_pem, private_key_encrypted, certificate_pem, chain_pem,
			self_signed, subject, issuer, signature_algorithm, public_key_algorithm, key_size,
			chain_length, fingerprint_sha256, ext_key_usage, not_before, not_after, status, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
		        $23,$24,$25,$26,$27,$28,$29,$30,$31,$32)
		RETURNING id, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q,
		c.CommonName, c.Organization, c.OrganizationalUnit, c.Country, c.Province, c.Locality,
		c.Email, nonNil(c.DNSNames), nonNil(c.IPAddresses), string(c.Origin), c.Owner,
		c.KeyAlgorithm, c.KeyBits, c.KeyCurve, c.CSRPEM, c.PrivateKeyPEM, c.PrivateKeyEncrypted,
		c.CertificatePEM, c.ChainPEM, c.SelfSigned, c.Subject, c.Issuer, c.SignatureAlgorithm,
		c.PublicKeyAlgorithm, c.KeySize, c.ChainLength, c.FingerprintSHA256, nonNil(c.ExtKeyUsage),
		c.NotBefore, c.NotAfter, string(c.Status), c.Notes,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return fmt.Errorf("certificate repo: create: %w", err)
	}
	return nil
}

// Update saves the mutable fields — in practice the issued certificate
// arriving for a pending request, or a note/owner edit.
func (r *CertificateRepository) Update(ctx context.Context, c *domain.Certificate) error {
	const q = `
		UPDATE certificates
		SET certificate_pem = $2, chain_pem = $3, self_signed = $4, subject = $5, issuer = $6,
		    signature_algorithm = $7, public_key_algorithm = $8, key_size = $9, chain_length = $10,
		    fingerprint_sha256 = $11, ext_key_usage = $12, not_before = $13, not_after = $14,
		    status = $15, notes = $16, owner = $17, signed_by_root_ca_id = $18, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`
	err := r.pool.QueryRow(ctx, q, c.ID, c.CertificatePEM, c.ChainPEM, c.SelfSigned, c.Subject,
		c.Issuer, c.SignatureAlgorithm, c.PublicKeyAlgorithm, c.KeySize, c.ChainLength,
		c.FingerprintSHA256, nonNil(c.ExtKeyUsage), c.NotBefore, c.NotAfter, string(c.Status), c.Notes, c.Owner,
		c.SignedByRootCAID,
	).Scan(&c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("certificate repo: update: %w", err)
	}
	return nil
}

// Delete removes a certificate record and its key material.
func (r *CertificateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("certificate repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// GetByID loads one certificate.
func (r *CertificateRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Certificate, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+certificateColumns+` FROM certificates WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("certificate repo: get: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("certificate repo: get: %w", err)
		}
		return nil, domain.ErrNotFound
	}
	return scanCertificate(rows)
}

// List returns certificates, newest first, optionally filtered.
func (r *CertificateRepository) List(ctx context.Context, f domain.CertificateFilter) ([]*domain.Certificate, error) {
	const q = `
		SELECT ` + certificateColumns + `
		FROM certificates
		WHERE ($1 = '' OR common_name ILIKE '%' || $1 || '%'
		       OR array_to_string(dns_names, ',') ILIKE '%' || $1 || '%'
		       OR owner ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR status = $2)
		  AND ($3 = '' OR origin = $3)
		  AND ($4 = '' OR (
		        certificate_pem <> '' AND (
		          ($4 = 'internal' AND (self_signed OR signed_by_root_ca_id IS NOT NULL)) OR
		          ($4 = 'external' AND NOT self_signed AND signed_by_root_ca_id IS NULL)
		        )
		      ))
		ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, strings.TrimSpace(f.Search), string(f.Status), string(f.Origin), f.Trust)
	if err != nil {
		return nil, fmt.Errorf("certificate repo: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FindSharingFingerprint returns other certificates already on file with the
// same SHA-256 fingerprint — the same certificate uploaded or generated more
// than once.
func (r *CertificateRepository) FindSharingFingerprint(ctx context.Context, fingerprint string, excludeID uuid.UUID) ([]*domain.Certificate, error) {
	if strings.TrimSpace(fingerprint) == "" {
		return nil, nil
	}
	q := `SELECT ` + certificateColumns + `
		FROM certificates
		WHERE id <> $1 AND fingerprint_sha256 = $2
		ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, excludeID, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("certificate repo: find sharing fingerprint: %w", err)
	}
	defer rows.Close()

	var out []*domain.Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AlertLevel returns the level last notified for this certificate (0 if none
// has been sent, or it doesn't exist).
func (r *CertificateRepository) AlertLevel(ctx context.Context, id uuid.UUID) (int, error) {
	var level int
	err := r.pool.QueryRow(ctx, `SELECT last_alert_level FROM certificates WHERE id = $1`, id).Scan(&level)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("certificate repo: alert level: %w", err)
	}
	return level, nil
}

// SetAlertLevel records the level just notified for this certificate.
func (r *CertificateRepository) SetAlertLevel(ctx context.Context, id uuid.UUID, level int) error {
	if _, err := r.pool.Exec(ctx, `UPDATE certificates SET last_alert_level = $1 WHERE id = $2`, level, id); err != nil {
		return fmt.Errorf("certificate repo: set alert level: %w", err)
	}
	return nil
}

func scanCertificate(rows pgx.Rows) (*domain.Certificate, error) {
	var (
		c      domain.Certificate
		origin string
		status string
	)
	err := rows.Scan(&c.ID, &c.CommonName, &c.Organization, &c.OrganizationalUnit, &c.Country,
		&c.Province, &c.Locality, &c.Email, &c.DNSNames, &c.IPAddresses, &origin, &c.Owner,
		&c.KeyAlgorithm, &c.KeyBits, &c.KeyCurve, &c.CSRPEM, &c.PrivateKeyPEM, &c.PrivateKeyEncrypted,
		&c.CertificatePEM, &c.ChainPEM, &c.SelfSigned, &c.SignedByRootCAID, &c.Subject, &c.Issuer,
		&c.SignatureAlgorithm, &c.PublicKeyAlgorithm, &c.KeySize, &c.ChainLength, &c.FingerprintSHA256,
		&c.ExtKeyUsage, &c.NotBefore, &c.NotAfter, &status, &c.Notes, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("certificate repo: scan: %w", err)
	}
	c.Origin = domain.CertOrigin(origin)
	c.Status = domain.CertLifecycle(status)
	return &c, nil
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
