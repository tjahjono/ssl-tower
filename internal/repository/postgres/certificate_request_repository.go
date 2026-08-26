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

// CertificateRequestRepository persists certificate request tickets.
type CertificateRequestRepository struct {
	pool *pgxpool.Pool
}

// NewCertificateRequestRepository wires the repository to a pool.
func NewCertificateRequestRepository(pool *pgxpool.Pool) *CertificateRequestRepository {
	return &CertificateRequestRepository{pool: pool}
}

var _ domain.CertificateRequestRepository = (*CertificateRequestRepository)(nil)

const certificateRequestColumns = `id, requester_id, requester_email, type, trust_class,
	existing_certificate_id, common_name, dns_names, organization, owner, justification, po_number,
	status, result_certificate_id, root_ca_id, rejection_reason,
	approved_by, approved_at, rejected_by, rejected_at, fulfilled_by, fulfilled_at,
	cancelled_by, cancelled_at, delivered_by, delivered_at, created_at, updated_at`

// Create inserts a newly submitted ticket.
func (r *CertificateRequestRepository) Create(ctx context.Context, c *domain.CertificateRequest) error {
	const q = `
		INSERT INTO certificate_requests (
			requester_id, requester_email, type, trust_class, existing_certificate_id,
			common_name, dns_names, organization, owner, justification, po_number, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q,
		c.RequesterID, c.RequesterEmail, string(c.Type), string(c.TrustClass), c.ExistingCertificateID,
		c.CommonName, nonNil(c.DNSNames), c.Organization, c.Owner, c.Justification, c.PONumber, string(c.Status),
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return fmt.Errorf("certificate request repo: create: %w", err)
	}
	return nil
}

// Update saves a ticket's mutable lifecycle fields — approval, rejection,
// fulfillment, cancellation, and delivery all go through this one method,
// since each just moves the ticket to a new status and stamps the actor and
// timestamp for that transition.
func (r *CertificateRequestRepository) Update(ctx context.Context, c *domain.CertificateRequest) error {
	const q = `
		UPDATE certificate_requests
		SET status = $2, result_certificate_id = $3, root_ca_id = $4, rejection_reason = $5,
		    approved_by = $6, approved_at = $7, rejected_by = $8, rejected_at = $9,
		    fulfilled_by = $10, fulfilled_at = $11, cancelled_by = $12, cancelled_at = $13,
		    delivered_by = $14, delivered_at = $15, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`
	err := r.pool.QueryRow(ctx, q, c.ID, string(c.Status), c.ResultCertificateID, c.RootCAID, c.RejectionReason,
		c.ApprovedBy, c.ApprovedAt, c.RejectedBy, c.RejectedAt,
		c.FulfilledBy, c.FulfilledAt, c.CancelledBy, c.CancelledAt,
		c.DeliveredBy, c.DeliveredAt,
	).Scan(&c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("certificate request repo: update: %w", err)
	}
	return nil
}

// GetByID loads one ticket.
func (r *CertificateRequestRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.CertificateRequest, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+certificateRequestColumns+` FROM certificate_requests WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("certificate request repo: get: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("certificate request repo: get: %w", err)
		}
		return nil, domain.ErrNotFound
	}
	return scanCertificateRequest(rows)
}

// List returns tickets, newest first, optionally filtered. Per the
// confirmed "all tickets" visibility decision, RequesterID is only applied
// when the caller explicitly wants one requester's tickets (e.g. a future
// per-requester view) — every ticket queue in the app today passes it nil.
func (r *CertificateRequestRepository) List(ctx context.Context, f domain.CertificateRequestFilter) ([]*domain.CertificateRequest, error) {
	const q = `
		SELECT ` + certificateRequestColumns + `
		FROM certificate_requests
		WHERE ($1 = '' OR status = $1)
		  AND ($2 = '' OR trust_class = $2)
		  AND ($3::uuid IS NULL OR requester_id = $3)
		  AND ($4 = '' OR common_name ILIKE '%' || $4 || '%'
		       OR requester_email ILIKE '%' || $4 || '%'
		       OR owner ILIKE '%' || $4 || '%')
		ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, string(f.Status), string(f.TrustClass), f.RequesterID, strings.TrimSpace(f.Search))
	if err != nil {
		return nil, fmt.Errorf("certificate request repo: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.CertificateRequest
	for rows.Next() {
		c, err := scanCertificateRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountOpen returns how many tickets are still pending or in progress —
// powers the "Tickets" nav badge.
func (r *CertificateRequestRepository) CountOpen(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT count(*) FROM certificate_requests WHERE status IN ('pending', 'in_progress')
	`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("certificate request repo: count open: %w", err)
	}
	return n, nil
}

func scanCertificateRequest(rows pgx.Rows) (*domain.CertificateRequest, error) {
	var (
		c          domain.CertificateRequest
		reqType    string
		trustClass string
		status     string
	)
	err := rows.Scan(&c.ID, &c.RequesterID, &c.RequesterEmail, &reqType, &trustClass,
		&c.ExistingCertificateID, &c.CommonName, &c.DNSNames, &c.Organization, &c.Owner, &c.Justification, &c.PONumber,
		&status, &c.ResultCertificateID, &c.RootCAID, &c.RejectionReason,
		&c.ApprovedBy, &c.ApprovedAt, &c.RejectedBy, &c.RejectedAt, &c.FulfilledBy, &c.FulfilledAt,
		&c.CancelledBy, &c.CancelledAt, &c.DeliveredBy, &c.DeliveredAt, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("certificate request repo: scan: %w", err)
	}
	c.Type = domain.RequestType(reqType)
	c.TrustClass = domain.CertTrustClass(trustClass)
	c.Status = domain.RequestStatus(status)
	return &c, nil
}
