package domain

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RequestType distinguishes a ticket asking for a brand-new certificate from
// one asking to renew a certificate already in the vault.
type RequestType string

// Request types a ticket can have.
const (
	RequestNew     RequestType = "new"
	RequestRenewal RequestType = "renewal"
)

// Valid reports whether t is a known request type.
func (t RequestType) Valid() bool {
	return t == RequestNew || t == RequestRenewal
}

// Label renders the request type for humans.
func (t RequestType) Label() string {
	if t == RequestRenewal {
		return "Renewal"
	}
	return "New certificate"
}

// RequestStatus tracks a certificate request ticket through its lifecycle.
// Internal and external tickets diverge after approval: an internal ticket
// is approved and signed in one combined action, landing directly on
// RequestFulfilled; an external ticket moves to RequestInProgress while
// procurement happens manually outside the app, and only reaches
// RequestFulfilled once the issued certificate is attached to the ticket.
type RequestStatus string

// Ticket statuses.
const (
	RequestPending    RequestStatus = "pending"
	RequestInProgress RequestStatus = "in_progress"
	RequestFulfilled  RequestStatus = "fulfilled"
	RequestRejected   RequestStatus = "rejected"
	RequestCancelled  RequestStatus = "cancelled"
)

// Label renders the ticket status for humans.
func (s RequestStatus) Label() string {
	switch s {
	case RequestPending:
		return "Pending approval"
	case RequestInProgress:
		return "In progress"
	case RequestFulfilled:
		return "Fulfilled"
	case RequestRejected:
		return "Rejected"
	case RequestCancelled:
		return "Cancelled"
	default:
		return "Unknown"
	}
}

// Open reports whether the ticket still needs attention from an editor or
// admin — the age/SLA indicator only applies while a ticket is open.
func (s RequestStatus) Open() bool {
	return s == RequestPending || s == RequestInProgress
}

// Closed reports whether the ticket has reached a terminal state.
func (s RequestStatus) Closed() bool {
	return !s.Open()
}

// CertificateRequest is a ticket asking editors/admins to issue or renew a
// certificate on a requester's behalf. Requesters never touch key material
// or the certificate vault directly and can never download a certificate —
// approving (and, for internal tickets, signing) or fulfilling (attaching an
// externally-issued certificate) is always done by an editor/admin, who then
// delivers the certificate to the requester by hand, per the v1.2
// self-service workflow.
type CertificateRequest struct {
	ID uuid.UUID

	RequesterID uuid.UUID
	// RequesterEmail is denormalized at submission time, the same way
	// AuditEntry captures ActorEmail, so a ticket stays readable even if the
	// requester's account is later removed.
	RequesterEmail string

	Type RequestType
	// TrustClass is chosen by the requester at submission time and is
	// binding — an approver cannot switch a ticket between internal and
	// external, since the two follow entirely different approval and
	// fulfillment paths. Only TrustInternal and TrustExternal are valid
	// here; a request is never TrustPending.
	TrustClass CertTrustClass

	// ExistingCertificateID targets a renewal at a specific certificate
	// already in the vault, picked by the requester from a list. Nil for a
	// new-certificate request.
	ExistingCertificateID *uuid.UUID

	CommonName    string
	DNSNames      []string
	Organization  string
	Owner         string // team/owner tag, mirrors Certificate.Owner
	Justification string

	// PONumber is required for external tickets — obtained by the
	// requester from the procurement team — and unused for internal ones.
	PONumber string

	Status RequestStatus

	// ResultCertificateID links to the certificate record an approver
	// created or updated while acting on this ticket. The ticket detail
	// page embeds the certificate vault's own CSR/attach/self-sign/
	// sign-with-root-CA forms scoped to this ticket, so fulfilling the
	// ticket and creating or updating the certificate happen as one action.
	ResultCertificateID *uuid.UUID
	// RootCAID records which internal Root CA an internal ticket was signed
	// against, once approved.
	RootCAID *uuid.UUID

	RejectionReason string

	ApprovedBy  *uuid.UUID
	ApprovedAt  *time.Time
	RejectedBy  *uuid.UUID
	RejectedAt  *time.Time
	FulfilledBy *uuid.UUID
	FulfilledAt *time.Time
	CancelledBy *uuid.UUID
	CancelledAt *time.Time
	// DeliveredBy/DeliveredAt record that an editor/admin has manually sent
	// the fulfilled certificate to the requester outside the app — a
	// separate step from Fulfilled so the queue can distinguish "issued"
	// from "actually in the requester's hands".
	DeliveredBy *uuid.UUID
	DeliveredAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// RequiresPO reports whether this ticket needs a procurement PO number —
// true only for external tickets.
func (r *CertificateRequest) RequiresPO() bool {
	return r != nil && r.TrustClass == TrustExternal
}

// Delivered reports whether the certificate has been handed to the
// requester yet.
func (r *CertificateRequest) Delivered() bool {
	return r != nil && r.DeliveredAt != nil
}

// AgeDays is how many whole days this ticket has been open since
// submission — the simple age indicator on the ticket queue.
func (r *CertificateRequest) AgeDays() int {
	if r == nil {
		return 0
	}
	return int(time.Since(r.CreatedAt).Hours() / 24)
}

// OverdueSLA reports whether this ticket has sat open past slaDays since it
// was approved. The SLA clock starts at approval, not submission, because
// approval is the moment an editor/admin actually takes ownership of the
// work — in practice this fires for external tickets sitting in
// RequestInProgress, since an internal ticket is normally approved and
// signed in the same action.
func (r *CertificateRequest) OverdueSLA(slaDays int) bool {
	if r == nil || r.ApprovedAt == nil || !r.Status.Open() {
		return false
	}
	return time.Since(*r.ApprovedAt) > time.Duration(slaDays)*24*time.Hour
}

// Validate normalises and checks a ticket's requester-supplied fields.
// Approval/fulfillment fields are set by the service layer, not validated
// here.
func (r *CertificateRequest) Validate() error {
	r.CommonName = strings.TrimSpace(r.CommonName)
	r.Organization = strings.TrimSpace(r.Organization)
	r.Owner = strings.TrimSpace(r.Owner)
	r.Justification = strings.TrimSpace(r.Justification)
	r.PONumber = strings.TrimSpace(r.PONumber)

	if !r.Type.Valid() {
		return Invalid("type", "request type must be new or renewal")
	}
	if r.Type == RequestRenewal && r.ExistingCertificateID == nil {
		return Invalid("existing_certificate_id", "pick the certificate to renew")
	}
	if r.Type == RequestNew && r.CommonName == "" {
		return Invalid("common_name", "common name is required")
	}
	if r.TrustClass != TrustInternal && r.TrustClass != TrustExternal {
		return Invalid("trust_class", "choose internal or external")
	}
	if r.RequiresPO() && r.PONumber == "" {
		return Invalid("po_number", "a PO number from procurement is required for external certificates")
	}
	return nil
}

// CertificateRequestFilter narrows a ticket listing.
type CertificateRequestFilter struct {
	Status      RequestStatus
	TrustClass  CertTrustClass
	RequesterID *uuid.UUID
	Search      string
}

// CertificateRequestRepository is the persistence port for certificate
// request tickets.
type CertificateRequestRepository interface {
	Create(ctx context.Context, r *CertificateRequest) error
	Update(ctx context.Context, r *CertificateRequest) error
	GetByID(ctx context.Context, id uuid.UUID) (*CertificateRequest, error)
	List(ctx context.Context, f CertificateRequestFilter) ([]*CertificateRequest, error)
	CountOpen(ctx context.Context) (int, error)
}
