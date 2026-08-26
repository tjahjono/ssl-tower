package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
)

// requestColor is the Teams MessageCard accent used for every ticket
// notification — a steady blue distinct from AlertLevel's severity colors,
// since a ticket update is informational, not a health warning.
const requestColor = "0EA5E9"

// CertificateRequestService implements the v1.2 self-service ticket
// workflow: a requester submits a ticket for a new or renewed certificate,
// and an editor/admin approves (and, for an internal ticket, signs in the
// same action) or rejects it. An external ticket instead moves to "in
// progress" on approval, since procurement with an outside CA happens
// manually, and is only fulfilled once the issued certificate is attached.
// Requesters never touch the certificate vault directly; CertificateService
// does the actual key/certificate work underneath every approval and
// fulfillment call here — this service only owns the ticket's own
// lifecycle and bookkeeping.
type CertificateRequestService struct {
	repo    domain.CertificateRequestRepository
	certs   *CertificateService
	email   *notify.EmailNotifier
	teams   *notify.TeamsNotifier
	log     *slog.Logger
	slaDays int
}

// NewCertificateRequestService builds the service. email and teams may be
// notifiers built from empty configuration, exactly as AlertService uses
// them — Send/Enabled on both handle that as a no-op.
func NewCertificateRequestService(repo domain.CertificateRequestRepository, certs *CertificateService, email *notify.EmailNotifier, teams *notify.TeamsNotifier, log *slog.Logger, slaDays int) *CertificateRequestService {
	if slaDays <= 0 {
		slaDays = 3
	}
	return &CertificateRequestService{repo: repo, certs: certs, email: email, teams: teams, log: log, slaDays: slaDays}
}

// SLADays exposes the configured SLA window for display on the ticket queue.
func (s *CertificateRequestService) SLADays() int { return s.slaDays }

// SubmitInput is the requester-facing ticket submission form.
type SubmitInput struct {
	RequesterID    uuid.UUID
	RequesterEmail string

	Type                  domain.RequestType
	TrustClass            domain.CertTrustClass
	ExistingCertificateID *uuid.UUID

	CommonName    string
	SANs          string // newline/comma separated, same convention as CreateCSRInput.SANs
	Organization  string
	Owner         string
	Justification string
	PONumber      string
}

// Submit records a new ticket. A renewal must name a certificate already in
// the vault; common name/organization are backfilled from it when the
// requester leaves them blank, purely as a convenience — the approver fills
// in the authoritative CSR fields later, when actually fulfilling the ticket.
func (s *CertificateRequestService) Submit(ctx context.Context, in SubmitInput) (*domain.CertificateRequest, error) {
	dnsNames, ips := splitSANs(in.SANs)

	r := &domain.CertificateRequest{
		RequesterID:           in.RequesterID,
		RequesterEmail:        strings.TrimSpace(in.RequesterEmail),
		Type:                  in.Type,
		TrustClass:            in.TrustClass,
		ExistingCertificateID: in.ExistingCertificateID,
		CommonName:            in.CommonName,
		DNSNames:              append(dnsNames, ips...),
		Organization:          in.Organization,
		Owner:                 in.Owner,
		Justification:         in.Justification,
		PONumber:              in.PONumber,
		Status:                domain.RequestPending,
	}

	if r.Type == domain.RequestRenewal && r.ExistingCertificateID != nil {
		existing, err := s.certs.Get(ctx, *r.ExistingCertificateID)
		if err != nil {
			return nil, domain.Invalid("existing_certificate_id", "the certificate you picked to renew could not be found")
		}
		if r.CommonName == "" {
			r.CommonName = existing.CommonName
		}
		if r.Organization == "" {
			r.Organization = existing.Organization
		}
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, r); err != nil {
		return nil, err
	}

	s.notify(ctx, fmt.Sprintf("New certificate request: %s", r.CommonName),
		fmt.Sprintf("%s requested a %s %s certificate for %s.%s",
			r.RequesterEmail, r.TrustClass.Label(), strings.ToLower(r.Type.Label()), r.CommonName, justificationSuffix(r.Justification)))
	return r, nil
}

// Get loads one ticket.
func (s *CertificateRequestService) Get(ctx context.Context, id uuid.UUID) (*domain.CertificateRequest, error) {
	return s.repo.GetByID(ctx, id)
}

// List returns tickets, optionally filtered.
func (s *CertificateRequestService) List(ctx context.Context, f domain.CertificateRequestFilter) ([]*domain.CertificateRequest, error) {
	return s.repo.List(ctx, f)
}

// CountOpen returns how many tickets are still pending or in progress.
func (s *CertificateRequestService) CountOpen(ctx context.Context) (int, error) {
	return s.repo.CountOpen(ctx)
}

// loadOpen loads a ticket and confirms it is still open (pending or in
// progress) — the shared guard every mutating action below starts with.
func (s *CertificateRequestService) loadPending(ctx context.Context, id uuid.UUID) (*domain.CertificateRequest, error) {
	r, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Status != domain.RequestPending {
		return nil, domain.Invalid("status", "this ticket is no longer pending")
	}
	return r, nil
}

// ApproveInternalInput approves and signs an internal ticket in one action —
// the "combined" approval flow: the approver fills in the CSR fields (the
// same form the certificate vault's own "Generate" page uses, pre-filled
// from the ticket) and picks a Root CA, and a single submission both mints
// the certificate and fulfills the ticket.
type ApproveInternalInput struct {
	TicketID   uuid.UUID
	ApproverID uuid.UUID
	CSR        CreateCSRInput
	RootCAID   uuid.UUID
	Days       int
}

// ApproveInternal signs an internal ticket's certificate against a Root CA
// and fulfills the ticket in the same action.
func (s *CertificateRequestService) ApproveInternal(ctx context.Context, in ApproveInternalInput) (*domain.CertificateRequest, *domain.Certificate, error) {
	r, err := s.loadPending(ctx, in.TicketID)
	if err != nil {
		return nil, nil, err
	}
	if r.TrustClass != domain.TrustInternal {
		return nil, nil, domain.Invalid("trust_class", "this ticket is external — approve it from the external flow instead")
	}

	cert, err := s.certs.CreateCSR(ctx, in.CSR)
	if err != nil {
		return nil, nil, err
	}
	signed, err := s.certs.SignWithRootCA(ctx, cert.ID, in.RootCAID, in.Days)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	r.ApprovedBy = &in.ApproverID
	r.ApprovedAt = &now
	r.ResultCertificateID = &signed.ID
	rootCAID := in.RootCAID
	r.RootCAID = &rootCAID
	r.FulfilledBy = &in.ApproverID
	r.FulfilledAt = &now
	r.Status = domain.RequestFulfilled
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, nil, err
	}

	s.notify(ctx, fmt.Sprintf("Certificate request fulfilled: %s", r.CommonName),
		fmt.Sprintf("%s approved and signed %s for %s, valid until %s. Deliver the certificate to the requester by hand.",
			r.RequesterEmail, signed.CommonName, r.RequesterEmail, signed.ExpiresIn()))
	return r, signed, nil
}

// ApproveExternalInput approves an external ticket, moving it into progress
// while procurement with an outside CA happens manually.
type ApproveExternalInput struct {
	TicketID   uuid.UUID
	ApproverID uuid.UUID
}

// ApproveExternal moves an external ticket from pending to in-progress.
// Nothing is signed here — an external certificate is bought from a public
// CA outside this app, using the requester's PO number, and only comes back
// into the app when FulfillExternal attaches it.
func (s *CertificateRequestService) ApproveExternal(ctx context.Context, in ApproveExternalInput) (*domain.CertificateRequest, error) {
	r, err := s.loadPending(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	if r.TrustClass != domain.TrustExternal {
		return nil, domain.Invalid("trust_class", "this ticket is internal — approve it from the internal flow instead")
	}

	now := time.Now().UTC()
	r.ApprovedBy = &in.ApproverID
	r.ApprovedAt = &now
	r.Status = domain.RequestInProgress
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, err
	}

	s.notify(ctx, fmt.Sprintf("Certificate request approved: %s", r.CommonName),
		fmt.Sprintf("%s's request for %s was approved and is now in progress with the external CA (PO %s).",
			r.RequesterEmail, r.CommonName, r.PONumber))
	return r, nil
}

// FulfillExternalInput attaches the certificate a public CA issued, closing
// out an in-progress external ticket.
type FulfillExternalInput struct {
	TicketID   uuid.UUID
	ApproverID uuid.UUID
	Import     ImportInput
}

// FulfillExternal attaches the externally-issued certificate to the ticket
// and fulfills it. Per the confirmed workflow, attaching the certificate is
// what closes an external ticket.
func (s *CertificateRequestService) FulfillExternal(ctx context.Context, in FulfillExternalInput) (*domain.CertificateRequest, *domain.Certificate, error) {
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, nil, err
	}
	if r.TrustClass != domain.TrustExternal {
		return nil, nil, domain.Invalid("trust_class", "this ticket is internal — fulfill it from the internal flow instead")
	}
	if r.Status != domain.RequestInProgress {
		return nil, nil, domain.Invalid("status", "approve this ticket before attaching a certificate")
	}

	in.Import.Owner = r.Owner
	cert, err := s.certs.Import(ctx, in.Import)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	r.ResultCertificateID = &cert.ID
	r.FulfilledBy = &in.ApproverID
	r.FulfilledAt = &now
	r.Status = domain.RequestFulfilled
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, nil, err
	}

	s.notify(ctx, fmt.Sprintf("Certificate request fulfilled: %s", r.CommonName),
		fmt.Sprintf("The certificate for %s has been attached and the ticket is fulfilled. Deliver it to %s by hand.",
			r.CommonName, r.RequesterEmail))
	return r, cert, nil
}

// RejectInput rejects a still-pending ticket.
type RejectInput struct {
	TicketID uuid.UUID
	ActorID  uuid.UUID
	Reason   string
}

// Reject closes a pending ticket without issuing anything.
func (s *CertificateRequestService) Reject(ctx context.Context, in RejectInput) (*domain.CertificateRequest, error) {
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return nil, domain.Invalid("reason", "a rejection reason is required")
	}
	r, err := s.loadPending(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	r.RejectedBy = &in.ActorID
	r.RejectedAt = &now
	r.RejectionReason = reason
	r.Status = domain.RequestRejected
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, err
	}

	s.notify(ctx, fmt.Sprintf("Certificate request rejected: %s", r.CommonName),
		fmt.Sprintf("%s's request for %s was rejected: %s", r.RequesterEmail, r.CommonName, reason))
	return r, nil
}

// CancelInput cancels a still-open ticket.
type CancelInput struct {
	TicketID uuid.UUID
	ActorID  uuid.UUID
}

// Cancel closes an open (pending or in-progress) ticket at the requester's
// or an editor/admin's request, before it was fulfilled.
func (s *CertificateRequestService) Cancel(ctx context.Context, in CancelInput) (*domain.CertificateRequest, error) {
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	if !r.Status.Open() {
		return nil, domain.Invalid("status", "only an open ticket can be cancelled")
	}

	now := time.Now().UTC()
	r.CancelledBy = &in.ActorID
	r.CancelledAt = &now
	r.Status = domain.RequestCancelled
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, err
	}

	s.notify(ctx, fmt.Sprintf("Certificate request cancelled: %s", r.CommonName),
		fmt.Sprintf("The request for %s was cancelled.", r.CommonName))
	return r, nil
}

// DeliverInput marks a fulfilled ticket's certificate as handed to the
// requester.
type DeliverInput struct {
	TicketID uuid.UUID
	ActorID  uuid.UUID
}

// Deliver records that an editor/admin has manually sent the fulfilled
// certificate to the requester — no certificate is ever downloadable by the
// requester themselves, so this is the app's only record that the loop was
// actually closed.
func (s *CertificateRequestService) Deliver(ctx context.Context, in DeliverInput) (*domain.CertificateRequest, error) {
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	if r.Status != domain.RequestFulfilled {
		return nil, domain.Invalid("status", "only a fulfilled ticket can be marked delivered")
	}
	if r.Delivered() {
		return nil, domain.Invalid("status", "this ticket is already marked delivered")
	}

	now := time.Now().UTC()
	r.DeliveredBy = &in.ActorID
	r.DeliveredAt = &now
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}

// notify fans one ticket update out to every configured channel, exactly as
// AlertService.notify does — a broken channel is logged and otherwise
// ignored, never allowed to fail the ticket action itself.
func (s *CertificateRequestService) notify(ctx context.Context, subject, body string) {
	if s.email.Enabled() {
		if err := s.email.Send(subject, body); err != nil {
			s.log.Warn("ticket: email send failed", "error", err)
		}
	}
	if s.teams.Enabled() {
		if err := s.teams.Send(ctx, subject, body, requestColor); err != nil {
			s.log.Warn("ticket: teams send failed", "error", err)
		}
	}
}

func justificationSuffix(justification string) string {
	if justification == "" {
		return ""
	}
	return " Justification: " + justification
}
