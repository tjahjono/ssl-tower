package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
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
	repo     domain.CertificateRequestRepository
	certs    *CertificateService
	settings *SettingsService
	log      *slog.Logger
}

// NewCertificateRequestService builds the service. Email/Teams notifiers and
// the SLA window are read live from settings at the point of use (see
// notify, SLADays, EmailReady) rather than held as fixed fields — same
// "reconstruct fresh from settings on every use" pattern AlertService uses,
// so an admin's SMTP/Teams/SLA change in the portal takes effect on the very
// next ticket action, no restart needed.
func NewCertificateRequestService(repo domain.CertificateRequestRepository, certs *CertificateService, settings *SettingsService, log *slog.Logger) *CertificateRequestService {
	return &CertificateRequestService{repo: repo, certs: certs, settings: settings, log: log}
}

// SLADays exposes the configured SLA window for display on the ticket queue.
func (s *CertificateRequestService) SLADays() int {
	if days := s.settings.Current().TicketSLADays; days > 0 {
		return days
	}
	return 3
}

// EmailReady reports whether enough SMTP configuration is present to attempt
// SendCertificateEmail — used by the ticket detail page to explain why the
// "send by email" form is unavailable rather than just letting it fail.
func (s *CertificateRequestService) EmailReady() bool { return s.settings.EmailNotifier().TransportReady() }

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
		// The requests page renders separate internal/external certificate
		// pickers kept in sync with the trust_class radio purely via CSS
		// (data-show-when) — a client can't be trusted to only ever submit a
		// consistent combination of the two, so the actual trust class of
		// the chosen certificate is re-checked here.
		if existing.TrustClass() != r.TrustClass {
			return nil, domain.Invalid("existing_certificate_id", "that certificate's trust class doesn't match the trust class chosen above")
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
//
// ReuseExistingCSR is renewal-only: instead of CSR minting a fresh key pair
// via CreateCSR, the certificate named by the ticket's ExistingCertificateID
// has its CSR and private key cloned verbatim into the new record (see
// CertificateService.CloneCSR) — same public key, same subject/SAN/EKU,
// just re-signed with a new serial/validity. CSR is ignored when this is
// true.
type ApproveInternalInput struct {
	TicketID         uuid.UUID
	ApproverID       uuid.UUID
	ReuseExistingCSR bool
	CSR              CreateCSRInput
	RootCAID         uuid.UUID
	Days             int
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

	var cert *domain.Certificate
	if in.ReuseExistingCSR {
		if r.Type != domain.RequestRenewal || r.ExistingCertificateID == nil {
			return nil, nil, domain.Invalid("reuse_existing_csr", "only a renewal ticket naming an existing certificate can reuse its CSR")
		}
		cert, err = s.certs.CloneCSR(ctx, CloneCSRInput{
			SourceCertificateID: *r.ExistingCertificateID,
			Owner:               in.CSR.Owner,
			Notes:               fmt.Sprintf("Renewal of certificate %s via ticket %s (same CSR/key reused)", *r.ExistingCertificateID, r.ID),
		})
	} else {
		cert, err = s.certs.CreateCSR(ctx, in.CSR)
	}
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

// GenerateCSRInput is the manual "Generate a CSR" ticket action — an
// in-progress external ticket's own counterpart to DigiCertSubmitInput, but
// without calling any outside API: it only mints a key pair and CSR for the
// admin to submit to whichever CA the ticket's PO number is with, by hand.
type GenerateCSRInput struct {
	TicketID           uuid.UUID
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	Email              string
	SANs               string
	ExtKeyUsages       []string
	KeyAlgorithm       string
	KeyBits            int
	KeyCurve           string
	Notes              string // appended to the auto-generated ticket cross-reference note
}

// GenerateCSR mints a key pair and CSR for an in-progress external ticket
// and records the resulting vault record on the ticket's
// PendingCertificateID — the same field DigiCertService.Submit uses, so
// FulfillExternal treats a manually-generated CSR exactly like a
// DigiCert-submitted one: whatever certificate the external CA eventually
// returns gets attached to this same record (matching the stored private
// key) instead of being imported as a separate one.
//
// Unlike DigiCert submission, which only ever applies to a renewal (it seeds
// the CSR from the certificate being renewed), this is available for a
// brand-new external certificate too — there being no existing certificate
// to copy from just means the admin fills the subject fields by hand,
// prefilled from the ticket the same way ApproveInternal's form prefills
// from an internal ticket.
func (s *CertificateRequestService) GenerateCSR(ctx context.Context, in GenerateCSRInput) (*domain.CertificateRequest, *domain.Certificate, error) {
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, nil, err
	}
	if r.TrustClass != domain.TrustExternal {
		return nil, nil, domain.Invalid("trust_class", "CSR generation only applies to external tickets")
	}
	if r.Status != domain.RequestInProgress {
		return nil, nil, domain.Invalid("status", "approve this ticket before generating a CSR")
	}
	if r.PendingCertificateID != nil {
		return nil, nil, domain.Invalid("status", "a CSR has already been generated for this ticket")
	}

	note := fmt.Sprintf("Generated for certificate request ticket %s (PO %s).", r.ID, r.PONumber)
	if extra := strings.TrimSpace(in.Notes); extra != "" {
		note = note + " " + extra
	}
	pending, err := s.certs.CreateCSR(ctx, CreateCSRInput{
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Country:            in.Country,
		Province:           in.Province,
		Locality:           in.Locality,
		Email:              in.Email,
		SANs:               in.SANs,
		ExtKeyUsages:       in.ExtKeyUsages,
		KeyAlgorithm:       in.KeyAlgorithm,
		KeyBits:            in.KeyBits,
		KeyCurve:           in.KeyCurve,
		Owner:              r.Owner,
		Notes:              note,
	})
	if err != nil {
		return nil, nil, err
	}

	pendingID := pending.ID
	r.PendingCertificateID = &pendingID
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, nil, err
	}
	return r, pending, nil
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
//
// If a CSR was already generated for this ticket — via GenerateCSR below, or
// an earlier DigiCert submission — PendingCertificateID names the vault
// record already holding that key pair, and the pasted certificate is
// attached to that same record (matching it to the stored private key)
// instead of being imported as a brand-new one; a private key pasted
// alongside it in that case is simply unused, since one is already on file.
// Otherwise this falls back to the original manual flow: Import creates a
// fresh record from whatever certificate/chain/key the admin pasted.
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

	var cert *domain.Certificate
	if r.PendingCertificateID != nil {
		blob := strings.TrimSpace(in.Import.CertificatePEM) + "\n" + in.Import.ChainPEM
		cert, err = s.certs.AttachCertificate(ctx, *r.PendingCertificateID, blob)
		if err != nil {
			return nil, nil, err
		}
	} else {
		in.Import.Owner = r.Owner
		cert, err = s.certs.Import(ctx, in.Import)
		if err != nil {
			return nil, nil, err
		}
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

// SendCertificateEmailInput is the ticket detail page's "send by email" form.
// IncludeKey must already be resolved to a real decision by the caller (the
// http handler zeroes it for anyone who isn't CanManageUsers(), exactly
// mirroring handleCertificateDownload's own admin-vs-editor gate) — this
// service trusts the value it's given rather than re-checking a role it has
// no notion of.
type SendCertificateEmailInput struct {
	TicketID   uuid.UUID
	ActorID    uuid.UUID
	Format     string
	Recipient  string
	IncludeKey bool
}

// SendCertificateEmail exports the ticket's result certificate and emails it
// directly to the given recipient — the alternative to the existing
// "download it, then hand it over by hand" flow. A successful send also
// closes the delivery loop automatically: emailing the certificate to the
// requester *is* handing it over, so this sets DeliveredBy/DeliveredAt the
// same way a manual "Mark delivered" click does, unless the ticket is
// already marked delivered. The plain "Mark delivered" button stays
// available for the out-of-band case (handed over in person, posted
// elsewhere, etc.).
func (s *CertificateRequestService) SendCertificateEmail(ctx context.Context, in SendCertificateEmailInput) (*domain.CertificateRequest, error) {
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	if r.ResultCertificateID == nil {
		return nil, domain.Invalid("status", "this ticket has no certificate to send yet")
	}
	recipient := strings.TrimSpace(in.Recipient)
	if recipient == "" {
		return nil, domain.Invalid("recipient", "a recipient email address is required")
	}
	email := s.settings.EmailNotifier()
	if !email.TransportReady() {
		return nil, domain.Invalid("email", "email isn't configured on this server — set SMTP_HOST and ALERT_EMAIL_FROM")
	}

	result, err := s.certs.Export(ctx, *r.ResultCertificateID, ExportOptions{Format: in.Format})
	if err != nil {
		return nil, fmt.Errorf("export certificate: %w", err)
	}
	attachments := []notify.Attachment{{Filename: result.Filename, ContentType: result.ContentType, Data: result.Data}}
	if in.IncludeKey {
		keyResult, err := s.certs.Export(ctx, *r.ResultCertificateID, ExportOptions{Format: certutil.FormatKEY})
		if err != nil {
			return nil, fmt.Errorf("export private key: %w", err)
		}
		attachments = append(attachments, notify.Attachment{Filename: keyResult.Filename, ContentType: keyResult.ContentType, Data: keyResult.Data})
	}

	subject := fmt.Sprintf("Your certificate: %s", r.CommonName)
	body := fmt.Sprintf(
		"Attached is the certificate you requested for %s.\n\nRequest ticket: %s\n\nThis was sent automatically by SSL Tower — reply to your usual contact there if anything looks wrong.",
		r.CommonName, r.ID,
	)
	if err := email.SendWithAttachment([]string{recipient}, subject, body, attachments...); err != nil {
		return nil, fmt.Errorf("send email: %w", err)
	}

	if r.Status == domain.RequestFulfilled && !r.Delivered() {
		now := time.Now().UTC()
		r.DeliveredBy = &in.ActorID
		r.DeliveredAt = &now
		if err := s.repo.Update(ctx, r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// AutoDraftRenewals scans every issued internal certificate approaching (or
// past) expiry and, for each one that can be traced back to the ticket that
// originally produced it and doesn't already have an open renewal ticket,
// creates a new pending renewal ticket on that requester's behalf —
// AutoGenerated, so the ticket queue can tell it apart from one a requester
// actually typed. It returns how many tickets were drafted.
//
// Scoped to internal certificates only: external renewal (DigiCert, a later
// phase) is deliberately an explicit admin click, not something a sweeper
// should submit to a paid CA unattended. A certificate with no resolvable
// origin ticket — generated directly in the vault, say — has no requester
// to draft a ticket for and is silently skipped; that's an accepted gap,
// not a bug, since there's nobody to notify in that case anyway.
func (s *CertificateRequestService) AutoDraftRenewals(ctx context.Context) (int, error) {
	certs, err := s.certs.List(ctx, domain.CertificateFilter{Status: domain.CertIssued, Trust: string(domain.TrustInternal)})
	if err != nil {
		return 0, fmt.Errorf("auto-draft renewals: list certificates: %w", err)
	}
	warningDays, criticalDays := s.certs.Thresholds()
	warningPct, criticalPct := s.certs.PercentThresholds()

	drafted := 0
	for _, c := range certs {
		if c.HealthStatus(warningDays, criticalDays, warningPct, criticalPct) == domain.StatusOK {
			continue
		}

		origin, err := s.repo.LatestByResultCertificateID(ctx, c.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return drafted, fmt.Errorf("auto-draft renewals: find origin ticket for %s: %w", c.ID, err)
		}

		open, err := s.repo.HasOpenRenewalFor(ctx, c.ID)
		if err != nil {
			return drafted, fmt.Errorf("auto-draft renewals: check existing renewal for %s: %w", c.ID, err)
		}
		if open {
			continue
		}

		certID := c.ID
		r := &domain.CertificateRequest{
			RequesterID:           origin.RequesterID,
			RequesterEmail:        origin.RequesterEmail,
			Type:                  domain.RequestRenewal,
			TrustClass:            domain.TrustInternal,
			ExistingCertificateID: &certID,
			CommonName:            c.CommonName,
			DNSNames:              append(append([]string{}, c.DNSNames...), c.IPAddresses...),
			Organization:          c.Organization,
			Owner:                 c.Owner,
			Justification:         fmt.Sprintf("Auto-drafted — certificate expires in %s.", c.ExpiresIn()),
			Status:                domain.RequestPending,
			AutoGenerated:         true,
		}
		if err := r.Validate(); err != nil {
			s.log.Warn("auto-draft renewals: drafted ticket failed validation, skipping", "certificate", c.ID, "error", err)
			continue
		}
		if err := s.repo.Create(ctx, r); err != nil {
			return drafted, fmt.Errorf("auto-draft renewals: create ticket for %s: %w", c.ID, err)
		}
		drafted++

		s.notify(ctx, fmt.Sprintf("Renewal ticket auto-drafted: %s", r.CommonName),
			fmt.Sprintf("%s's certificate for %s is approaching expiry (%s) — a renewal ticket has been auto-drafted on their behalf.",
				r.RequesterEmail, r.CommonName, c.ExpiresIn()))
	}
	return drafted, nil
}

// notify fans one ticket update out to every configured channel, exactly as
// AlertService.notify does — a broken channel is logged and otherwise
// ignored, never allowed to fail the ticket action itself.
func (s *CertificateRequestService) notify(ctx context.Context, subject, body string) {
	email := s.settings.EmailNotifier()
	teams := s.settings.TeamsNotifier()
	if email.Enabled() {
		if err := email.Send(subject, body); err != nil {
			s.log.Warn("ticket: email send failed", "error", err)
		}
	}
	if teams.Enabled() {
		if err := teams.Send(ctx, subject, body, requestColor); err != nil {
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
