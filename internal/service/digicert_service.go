package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/digicert"
)

// DigiCertService submits an in-progress external renewal ticket to
// DigiCert's CertCentral API and polls it to completion — the Phase 6
// alternative to FulfillExternal's "paste the PEM a CA emailed you" manual
// flow. The two coexist rather than replace one another: DigiCert is just a
// different source for the certificate PEM that eventually needs attaching,
// not a separate ticket lifecycle, and the manual flow stays the fallback
// for every non-DigiCert CA (or if a DigiCert call fails). See
// internal/pkg/digicert's package doc comment for what about the wire
// format is still unverified against a real account.
type DigiCertService struct {
	repo   domain.CertificateRequestRepository
	certs  *CertificateService
	client digicert.Client
	log    *slog.Logger
}

// NewDigiCertService builds the service. client is nil when the integration
// isn't configured (DIGICERT_API_KEY empty) — every method below reports a
// clear domain.Invalid error via Enabled() rather than touching a nil
// client.
func NewDigiCertService(repo domain.CertificateRequestRepository, certs *CertificateService, client digicert.Client, log *slog.Logger) *DigiCertService {
	return &DigiCertService{repo: repo, certs: certs, client: client, log: log}
}

// Enabled reports whether the DigiCert integration is configured at all —
// gates both the ticket detail page's "Submit to DigiCert" section and
// these methods themselves.
func (s *DigiCertService) Enabled() bool { return s.client != nil }

// DigiCertSubmitInput is the "Submit to DigiCert" ticket action. Days is the
// requested validity; DigiCert (or a future automated renewal cadence tied
// to SC-081v3's shrinking ceiling) may issue for less.
type DigiCertSubmitInput struct {
	TicketID uuid.UUID
	ActorID  uuid.UUID
	Days     int
}

// Submit generates a fresh key pair and CSR from the certificate being
// renewed — reusing the same certutil-backed CreateCSR building block
// ApproveInternal already uses, seeded from the existing certificate's
// subject and SANs — and submits it to DigiCert: a
// reissue against the certificate's existing DigiCertOrderID when it has
// one (DigiCert's faster path), or a brand-new order otherwise. The CSR's
// key pair is generated and stored via the normal vault CreateCSR path (so
// it's encrypted at rest exactly like any other pending certificate) rather
// than held only in memory, since real CA issuance can take time — the
// resulting pending record's ID is what CheckStatus later attaches the
// issued certificate to.
//
// Scoped to in-progress external renewal tickets only: TrustClass must be
// external (an internal certificate is renewed through the ticket queue's
// own internal-approval flow instead — there's no outside CA to call for
// one) and Type must be renewal naming an existing certificate, since a
// brand-new external certificate has no prior
// subject/SANs to seed the CSR from and still goes through the existing
// manual-paste flow.
func (s *DigiCertService) Submit(ctx context.Context, in DigiCertSubmitInput) (*domain.CertificateRequest, error) {
	if !s.Enabled() {
		return nil, domain.Invalid("digicert", "the DigiCert integration isn't configured — set DIGICERT_API_KEY and DIGICERT_BASE_URL")
	}
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, err
	}
	if r.TrustClass != domain.TrustExternal {
		return nil, domain.Invalid("trust_class", "DigiCert submission only applies to external tickets")
	}
	if r.Type != domain.RequestRenewal || r.ExistingCertificateID == nil {
		return nil, domain.Invalid("type", "DigiCert submission is only available for a renewal ticket naming an existing certificate")
	}
	if r.Status != domain.RequestInProgress {
		return nil, domain.Invalid("status", "approve this ticket before submitting it to DigiCert")
	}
	if r.SubmittedToExternalCA() {
		return nil, domain.Invalid("status", "this ticket has already been submitted to DigiCert")
	}

	existing, err := s.certs.Get(ctx, *r.ExistingCertificateID)
	if err != nil {
		return nil, fmt.Errorf("load certificate to renew: %w", err)
	}

	days := in.Days
	if days <= 0 {
		// The CA/Browser Forum's public-certificate max-validity ceiling as
		// of this writing (Ballot SC-081v3) — see CLAUDE.md. Falls to 100
		// days in March 2027 and 47 in March 2029; this default should be
		// revisited as that schedule advances.
		days = 200
	}

	sans := strings.Join(append(append([]string{}, existing.DNSNames...), existing.IPAddresses...), "\n")
	pending, err := s.certs.CreateCSR(ctx, CreateCSRInput{
		CommonName: existing.CommonName, Organization: existing.Organization,
		OrganizationalUnit: existing.OrganizationalUnit, Country: existing.Country,
		Province: existing.Province, Locality: existing.Locality, Email: existing.Email,
		SANs: sans, KeyAlgorithm: existing.KeyAlgorithm, KeyBits: existing.KeyBits, KeyCurve: existing.KeyCurve,
		Owner: existing.Owner, Notes: fmt.Sprintf("DigiCert renewal of certificate %s (ticket %s)", existing.ID, r.ID),
		ExtKeyUsages: existing.ExtKeyUsage,
	})
	if err != nil {
		return nil, fmt.Errorf("generate renewal CSR: %w", err)
	}

	orderReq := digicert.OrderRequest{
		CSRPEM:       pending.CSRPEM,
		CommonName:   existing.CommonName,
		DNSNames:     existing.DNSNames,
		ValidityDays: days,
	}
	var order *digicert.Order
	if existing.DigiCertOrderID != "" {
		order, err = s.client.SubmitReissue(ctx, existing.DigiCertOrderID, orderReq)
	} else {
		order, err = s.client.SubmitOrder(ctx, orderReq)
	}
	if err != nil {
		return nil, fmt.Errorf("submit to digicert: %w", err)
	}

	r.ExternalProvider = "digicert"
	r.ExternalOrderRef = order.OrderID
	r.ExternalOrderStatus = order.Status
	pendingID := pending.ID
	r.PendingCertificateID = &pendingID
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}

// DigiCertCheckStatusInput is the "Check status" ticket action.
type DigiCertCheckStatusInput struct {
	TicketID uuid.UUID
	ActorID  uuid.UUID
}

// CheckStatus polls DigiCert for the submitted order's current state. A
// status that isn't yet "issued" just refreshes ExternalOrderStatus for
// display and returns — the admin polls again later. Once DigiCert reports
// it issued, this downloads the certificate and attaches it to the pending
// vault record Submit created (matching it to the private key already
// stored there, via the existing AttachCertificate — not Import, since
// unlike a manually-pasted external certificate, this app generated the key
// pair itself and it's already on file), records the DigiCert order ID on
// the resulting certificate, and fulfills the ticket exactly the way
// ApproveInternal/FulfillExternal already do.
func (s *DigiCertService) CheckStatus(ctx context.Context, in DigiCertCheckStatusInput) (*domain.CertificateRequest, *domain.Certificate, error) {
	if !s.Enabled() {
		return nil, nil, domain.Invalid("digicert", "the DigiCert integration isn't configured")
	}
	r, err := s.repo.GetByID(ctx, in.TicketID)
	if err != nil {
		return nil, nil, err
	}
	if !r.SubmittedToExternalCA() {
		return nil, nil, domain.Invalid("status", "this ticket hasn't been submitted to DigiCert yet")
	}
	if r.Status == domain.RequestFulfilled {
		return nil, nil, domain.Invalid("status", "this ticket is already fulfilled")
	}

	order, err := s.client.OrderStatus(ctx, r.ExternalOrderRef)
	if err != nil {
		return nil, nil, fmt.Errorf("check digicert order status: %w", err)
	}
	r.ExternalOrderStatus = order.Status

	if !digicert.StatusIsIssued(order.Status) {
		if err := s.repo.Update(ctx, r); err != nil {
			return nil, nil, err
		}
		return r, nil, nil
	}

	if r.PendingCertificateID == nil {
		return nil, nil, fmt.Errorf("digicert: order %s reports issued but no pending certificate is on file for ticket %s", r.ExternalOrderRef, r.ID)
	}
	pemData, err := s.client.DownloadCertificate(ctx, r.ExternalOrderRef)
	if err != nil {
		return nil, nil, fmt.Errorf("download digicert certificate: %w", err)
	}
	signed, err := s.certs.AttachCertificate(ctx, *r.PendingCertificateID, string(pemData))
	if err != nil {
		return nil, nil, fmt.Errorf("attach digicert certificate: %w", err)
	}
	signed, err = s.certs.SetDigiCertOrderID(ctx, signed.ID, r.ExternalOrderRef)
	if err != nil {
		return nil, nil, fmt.Errorf("record digicert order id: %w", err)
	}

	now := time.Now().UTC()
	r.ResultCertificateID = &signed.ID
	r.FulfilledBy = &in.ActorID
	r.FulfilledAt = &now
	r.Status = domain.RequestFulfilled
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, nil, err
	}
	return r, signed, nil
}
