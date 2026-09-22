package service

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
)

// fakeCertificateRequestRepo is a minimal in-memory
// domain.CertificateRequestRepository, mirroring fakeCertificateRepo's shape.
type fakeCertificateRequestRepo struct {
	byID map[uuid.UUID]*domain.CertificateRequest
}

func newFakeCertificateRequestRepo() *fakeCertificateRequestRepo {
	return &fakeCertificateRequestRepo{byID: map[uuid.UUID]*domain.CertificateRequest{}}
}

func (f *fakeCertificateRequestRepo) Create(_ context.Context, r *domain.CertificateRequest) error {
	r.ID = uuid.New()
	f.byID[r.ID] = r
	return nil
}

func (f *fakeCertificateRequestRepo) Update(_ context.Context, r *domain.CertificateRequest) error {
	if _, ok := f.byID[r.ID]; !ok {
		return domain.ErrNotFound
	}
	f.byID[r.ID] = r
	return nil
}

func (f *fakeCertificateRequestRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.CertificateRequest, error) {
	r, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return r, nil
}

func (f *fakeCertificateRequestRepo) List(_ context.Context, _ domain.CertificateRequestFilter) ([]*domain.CertificateRequest, error) {
	out := make([]*domain.CertificateRequest, 0, len(f.byID))
	for _, r := range f.byID {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeCertificateRequestRepo) CountOpen(_ context.Context) (int, error) {
	n := 0
	for _, r := range f.byID {
		if r.Status.Open() {
			n++
		}
	}
	return n, nil
}

func (f *fakeCertificateRequestRepo) LatestByResultCertificateID(_ context.Context, certificateID uuid.UUID) (*domain.CertificateRequest, error) {
	var latest *domain.CertificateRequest
	for _, r := range f.byID {
		if r.ResultCertificateID == nil || *r.ResultCertificateID != certificateID {
			continue
		}
		if latest == nil || r.CreatedAt.After(latest.CreatedAt) {
			latest = r
		}
	}
	if latest == nil {
		return nil, domain.ErrNotFound
	}
	return latest, nil
}

func (f *fakeCertificateRequestRepo) HasOpenRenewalFor(_ context.Context, certificateID uuid.UUID) (bool, error) {
	for _, r := range f.byID {
		if r.ExistingCertificateID != nil && *r.ExistingCertificateID == certificateID && r.Status.Open() {
			return true, nil
		}
	}
	return false, nil
}

func newTestCertificateRequestService(t *testing.T) (*CertificateRequestService, *CertificateService) {
	t.Helper()
	certs := newTestCertificateService(t)
	settings := newTestSettingsService(domain.AppSettings{TicketSLADays: 3})
	reqs := NewCertificateRequestService(newFakeCertificateRequestRepo(), certs, settings, discardLogger())
	return reqs, certs
}

func TestSubmitRequiresPOForExternal(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	_, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustExternal, CommonName: "app.example.com",
	})
	if err == nil {
		t.Fatal("expected an error submitting an external request with no PO number")
	}
}

func TestSubmitBackfillsRenewalFieldsFromExistingCertificate(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	existing, err := certs.CreateCSR(context.Background(), CreateCSRInput{CommonName: "old.example.com", KeyAlgorithm: "rsa", KeyBits: 2048, SelfSignDays: 30})
	if err != nil {
		t.Fatalf("CreateCSR (setup): %v", err)
	}

	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustInternal,
		ExistingCertificateID: &existing.ID,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ticket.CommonName != "old.example.com" {
		t.Errorf("CommonName = %q, want backfilled %q", ticket.CommonName, "old.example.com")
	}
	if ticket.Status != domain.RequestPending {
		t.Errorf("Status = %q, want pending", ticket.Status)
	}
}

// TestSubmitRejectsTrustClassMismatchWithExistingCertificate covers the
// server-side guard added alongside the requests page's split internal/
// external "certificate to renew" pickers: the two selects are only kept in
// sync with the trust_class radio via CSS, so a tampered (or simply stale)
// submission naming a certificate whose actual trust class disagrees with
// the submitted trust_class must still be rejected.
func TestSubmitRejectsTrustClassMismatchWithExistingCertificate(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	existing, err := certs.CreateCSR(context.Background(), CreateCSRInput{CommonName: "internal-cert.example.com", KeyAlgorithm: "rsa", KeyBits: 2048, SelfSignDays: 30})
	if err != nil {
		t.Fatalf("CreateCSR (setup): %v", err)
	}
	if existing.TrustClass() != domain.TrustInternal {
		t.Fatalf("setup: expected the self-signed certificate to be internal, got %q", existing.TrustClass())
	}

	_, err = reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustExternal,
		ExistingCertificateID: &existing.ID,
	})
	if err == nil {
		t.Fatal("expected an error submitting a renewal whose trust class doesn't match the chosen certificate's actual trust class")
	}
}

func TestApproveInternalSignsAndFulfillsInOneAction(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), RequesterEmail: "dev@example.com",
		Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "internal.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	approverID := uuid.New()
	updated, cert, err := reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: approverID,
		CSR:      CreateCSRInput{CommonName: "internal.example.com", KeyAlgorithm: "rsa", KeyBits: 2048},
		RootCAID: ca.ID, Days: 30,
	})
	if err != nil {
		t.Fatalf("ApproveInternal: %v", err)
	}
	if updated.Status != domain.RequestFulfilled {
		t.Errorf("Status = %q, want fulfilled", updated.Status)
	}
	if updated.ResultCertificateID == nil || *updated.ResultCertificateID != cert.ID {
		t.Error("ResultCertificateID must link to the signed certificate")
	}
	if updated.ApprovedBy == nil || *updated.ApprovedBy != approverID {
		t.Error("ApprovedBy must record the approver")
	}
	if cert.TrustClass() != domain.TrustInternal {
		t.Errorf("issued certificate TrustClass = %q, want internal", cert.TrustClass())
	}
}

func TestApproveInternalRejectsExternalTicket(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustExternal,
		CommonName: "app.example.com", PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	_, _, err = reqs.ApproveInternal(context.Background(), ApproveInternalInput{TicketID: ticket.ID, ApproverID: uuid.New()})
	if err == nil {
		t.Fatal("expected an error approving an external ticket through the internal flow")
	}
}

func TestApproveInternalReuseExistingCSRClonesKeyAndCSR(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	existing, err := certs.CreateCSR(context.Background(), CreateCSRInput{CommonName: "renew-me.example.com", KeyAlgorithm: "rsa", KeyBits: 2048})
	if err != nil {
		t.Fatalf("CreateCSR (setup): %v", err)
	}
	existing, err = certs.SignWithRootCA(context.Background(), existing.ID, ca.ID, 30)
	if err != nil {
		t.Fatalf("SignWithRootCA (setup): %v", err)
	}

	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), RequesterEmail: "dev@example.com",
		Type: domain.RequestRenewal, TrustClass: domain.TrustInternal,
		ExistingCertificateID: &existing.ID,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	_, cert, err := reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(),
		ReuseExistingCSR: true,
		RootCAID:         ca.ID, Days: 30,
	})
	if err != nil {
		t.Fatalf("ApproveInternal: %v", err)
	}
	if cert.ID == existing.ID {
		t.Fatal("reusing a CSR must still create a brand-new certificate record, not mutate the original")
	}
	if cert.CSRPEM != existing.CSRPEM {
		t.Error("cloned certificate's CSR PEM does not match the original")
	}
	oldKey, err := certs.PrivateKey(existing)
	if err != nil {
		t.Fatalf("PrivateKey (original): %v", err)
	}
	newKey, err := certs.PrivateKey(cert)
	if err != nil {
		t.Fatalf("PrivateKey (clone): %v", err)
	}
	if oldKey != newKey {
		t.Error("reusing the CSR must reuse the exact same private key")
	}
	reloaded, err := certs.Get(context.Background(), existing.ID)
	if err != nil {
		t.Fatalf("Get (original, after clone): %v", err)
	}
	if reloaded.CSRPEM != existing.CSRPEM {
		t.Error("the original certificate record must be left untouched")
	}
}

func TestApproveInternalReuseExistingCSRRejectsNonRenewalTicket(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "new.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	_, _, err = reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(), ReuseExistingCSR: true, RootCAID: uuid.New(), Days: 30,
	})
	if err == nil {
		t.Fatal("expected an error reusing a CSR on a non-renewal ticket")
	}
}

func TestApproveInternalReuseExistingCSRRejectsWhenSourceHasNoKey(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, _ := buildTestRootCAPEMs(t)
	existing, err := certs.Import(context.Background(), ImportInput{CertificatePEM: caCertPEM})
	if err != nil {
		t.Fatalf("Import (setup): %v", err)
	}
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustInternal,
		ExistingCertificateID: &existing.ID,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	_, _, err = reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(), ReuseExistingCSR: true, RootCAID: uuid.New(), Days: 30,
	})
	if err == nil {
		t.Fatal("expected an error reusing a CSR from a certificate with no stored key")
	}
}

func TestAutoDraftRenewalsDraftsForExpiringCertWithOriginTicket(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	requesterID := uuid.New()
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: requesterID, RequesterEmail: "dev@example.com",
		Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "soon-to-expire.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// A 10-day certificate sits well inside the default 30-day/33% warning
	// window (internal certificates only ever use the day-based half of
	// that check — see HealthStatus's doc comment), so this should be
	// eligible for auto-drafting immediately.
	_, cert, err := reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(),
		CSR:      CreateCSRInput{CommonName: "soon-to-expire.example.com", KeyAlgorithm: "rsa", KeyBits: 2048},
		RootCAID: ca.ID, Days: 10,
	})
	if err != nil {
		t.Fatalf("ApproveInternal: %v", err)
	}

	drafted, err := reqs.AutoDraftRenewals(context.Background())
	if err != nil {
		t.Fatalf("AutoDraftRenewals: %v", err)
	}
	if drafted != 1 {
		t.Fatalf("AutoDraftRenewals drafted %d ticket(s), want 1", drafted)
	}

	tickets, err := reqs.List(context.Background(), domain.CertificateRequestFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var renewal *domain.CertificateRequest
	for _, r := range tickets {
		if r.AutoGenerated {
			renewal = r
		}
	}
	if renewal == nil {
		t.Fatal("expected one auto-generated ticket in the list")
	}
	if renewal.Type != domain.RequestRenewal {
		t.Errorf("Type = %q, want renewal", renewal.Type)
	}
	if renewal.TrustClass != domain.TrustInternal {
		t.Errorf("TrustClass = %q, want internal", renewal.TrustClass)
	}
	if renewal.ExistingCertificateID == nil || *renewal.ExistingCertificateID != cert.ID {
		t.Error("ExistingCertificateID must point at the expiring certificate")
	}
	if renewal.RequesterID != requesterID {
		t.Errorf("RequesterID = %v, want the original requester %v", renewal.RequesterID, requesterID)
	}
	if renewal.Status != domain.RequestPending {
		t.Errorf("Status = %q, want pending", renewal.Status)
	}

	// Running the sweep again must not create a duplicate — an open
	// renewal ticket for this certificate already exists.
	draftedAgain, err := reqs.AutoDraftRenewals(context.Background())
	if err != nil {
		t.Fatalf("AutoDraftRenewals (second run): %v", err)
	}
	if draftedAgain != 0 {
		t.Fatalf("AutoDraftRenewals drafted %d more ticket(s) on a second run, want 0 (duplicate)", draftedAgain)
	}
}

func TestAutoDraftRenewalsSkipsCertificateWithNoOriginTicket(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	// Issued directly in the vault, never through a ticket — there's no
	// requester to draft a renewal ticket for, so this must be skipped.
	pending, err := certs.CreateCSR(context.Background(), CreateCSRInput{CommonName: "vault-only.example.com", KeyAlgorithm: "rsa", KeyBits: 2048})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if _, err := certs.SignWithRootCA(context.Background(), pending.ID, ca.ID, 10); err != nil {
		t.Fatalf("SignWithRootCA: %v", err)
	}

	drafted, err := reqs.AutoDraftRenewals(context.Background())
	if err != nil {
		t.Fatalf("AutoDraftRenewals: %v", err)
	}
	if drafted != 0 {
		t.Fatalf("AutoDraftRenewals drafted %d ticket(s), want 0 — this certificate has no origin ticket", drafted)
	}
}

func TestAutoDraftRenewalsSkipsCertificateNotYetExpiring(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "long-lived.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// A 10-year certificate is nowhere near the default 30-day warning
	// window.
	if _, _, err := reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(),
		CSR:      CreateCSRInput{CommonName: "long-lived.example.com", KeyAlgorithm: "rsa", KeyBits: 2048},
		RootCAID: ca.ID, Days: 3650,
	}); err != nil {
		t.Fatalf("ApproveInternal: %v", err)
	}

	drafted, err := reqs.AutoDraftRenewals(context.Background())
	if err != nil {
		t.Fatalf("AutoDraftRenewals: %v", err)
	}
	if drafted != 0 {
		t.Fatalf("AutoDraftRenewals drafted %d ticket(s), want 0 — this certificate isn't expiring soon", drafted)
	}
}

func TestExternalTicketApproveThenFulfillCloses(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustExternal,
		CommonName: "public.example.com", PONumber: "PO-99",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	approverID := uuid.New()
	if _, _, err := reqs.FulfillExternal(context.Background(), FulfillExternalInput{TicketID: ticket.ID, ApproverID: approverID}); err == nil {
		t.Fatal("expected fulfillment to be rejected before the ticket is approved")
	}

	approved, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: approverID})
	if err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}
	if approved.Status != domain.RequestInProgress {
		t.Fatalf("Status = %q, want in_progress", approved.Status)
	}

	// Build a leaf certificate whose subject differs from its issuer — the
	// shape a real external CA's answer takes — by signing one against a
	// throwaway CA fixture. Import only cares that the PEM parses; the point
	// here is that TrustClass() must key off Subject != Issuer, not off
	// which CA (if any) this test happens to use to produce that shape.
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	fixtureCA, err := certs.UploadRootCA(context.Background(), "External-shaped fixture CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA (fixture): %v", err)
	}
	pendingLeaf, err := certs.CreateCSR(context.Background(), CreateCSRInput{CommonName: "public.example.com", KeyAlgorithm: "rsa", KeyBits: 2048})
	if err != nil {
		t.Fatalf("CreateCSR (fixture): %v", err)
	}
	signedLeaf, err := certs.SignWithRootCA(context.Background(), pendingLeaf.ID, fixtureCA.ID, 30)
	if err != nil {
		t.Fatalf("SignWithRootCA (fixture): %v", err)
	}
	certPEM := signedLeaf.CertificatePEM

	fulfilled, cert, err := reqs.FulfillExternal(context.Background(), FulfillExternalInput{
		TicketID: ticket.ID, ApproverID: approverID,
		Import: ImportInput{CertificatePEM: certPEM},
	})
	if err != nil {
		t.Fatalf("FulfillExternal: %v", err)
	}
	if fulfilled.Status != domain.RequestFulfilled {
		t.Errorf("Status = %q, want fulfilled", fulfilled.Status)
	}
	if fulfilled.ResultCertificateID == nil || *fulfilled.ResultCertificateID != cert.ID {
		t.Error("ResultCertificateID must link to the imported certificate")
	}

	loaded, err := certs.Get(context.Background(), cert.ID)
	if err != nil {
		t.Fatalf("Get imported certificate: %v", err)
	}
	if loaded.TrustClass() != domain.TrustExternal {
		t.Errorf("imported certificate TrustClass = %q, want external", loaded.TrustClass())
	}
}

// TestGenerateCSRThenFulfillExternalAttachesToSameCertificate covers the
// manual "Generate a CSR" ticket action end to end: generating a CSR records
// a PendingCertificateID on the ticket, and a later FulfillExternal attaches
// the externally-signed certificate to that same vault record — proven by
// asserting the resulting certificate's ID equals the pending one's, rather
// than a freshly Import-ed record — matching it to the private key that was
// already generated instead of requiring the admin to paste one in.
func TestGenerateCSRThenFulfillExternalAttachesToSameCertificate(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustExternal,
		CommonName: "csr-flow.example.com", PONumber: "PO-CSR-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approverID := uuid.New()

	if _, _, err := reqs.GenerateCSR(context.Background(), GenerateCSRInput{
		TicketID: ticket.ID, CommonName: ticket.CommonName, KeyAlgorithm: "rsa", KeyBits: 2048,
	}); err == nil {
		t.Fatal("expected GenerateCSR to be rejected before the ticket is approved")
	}

	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: approverID}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}

	updated, pending, err := reqs.GenerateCSR(context.Background(), GenerateCSRInput{
		TicketID: ticket.ID, CommonName: ticket.CommonName, KeyAlgorithm: "rsa", KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if updated.PendingCertificateID == nil || *updated.PendingCertificateID != pending.ID {
		t.Fatal("GenerateCSR must record the new certificate as the ticket's PendingCertificateID")
	}
	if pending.CSRPEM == "" {
		t.Fatal("GenerateCSR must produce a certificate record holding a CSR")
	}

	// Generating a second CSR for the same ticket must be rejected — one is
	// already on file.
	if _, _, err := reqs.GenerateCSR(context.Background(), GenerateCSRInput{
		TicketID: ticket.ID, CommonName: ticket.CommonName, KeyAlgorithm: "rsa", KeyBits: 2048,
	}); err == nil {
		t.Fatal("expected a second GenerateCSR call to be rejected")
	}

	// Simulate the external CA signing exactly this CSR (subject != issuer,
	// the realistic external shape — see TestExternalTicketApproveThenFulfillCloses).
	keyPEM, err := certs.PrivateKey(pending)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	key, err := certutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	csr, err := certutil.ParseCSRPEM(pending.CSRPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	caCert, err := certutil.ParseCertificatesPEM(caCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatesPEM (ca): %v", err)
	}
	caKey, err := certutil.ParsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM (ca): %v", err)
	}
	_, certPEM, err := certutil.SignWithCA(csr, caCert[0], caKey, 365, nil)
	if err != nil {
		t.Fatalf("SignWithCA: %v", err)
	}
	_ = key // only needed to confirm the key parses; AttachCertificate re-derives the match itself.

	fulfilled, cert, err := reqs.FulfillExternal(context.Background(), FulfillExternalInput{
		TicketID: ticket.ID, ApproverID: approverID,
		// A stray pasted private key must be silently ignored — the ticket
		// already has one on file via PendingCertificateID.
		Import: ImportInput{CertificatePEM: certPEM, PrivateKeyPEM: "-----BEGIN garbage-----"},
	})
	if err != nil {
		t.Fatalf("FulfillExternal: %v", err)
	}
	if fulfilled.Status != domain.RequestFulfilled {
		t.Errorf("Status = %q, want fulfilled", fulfilled.Status)
	}
	if cert.ID != pending.ID {
		t.Errorf("fulfilled certificate ID = %s, want the same record GenerateCSR created (%s), not a new one", cert.ID, pending.ID)
	}
	if fulfilled.ResultCertificateID == nil || *fulfilled.ResultCertificateID != pending.ID {
		t.Error("ResultCertificateID must link to the pre-generated CSR's certificate record")
	}
}

// TestGenerateCSRRejectsInternalTicket confirms the manual CSR-generation
// action is exclusive to external tickets — an internal ticket already has
// its own "Approve & sign" path that mints and signs a certificate in one
// step, with no separate CSR-generation stage.
// TestGenerateCSRUsesFullSubjectAndEKUFields covers the field-parity fix:
// GenerateCSRInput used to only take common name/organization/SANs/key
// spec, silently dropping OU/country/province/locality/email/EKU even
// though the vault's own "Generate a CSR" tab has always offered them.
func TestGenerateCSRUsesFullSubjectAndEKUFields(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustExternal,
		CommonName: "full-fields.example.com", PONumber: "PO-CSR-2",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: uuid.New()}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}

	_, pending, err := reqs.GenerateCSR(context.Background(), GenerateCSRInput{
		TicketID:           ticket.ID,
		CommonName:         ticket.CommonName,
		Organization:       "Acme Corp",
		OrganizationalUnit: "Platform",
		Country:            "id",
		Province:           "Jakarta",
		Locality:           "Jakarta Selatan",
		Email:              "ops@example.com",
		ExtKeyUsages:       []string{certutil.EKUCodeSigning},
		KeyAlgorithm:       "rsa", KeyBits: 2048,
		Notes: "handled by the platform team",
	})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if pending.OrganizationalUnit != "Platform" {
		t.Errorf("OrganizationalUnit = %q, want %q", pending.OrganizationalUnit, "Platform")
	}
	if pending.Country != "ID" {
		t.Errorf("Country = %q, want %q", pending.Country, "ID")
	}
	if pending.Province != "Jakarta" || pending.Locality != "Jakarta Selatan" {
		t.Errorf("Province/Locality = %q/%q, want Jakarta/Jakarta Selatan", pending.Province, pending.Locality)
	}
	if pending.Email != "ops@example.com" {
		t.Errorf("Email = %q, want %q", pending.Email, "ops@example.com")
	}
	if len(pending.ExtKeyUsage) != 1 || pending.ExtKeyUsage[0] != certutil.EKUCodeSigning {
		t.Errorf("ExtKeyUsage = %v, want [%s]", pending.ExtKeyUsage, certutil.EKUCodeSigning)
	}
	if !strings.Contains(pending.Notes, "handled by the platform team") {
		t.Errorf("Notes = %q, want it to include the caller-supplied note alongside the auto-generated one", pending.Notes)
	}
	if !strings.Contains(pending.Notes, ticket.ID.String()) {
		t.Errorf("Notes = %q, want the auto-generated ticket cross-reference preserved", pending.Notes)
	}
}

func TestGenerateCSRRejectsInternalTicket(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal,
		CommonName: "internal.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, _, err := reqs.GenerateCSR(context.Background(), GenerateCSRInput{
		TicketID: ticket.ID, CommonName: ticket.CommonName, KeyAlgorithm: "rsa", KeyBits: 2048,
	}); err == nil {
		t.Fatal("expected GenerateCSR to reject an internal ticket")
	}
}

// TestSendCertificateEmailRequiresAFulfilledResult covers the guard that
// stops a "send by email" attempt on a ticket that hasn't produced a
// certificate yet — there's nothing to attach.
func TestSendCertificateEmailRequiresAFulfilledResult(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), RequesterEmail: "dev@example.com",
		Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "internal.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	_, err = reqs.SendCertificateEmail(context.Background(), SendCertificateEmailInput{
		TicketID: ticket.ID, ActorID: uuid.New(), Format: "pem", Recipient: "dev@example.com",
	})
	if err == nil {
		t.Fatal("expected an error sending a ticket with no result certificate yet")
	}
}

// TestSendCertificateEmailRequiresARecipient covers the guard against an
// empty recipient — separate from HTML's own `required` attribute, since a
// direct API/form-tampering call could still submit one.
func TestSendCertificateEmailRequiresARecipient(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	ticket, cert := fulfillInternalTicket(t, reqs, certs, "internal.example.com")

	_, err := reqs.SendCertificateEmail(context.Background(), SendCertificateEmailInput{
		TicketID: ticket.ID, ActorID: uuid.New(), Format: "pem", Recipient: "   ",
	})
	if err == nil {
		t.Fatal("expected an error sending with a blank recipient")
	}
	if cert == nil {
		t.Fatal("fulfillInternalTicket must return the issued certificate")
	}
}

// TestSendCertificateEmailRequiresEmailConfigured covers the case this
// session's test harness always hits (newTestCertificateRequestService
// builds an unconfigured EmailNotifier, same as a fresh deployment that
// hasn't set SMTP_HOST yet): SendCertificateEmail must fail clearly rather
// than silently no-op like the alert channel's Send does, and — just as
// importantly — must NOT mark the ticket delivered on that failure, since
// nothing was actually sent.
func TestSendCertificateEmailRequiresEmailConfigured(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	ticket, _ := fulfillInternalTicket(t, reqs, certs, "internal.example.com")

	_, err := reqs.SendCertificateEmail(context.Background(), SendCertificateEmailInput{
		TicketID: ticket.ID, ActorID: uuid.New(), Format: "pem", Recipient: "dev@example.com",
	})
	if err == nil {
		t.Fatal("expected an error when SMTP isn't configured")
	}

	reloaded, getErr := reqs.Get(context.Background(), ticket.ID)
	if getErr != nil {
		t.Fatalf("Get: %v", getErr)
	}
	if reloaded.Delivered() {
		t.Fatal("a failed send must not mark the ticket delivered")
	}
}

// fulfillInternalTicket submits and self-signs an internal ticket in one
// step, returning it in the domain.RequestFulfilled state with a
// ResultCertificateID set — the precondition every SendCertificateEmail test
// needs, factored out since TestApproveInternalSignsAndFulfillsInOneAction
// already establishes the same shape inline.
func fulfillInternalTicket(t *testing.T, reqs *CertificateRequestService, certs *CertificateService, commonName string) (*domain.CertificateRequest, *domain.Certificate) {
	t.Helper()
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Fixture CA for "+commonName, caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), RequesterEmail: "dev@example.com",
		Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: commonName,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	updated, cert, err := reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(),
		CSR:      CreateCSRInput{CommonName: commonName, KeyAlgorithm: "rsa", KeyBits: 2048},
		RootCAID: ca.ID, Days: 30,
	})
	if err != nil {
		t.Fatalf("ApproveInternal: %v", err)
	}
	return updated, cert
}

func TestRejectRequiresReasonAndOnlyAppliesToPending(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "app.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if _, err := reqs.Reject(context.Background(), RejectInput{TicketID: ticket.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error rejecting with no reason")
	}

	rejected, err := reqs.Reject(context.Background(), RejectInput{TicketID: ticket.ID, ActorID: uuid.New(), Reason: "duplicate request"})
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if rejected.Status != domain.RequestRejected {
		t.Errorf("Status = %q, want rejected", rejected.Status)
	}

	if _, err := reqs.Reject(context.Background(), RejectInput{TicketID: ticket.ID, ActorID: uuid.New(), Reason: "again"}); err == nil {
		t.Fatal("expected an error rejecting an already-closed ticket")
	}
}

func TestCancelOnlyAppliesToOpenTickets(t *testing.T) {
	reqs, _ := newTestCertificateRequestService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "app.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	cancelled, err := reqs.Cancel(context.Background(), CancelInput{TicketID: ticket.ID, ActorID: uuid.New()})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.Status != domain.RequestCancelled {
		t.Errorf("Status = %q, want cancelled", cancelled.Status)
	}
	if _, err := reqs.Cancel(context.Background(), CancelInput{TicketID: ticket.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error cancelling an already-closed ticket")
	}
}

func TestDeliverOnlyAppliesOnceToFulfilledTickets(t *testing.T) {
	reqs, certs := newTestCertificateRequestService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "app.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if _, err := reqs.Deliver(context.Background(), DeliverInput{TicketID: ticket.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error delivering a not-yet-fulfilled ticket")
	}

	fulfilled, _, err := reqs.ApproveInternal(context.Background(), ApproveInternalInput{
		TicketID: ticket.ID, ApproverID: uuid.New(),
		CSR:      CreateCSRInput{CommonName: "app.example.com", KeyAlgorithm: "rsa", KeyBits: 2048},
		RootCAID: ca.ID, Days: 30,
	})
	if err != nil {
		t.Fatalf("ApproveInternal: %v", err)
	}
	if fulfilled.Delivered() {
		t.Fatal("a freshly fulfilled ticket must not already be marked delivered")
	}

	delivered, err := reqs.Deliver(context.Background(), DeliverInput{TicketID: fulfilled.ID, ActorID: uuid.New()})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !delivered.Delivered() {
		t.Error("expected Delivered() to report true after Deliver succeeds")
	}
	if _, err := reqs.Deliver(context.Background(), DeliverInput{TicketID: fulfilled.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error delivering an already-delivered ticket")
	}
}
