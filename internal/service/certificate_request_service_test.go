package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
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

func newTestCertificateRequestService(t *testing.T) (*CertificateRequestService, *CertificateService) {
	t.Helper()
	certs := newTestCertificateService(t)
	reqs := NewCertificateRequestService(newFakeCertificateRequestRepo(), certs,
		notify.NewEmailNotifier(notify.EmailConfig{}), notify.NewTeamsNotifier(""), discardLogger(), 3)
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
