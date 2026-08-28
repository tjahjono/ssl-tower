package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
	"github.com/ivangiovn/ssl-generator/internal/pkg/digicert"
)

// fakeDigiCertClient is an in-memory digicert.Client — there is no live
// CertCentral account to test HTTPClient against (see the digicert package
// doc comment), so DigiCertService's tests exercise this fake instead.
type fakeDigiCertClient struct {
	nextID   int
	orders   map[string]*digicert.Order
	certs    map[string][]byte
	reissued map[string]bool
}

func newFakeDigiCertClient() *fakeDigiCertClient {
	return &fakeDigiCertClient{
		orders:   map[string]*digicert.Order{},
		certs:    map[string][]byte{},
		reissued: map[string]bool{},
	}
}

func (f *fakeDigiCertClient) SubmitOrder(_ context.Context, _ digicert.OrderRequest) (*digicert.Order, error) {
	f.nextID++
	order := &digicert.Order{OrderID: fmt.Sprintf("order-%d", f.nextID), Status: "pending"}
	f.orders[order.OrderID] = order
	return order, nil
}

func (f *fakeDigiCertClient) SubmitReissue(_ context.Context, orderID string, _ digicert.OrderRequest) (*digicert.Order, error) {
	f.reissued[orderID] = true
	f.nextID++
	order := &digicert.Order{OrderID: fmt.Sprintf("reissue-%d", f.nextID), Status: "pending"}
	f.orders[order.OrderID] = order
	return order, nil
}

func (f *fakeDigiCertClient) OrderStatus(_ context.Context, orderID string) (*digicert.Order, error) {
	o, ok := f.orders[orderID]
	if !ok {
		return nil, fmt.Errorf("fakeDigiCertClient: no such order %q", orderID)
	}
	return o, nil
}

func (f *fakeDigiCertClient) DownloadCertificate(_ context.Context, orderID string) ([]byte, error) {
	pem, ok := f.certs[orderID]
	if !ok {
		return nil, fmt.Errorf("fakeDigiCertClient: no certificate on file for order %q", orderID)
	}
	return pem, nil
}

// markIssued flips an order to "issued" and stakes out the PEM
// DownloadCertificate should return for it — standing in for DigiCert
// actually finishing validation and issuing the certificate.
func (f *fakeDigiCertClient) markIssued(orderID string, pem []byte) {
	f.orders[orderID].Status = "issued"
	f.certs[orderID] = pem
}

var _ digicert.Client = (*fakeDigiCertClient)(nil)

func newTestDigiCertService(t *testing.T) (*DigiCertService, *CertificateRequestService, *CertificateService, *fakeDigiCertClient) {
	t.Helper()
	certs := newTestCertificateService(t)
	repo := newFakeCertificateRequestRepo()
	reqs := NewCertificateRequestService(repo, certs, newTestSettingsService(domain.AppSettings{TicketSLADays: 3}), discardLogger())
	client := newFakeDigiCertClient()
	dc := NewDigiCertService(repo, certs, client, discardLogger())
	return dc, reqs, certs, client
}

// externalCertFixture builds a certificate whose Subject differs from its
// Issuer (TrustClass() == TrustExternal), the same technique
// TestExternalTicketApproveThenFulfillCloses uses: sign a leaf against a
// throwaway CA fixture and import only the leaf.
func externalCertFixture(t *testing.T, certs *CertificateService, commonName string) *domain.Certificate {
	t.Helper()
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := certs.UploadRootCA(context.Background(), "fixture CA for "+commonName, caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA (fixture): %v", err)
	}
	pending, err := certs.CreateCSR(context.Background(), CreateCSRInput{CommonName: commonName, KeyAlgorithm: "rsa", KeyBits: 2048})
	if err != nil {
		t.Fatalf("CreateCSR (fixture): %v", err)
	}
	signed, err := certs.SignWithRootCA(context.Background(), pending.ID, ca.ID, 200)
	if err != nil {
		t.Fatalf("SignWithRootCA (fixture): %v", err)
	}
	imported, err := certs.Import(context.Background(), ImportInput{CertificatePEM: signed.CertificatePEM})
	if err != nil {
		t.Fatalf("Import (fixture): %v", err)
	}
	if imported.TrustClass() != domain.TrustExternal {
		t.Fatalf("fixture setup: expected TrustExternal, got %q", imported.TrustClass())
	}
	return imported
}

func TestDigiCertSubmitRejectsWrongTrustClass(t *testing.T) {
	dc, reqs, _, _ := newTestDigiCertService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustInternal, CommonName: "internal.example.com",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error submitting an internal ticket to DigiCert")
	}
}

func TestDigiCertSubmitRejectsNewRatherThanRenewal(t *testing.T) {
	dc, reqs, _, _ := newTestDigiCertService(t)
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestNew, TrustClass: domain.TrustExternal, CommonName: "app.example.com", PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: uuid.New()}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}
	if _, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error submitting a new-certificate ticket to DigiCert — only renewals are supported")
	}
}

func TestDigiCertSubmitRejectsWhenNotYetApproved(t *testing.T) {
	dc, reqs, certs, _ := newTestDigiCertService(t)
	existing := externalCertFixture(t, certs, "renew-me.example.com")
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustExternal,
		ExistingCertificateID: &existing.ID, PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error submitting a still-pending (not yet approved) ticket to DigiCert")
	}
}

func TestDigiCertSubmitPlacesNewOrderAndTracksPendingCertificate(t *testing.T) {
	dc, reqs, certs, client := newTestDigiCertService(t)
	existing := externalCertFixture(t, certs, "renew-me.example.com")

	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustExternal,
		ExistingCertificateID: &existing.ID, PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approverID := uuid.New()
	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: approverID}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}

	updated, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: approverID, Days: 90})
	if err != nil {
		t.Fatalf("dc.Submit: %v", err)
	}
	if updated.ExternalProvider != "digicert" {
		t.Errorf("ExternalProvider = %q, want digicert", updated.ExternalProvider)
	}
	if updated.ExternalOrderRef == "" {
		t.Error("expected ExternalOrderRef to be set")
	}
	if updated.ExternalOrderStatus != "pending" {
		t.Errorf("ExternalOrderStatus = %q, want pending", updated.ExternalOrderStatus)
	}
	if updated.PendingCertificateID == nil {
		t.Fatal("expected PendingCertificateID to be set")
	}
	if client.reissued[updated.ExternalOrderRef] {
		t.Error("a certificate with no prior DigiCertOrderID must place a new order, not a reissue")
	}

	pending, err := certs.Get(context.Background(), *updated.PendingCertificateID)
	if err != nil {
		t.Fatalf("Get pending certificate: %v", err)
	}
	if pending.CommonName != existing.CommonName {
		t.Errorf("pending CommonName = %q, want %q (seeded from the certificate being renewed)", pending.CommonName, existing.CommonName)
	}
	if pending.CSRPEM == "" {
		t.Error("expected the pending certificate to carry a generated CSR")
	}

	// Submitting a second time must be rejected — already submitted.
	if _, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: approverID}); err == nil {
		t.Fatal("expected an error re-submitting an already-submitted ticket to DigiCert")
	}
}

func TestDigiCertSubmitUsesReissueWhenExistingHasOrderID(t *testing.T) {
	dc, reqs, certs, client := newTestDigiCertService(t)
	existing := externalCertFixture(t, certs, "renew-me.example.com")
	if _, err := certs.SetDigiCertOrderID(context.Background(), existing.ID, "prior-order-1"); err != nil {
		t.Fatalf("SetDigiCertOrderID (setup): %v", err)
	}

	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustExternal,
		ExistingCertificateID: &existing.ID, PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approverID := uuid.New()
	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: approverID}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}

	updated, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: approverID})
	if err != nil {
		t.Fatalf("dc.Submit: %v", err)
	}
	if !client.reissued["prior-order-1"] {
		t.Error("expected SubmitReissue to be called against the certificate's existing DigiCertOrderID")
	}
	if updated.ExternalOrderRef == "prior-order-1" {
		t.Error("expected the ticket to track the new reissue's order ID, not the prior order's")
	}
}

func TestDigiCertCheckStatusNotYetIssuedJustUpdatesStatus(t *testing.T) {
	dc, reqs, certs, client := newTestDigiCertService(t)
	existing := externalCertFixture(t, certs, "renew-me.example.com")
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustExternal,
		ExistingCertificateID: &existing.ID, PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approverID := uuid.New()
	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: approverID}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}
	submitted, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: approverID})
	if err != nil {
		t.Fatalf("dc.Submit: %v", err)
	}
	client.orders[submitted.ExternalOrderRef].Status = "pending_review"

	updated, cert, err := dc.CheckStatus(context.Background(), DigiCertCheckStatusInput{TicketID: ticket.ID, ActorID: approverID})
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if cert != nil {
		t.Fatal("expected no certificate yet — the order isn't issued")
	}
	if updated.Status == domain.RequestFulfilled {
		t.Error("ticket must not be fulfilled while the DigiCert order is still pending")
	}
	if updated.ExternalOrderStatus != "pending_review" {
		t.Errorf("ExternalOrderStatus = %q, want pending_review", updated.ExternalOrderStatus)
	}
}

func TestDigiCertCheckStatusIssuedFulfillsTicket(t *testing.T) {
	dc, reqs, certs, client := newTestDigiCertService(t)
	existing := externalCertFixture(t, certs, "renew-me.example.com")
	ticket, err := reqs.Submit(context.Background(), SubmitInput{
		RequesterID: uuid.New(), Type: domain.RequestRenewal, TrustClass: domain.TrustExternal,
		ExistingCertificateID: &existing.ID, PONumber: "PO-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approverID := uuid.New()
	if _, err := reqs.ApproveExternal(context.Background(), ApproveExternalInput{TicketID: ticket.ID, ApproverID: approverID}); err != nil {
		t.Fatalf("ApproveExternal: %v", err)
	}
	submitted, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: ticket.ID, ActorID: approverID, Days: 90})
	if err != nil {
		t.Fatalf("dc.Submit: %v", err)
	}

	// Stand in for DigiCert actually issuing the certificate: sign a leaf
	// for the exact key pair Submit generated and stored against the
	// pending certificate record, so AttachCertificate's key-match check
	// passes exactly as it would for a real DigiCert response.
	pending, err := certs.Get(context.Background(), *submitted.PendingCertificateID)
	if err != nil {
		t.Fatalf("Get pending certificate: %v", err)
	}
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
	_, leafPEM, err := certutil.SelfSign(csr, key, 90, nil)
	if err != nil {
		t.Fatalf("SelfSign (fixture issuance): %v", err)
	}
	client.markIssued(submitted.ExternalOrderRef, []byte(leafPEM))

	updated, cert, err := dc.CheckStatus(context.Background(), DigiCertCheckStatusInput{TicketID: ticket.ID, ActorID: approverID})
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if cert == nil {
		t.Fatal("expected a fulfilled certificate once DigiCert reports the order issued")
	}
	if cert.ID != pending.ID {
		t.Errorf("fulfilled certificate ID = %v, want the pending record %v (attached in place, not a new record)", cert.ID, pending.ID)
	}
	if cert.DigiCertOrderID != submitted.ExternalOrderRef {
		t.Errorf("DigiCertOrderID = %q, want %q", cert.DigiCertOrderID, submitted.ExternalOrderRef)
	}
	if updated.Status != domain.RequestFulfilled {
		t.Errorf("ticket Status = %q, want fulfilled", updated.Status)
	}
	if updated.ResultCertificateID == nil || *updated.ResultCertificateID != cert.ID {
		t.Error("ResultCertificateID must link to the fulfilled certificate")
	}
	if updated.FulfilledBy == nil || *updated.FulfilledBy != approverID {
		t.Error("FulfilledBy must record the actor who triggered the status check")
	}
}

func TestDigiCertServiceDisabledReturnsClearError(t *testing.T) {
	certs := newTestCertificateService(t)
	repo := newFakeCertificateRequestRepo()
	dc := NewDigiCertService(repo, certs, nil, discardLogger())
	if dc.Enabled() {
		t.Fatal("expected Enabled() to be false with a nil client")
	}
	if _, err := dc.Submit(context.Background(), DigiCertSubmitInput{TicketID: uuid.New(), ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error calling Submit when the integration isn't configured")
	}
	if _, _, err := dc.CheckStatus(context.Background(), DigiCertCheckStatusInput{TicketID: uuid.New(), ActorID: uuid.New()}); err == nil {
		t.Fatal("expected an error calling CheckStatus when the integration isn't configured")
	}
}
