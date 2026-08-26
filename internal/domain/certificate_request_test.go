package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCertificateRequestValidateNewInternal(t *testing.T) {
	r := &CertificateRequest{Type: RequestNew, TrustClass: TrustInternal, CommonName: "app.internal.example"}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestCertificateRequestValidateRejectsMissingCommonNameForNew(t *testing.T) {
	r := &CertificateRequest{Type: RequestNew, TrustClass: TrustInternal}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for a new-certificate request with no common name")
	}
}

func TestCertificateRequestValidateRejectsRenewalWithoutTarget(t *testing.T) {
	r := &CertificateRequest{Type: RequestRenewal, TrustClass: TrustInternal, CommonName: "app.example.com"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for a renewal with no existing certificate picked")
	}
}

func TestCertificateRequestValidateAcceptsRenewalWithTarget(t *testing.T) {
	id := uuid.New()
	r := &CertificateRequest{Type: RequestRenewal, TrustClass: TrustExternal, ExistingCertificateID: &id, PONumber: "PO-1"}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestCertificateRequestValidateRejectsUnknownTrustClass(t *testing.T) {
	r := &CertificateRequest{Type: RequestNew, CommonName: "app.example.com", TrustClass: CertTrustClass("bogus")}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for an unknown trust class")
	}
}

func TestCertificateRequestValidateRequiresPOForExternal(t *testing.T) {
	r := &CertificateRequest{Type: RequestNew, TrustClass: TrustExternal, CommonName: "app.example.com"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for an external request with no PO number")
	}
	r.PONumber = "PO-42"
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil once a PO number is supplied", err)
	}
}

func TestCertificateRequestRequiresPO(t *testing.T) {
	internal := &CertificateRequest{TrustClass: TrustInternal}
	if internal.RequiresPO() {
		t.Error("an internal request must not require a PO number")
	}
	external := &CertificateRequest{TrustClass: TrustExternal}
	if !external.RequiresPO() {
		t.Error("an external request must require a PO number")
	}
}

func TestCertificateRequestOverdueSLA(t *testing.T) {
	approved := time.Now().Add(-4 * 24 * time.Hour)
	r := &CertificateRequest{Status: RequestInProgress, ApprovedAt: &approved}
	if !r.OverdueSLA(3) {
		t.Error("a ticket approved 4 days ago must be overdue against a 3-day SLA")
	}
	if r.OverdueSLA(5) {
		t.Error("a ticket approved 4 days ago must not be overdue against a 5-day SLA")
	}
}

func TestCertificateRequestOverdueSLAIgnoresUnapprovedOrClosedTickets(t *testing.T) {
	longAgo := time.Now().Add(-30 * 24 * time.Hour)
	pending := &CertificateRequest{Status: RequestPending}
	if pending.OverdueSLA(3) {
		t.Error("a pending ticket with no ApprovedAt must never be overdue")
	}
	fulfilled := &CertificateRequest{Status: RequestFulfilled, ApprovedAt: &longAgo}
	if fulfilled.OverdueSLA(3) {
		t.Error("a closed ticket must never be flagged overdue, however old")
	}
}

func TestCertificateRequestDelivered(t *testing.T) {
	r := &CertificateRequest{}
	if r.Delivered() {
		t.Error("a ticket with no DeliveredAt must not report Delivered")
	}
	now := time.Now()
	r.DeliveredAt = &now
	if !r.Delivered() {
		t.Error("a ticket with DeliveredAt set must report Delivered")
	}
}

func TestRequestStatusOpenAndClosed(t *testing.T) {
	for _, s := range []RequestStatus{RequestPending, RequestInProgress} {
		if !s.Open() || s.Closed() {
			t.Errorf("%q must be Open and not Closed", s)
		}
	}
	for _, s := range []RequestStatus{RequestFulfilled, RequestRejected, RequestCancelled} {
		if s.Open() || !s.Closed() {
			t.Errorf("%q must be Closed and not Open", s)
		}
	}
}
