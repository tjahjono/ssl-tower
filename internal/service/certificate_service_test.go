package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
	"github.com/ivangiovn/ssl-generator/internal/pkg/secret"
)

// fakeCertificateRepo is a minimal in-memory domain.CertificateRepository for
// exercising CertificateService without a real Postgres instance.
type fakeCertificateRepo struct {
	byID map[uuid.UUID]*domain.Certificate
}

func newFakeCertificateRepo() *fakeCertificateRepo {
	return &fakeCertificateRepo{byID: map[uuid.UUID]*domain.Certificate{}}
}

func (f *fakeCertificateRepo) Create(_ context.Context, c *domain.Certificate) error {
	c.ID = uuid.New()
	f.byID[c.ID] = c
	return nil
}

func (f *fakeCertificateRepo) Update(_ context.Context, c *domain.Certificate) error {
	if _, ok := f.byID[c.ID]; !ok {
		return domain.ErrNotFound
	}
	f.byID[c.ID] = c
	return nil
}

func (f *fakeCertificateRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.byID, id)
	return nil
}

func (f *fakeCertificateRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Certificate, error) {
	c, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return c, nil
}

func (f *fakeCertificateRepo) List(_ context.Context, _ domain.CertificateFilter) ([]*domain.Certificate, error) {
	out := make([]*domain.Certificate, 0, len(f.byID))
	for _, c := range f.byID {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeCertificateRepo) FindSharingFingerprint(_ context.Context, _ string, _ uuid.UUID) ([]*domain.Certificate, error) {
	return nil, nil
}

func (f *fakeCertificateRepo) AlertLevel(_ context.Context, _ uuid.UUID) (int, error) { return 0, nil }
func (f *fakeCertificateRepo) SetAlertLevel(_ context.Context, _ uuid.UUID, _ int) error {
	return nil
}

func newTestCertificateService(t *testing.T) *CertificateService {
	t.Helper()
	sealer, err := secret.NewSealer("")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return NewCertificateService(newFakeCertificateRepo(), sealer, discardLogger(), CertificateOptions{})
}

func TestImportCSRStoresSubjectSANsAndRequestedEKU(t *testing.T) {
	svc := newTestCertificateService(t)
	req := certutil.CSRRequest{
		Subject: certutil.Subject{
			CommonName:   "laptop.example.com",
			Organization: "Example Pte Ltd",
			Country:      "ID",
		},
		DNSNames:     []string{"laptop.example.com", "alt.example.com"},
		KeySpec:      certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048},
		ExtKeyUsages: []string{certutil.EKUClientAuth},
	}
	csrPEM, key, err := certutil.CreateCSR(req)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	keyPEM, err := certutil.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}

	record, err := svc.ImportCSR(context.Background(), ImportCSRInput{
		CSRPEM:        csrPEM,
		PrivateKeyPEM: keyPEM,
		Owner:         "Laptop team",
	})
	if err != nil {
		t.Fatalf("ImportCSR: %v", err)
	}
	if record.Status != domain.CertPending {
		t.Errorf("status = %q, want pending", record.Status)
	}
	if record.Origin != domain.OriginGenerated {
		t.Errorf("origin = %q, want generated", record.Origin)
	}
	if record.CommonName != "laptop.example.com" {
		t.Errorf("common name = %q", record.CommonName)
	}
	if record.Organization != "Example Pte Ltd" {
		t.Errorf("organization = %q", record.Organization)
	}
	if len(record.DNSNames) != 2 {
		t.Errorf("dns names = %v", record.DNSNames)
	}
	if !record.HasPrivateKey() {
		t.Error("expected the imported key to be stored")
	}
	if len(record.ExtKeyUsage) != 1 || record.ExtKeyUsage[0] != certutil.EKUClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [%s]", record.ExtKeyUsage, certutil.EKUClientAuth)
	}
}

func TestImportCSRRejectsMismatchedKey(t *testing.T) {
	svc := newTestCertificateService(t)
	csrPEM, _, err := certutil.CreateCSR(certutil.CSRRequest{
		Subject: certutil.Subject{CommonName: "one.example.com"},
		KeySpec: certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	_, otherKey, err := certutil.CreateCSR(certutil.CSRRequest{
		Subject: certutil.Subject{CommonName: "two.example.com"},
		KeySpec: certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	otherKeyPEM, err := certutil.EncodePrivateKeyPEM(otherKey)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}

	_, err = svc.ImportCSR(context.Background(), ImportCSRInput{CSRPEM: csrPEM, PrivateKeyPEM: otherKeyPEM})
	if err == nil {
		t.Fatal("expected an error for a key that doesn't match the CSR")
	}
}

func TestGroupByIssuer(t *testing.T) {
	issued := func(issuer string) *domain.Certificate {
		return &domain.Certificate{
			Status:         domain.CertIssued,
			CertificatePEM: "present",
			Subject:        "CN=example.com",
			Issuer:         issuer,
		}
	}
	pending := &domain.Certificate{Status: domain.CertPending}

	certs := []*domain.Certificate{
		issued("CN=Let's Encrypt"),
		issued("CN=Let's Encrypt"),
		pending,
		issued("CN=DigiCert"),
	}

	groups := GroupByIssuer(certs)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups (Let's Encrypt, DigiCert, Not yet issued), got %d: %+v", len(groups), groups)
	}

	// Largest group first.
	if groups[0].Issuer != "Let's Encrypt" || len(groups[0].Certificates) != 2 {
		t.Fatalf("expected Let's Encrypt with 2 certificates to sort first, got %+v", groups[0])
	}

	var sawDigiCert, sawPending bool
	for _, g := range groups[1:] {
		switch g.Issuer {
		case "DigiCert":
			sawDigiCert = len(g.Certificates) == 1
		case "Not yet issued":
			sawPending = len(g.Certificates) == 1
		}
	}
	if !sawDigiCert {
		t.Error("expected a DigiCert group with exactly one certificate")
	}
	if !sawPending {
		t.Error("expected a Not yet issued group holding the pending certificate")
	}
}

func TestCreateCSRStoresRequestedExtKeyUsage(t *testing.T) {
	svc := newTestCertificateService(t)
	record, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName:   "pending.example.com",
		KeyAlgorithm: "rsa",
		KeyBits:      2048,
		ExtKeyUsages: []string{certutil.EKUCodeSigning},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if len(record.ExtKeyUsage) != 1 || record.ExtKeyUsage[0] != certutil.EKUCodeSigning {
		t.Fatalf("ExtKeyUsage = %v, want [%s]", record.ExtKeyUsage, certutil.EKUCodeSigning)
	}
}

func TestCreateCSRRejectsUnknownExtKeyUsage(t *testing.T) {
	svc := newTestCertificateService(t)
	_, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName:   "bad.example.com",
		KeyAlgorithm: "rsa",
		KeyBits:      2048,
		ExtKeyUsages: []string{"not_a_real_eku"},
	})
	if err == nil {
		t.Fatal("expected an error for an unrecognised EKU")
	}
}

func TestSelfSignAppliesRequestedExtKeyUsage(t *testing.T) {
	svc := newTestCertificateService(t)
	record, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName:   "selfsigned.example.com",
		KeyAlgorithm: "rsa",
		KeyBits:      2048,
		ExtKeyUsages: []string{certutil.EKUClientAuth},
		SelfSignDays: 30,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if record.Status != domain.CertIssued {
		t.Fatalf("expected the certificate to be issued, got status %q", record.Status)
	}
	if len(record.ExtKeyUsage) != 1 || record.ExtKeyUsage[0] != certutil.EKUClientAuth {
		t.Fatalf("issued ExtKeyUsage = %v, want [%s]", record.ExtKeyUsage, certutil.EKUClientAuth)
	}
}

func TestAttachCertificateOverwritesExtKeyUsageWithIssuedLeaf(t *testing.T) {
	svc := newTestCertificateService(t)
	pending, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName:   "attach.example.com",
		KeyAlgorithm: "rsa",
		KeyBits:      2048,
		ExtKeyUsages: []string{certutil.EKUServerAuth},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	// The "CA" signs with a different EKU than was requested — a realistic
	// case, since a public CA decides EKU from its own product profile.
	keyPEM, err := svc.PrivateKey(pending)
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
	_, certPEM, err := certutil.SelfSign(csr, key, 365, []string{certutil.EKUClientAuth, certutil.EKUCodeSigning})
	if err != nil {
		t.Fatalf("SelfSign: %v", err)
	}

	updated, err := svc.AttachCertificate(context.Background(), pending.ID, certPEM)
	if err != nil {
		t.Fatalf("AttachCertificate: %v", err)
	}
	want := []string{certutil.EKUClientAuth, certutil.EKUCodeSigning}
	if len(updated.ExtKeyUsage) != len(want) || updated.ExtKeyUsage[0] != want[0] || updated.ExtKeyUsage[1] != want[1] {
		t.Errorf("ExtKeyUsage after attach = %v, want %v (the issued leaf's, not the original request)", updated.ExtKeyUsage, want)
	}
}

func TestGroupByIssuerRequiresCertificateData(t *testing.T) {
	// A certificate marked issued but with no certificate PEM actually on
	// file must land in "Not yet issued", not silently vanish or crash.
	c := &domain.Certificate{Status: domain.CertIssued}
	groups := GroupByIssuer([]*domain.Certificate{c})
	if len(groups) != 1 || groups[0].Issuer != "Not yet issued" {
		t.Fatalf("expected a single Not yet issued group, got %+v", groups)
	}
}
