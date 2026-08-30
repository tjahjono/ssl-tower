package service

import (
	"context"
	"strings"
	"testing"
	"time"

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

// fakeRootCARepo is a minimal in-memory domain.RootCARepository, mirroring
// fakeCertificateRepo's shape.
type fakeRootCARepo struct {
	byID map[uuid.UUID]*domain.RootCA
}

func newFakeRootCARepo() *fakeRootCARepo {
	return &fakeRootCARepo{byID: map[uuid.UUID]*domain.RootCA{}}
}

func (f *fakeRootCARepo) Create(_ context.Context, c *domain.RootCA) error {
	c.ID = uuid.New()
	f.byID[c.ID] = c
	return nil
}

func (f *fakeRootCARepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.byID, id)
	return nil
}

func (f *fakeRootCARepo) GetByID(_ context.Context, id uuid.UUID) (*domain.RootCA, error) {
	c, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return c, nil
}

func (f *fakeRootCARepo) List(_ context.Context) ([]*domain.RootCA, error) {
	out := make([]*domain.RootCA, 0, len(f.byID))
	for _, c := range f.byID {
		out = append(out, c)
	}
	return out, nil
}

// fakeEncryptionRotationRepository is a stand-in for
// domain.EncryptionRotationRepository. Most tests in this file never touch
// RotateEncryptionKey, so it just counts calls and returns whatever result/
// err it's configured with. When total > 0 it also calls progress once per
// simulated row (0, total) then (1, total)...(total, total) — real enough to
// exercise CertificateService's job-tracking/polling plumbing (v1.6) without
// a real database.
type fakeEncryptionRotationRepository struct {
	result domain.RotationResult
	err    error
	total  int
	calls  int
	// block, when non-nil, is received from before returning — lets a test
	// hold a rotation "in flight" for as long as it wants, deterministically,
	// instead of racing a fast/instant fake call against a concurrency check.
	block chan struct{}
}

func (f *fakeEncryptionRotationRepository) RotateEncryptionKey(_ context.Context, _, _ *secret.Sealer, _ string, progress func(done, total int)) (domain.RotationResult, error) {
	f.calls++
	if progress != nil && f.total > 0 {
		for done := 0; done <= f.total; done++ {
			progress(done, f.total)
		}
	}
	if f.block != nil {
		<-f.block
	}
	return f.result, f.err
}

func newTestCertificateService(t *testing.T) *CertificateService {
	t.Helper()
	sealer, err := secret.NewSealer("")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	// 30/7/1-day thresholds mirror .env.example's documented defaults —
	// tests written before thresholds moved to the portal (v1.5) assume
	// these same values, so newTestSettingsService is seeded with them here
	// rather than zero, which would make every certificate look perpetually
	// healthy regardless of how close to expiry it actually is.
	settings := newTestSettingsService(domain.AppSettings{ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1})
	return NewCertificateService(newFakeCertificateRepo(), newFakeRootCARepo(), &fakeEncryptionRotationRepository{}, sealer, settings, discardLogger(), CertificateOptions{})
}

func TestStartEncryptionKeyRotationReportsProgressToCompletion(t *testing.T) {
	rotationRepo := &fakeEncryptionRotationRepository{
		result: domain.RotationResult{CertificatesReencrypted: 3, RootCAsReencrypted: 1},
		total:  4,
	}
	sealer, err := secret.NewSealer("")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	settings := newTestSettingsService(domain.AppSettings{})
	svc := NewCertificateService(newFakeCertificateRepo(), newFakeRootCARepo(), rotationRepo, sealer, settings, discardLogger(), CertificateOptions{})

	id, err := svc.StartEncryptionKeyRotation("")
	if err != nil {
		t.Fatalf("StartEncryptionKeyRotation: %v", err)
	}

	// Poll until the fake repo's goroutine finishes — it runs synchronously
	// fast, but this is still a real goroutine hand-off, so poll rather than
	// assume it's done by the time StartEncryptionKeyRotation returns.
	deadline := time.Now().Add(2 * time.Second)
	var status RotationStatus
	for time.Now().Before(deadline) {
		var ok bool
		status, ok = svc.EncryptionKeyRotationStatus(id)
		if !ok {
			t.Fatalf("EncryptionKeyRotationStatus(%s) = not found, want the job just started", id)
		}
		if status.Finished {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !status.Finished {
		t.Fatal("rotation did not finish within the test deadline")
	}
	if status.Err != nil {
		t.Fatalf("status.Err = %v, want nil", status.Err)
	}
	if status.Result.CertificatesReencrypted != 3 || status.Result.RootCAsReencrypted != 1 {
		t.Fatalf("status.Result = %+v, want {3 1}", status.Result)
	}
	if status.Done != status.Total || status.Total != 4 {
		t.Fatalf("status Done/Total = %d/%d, want 4/4 once finished", status.Done, status.Total)
	}

	if rotationRepo.calls != 1 {
		t.Fatalf("expected exactly one RotateEncryptionKey call, got %d", rotationRepo.calls)
	}

	// MarkRotationReported must return true exactly once, for the one HTTP
	// request that gets to record the audit entry.
	if !svc.MarkRotationReported(id) {
		t.Fatal("expected the first MarkRotationReported call to return true")
	}
	if svc.MarkRotationReported(id) {
		t.Fatal("expected a second MarkRotationReported call to return false")
	}

	// A random/stale ID must never be mistaken for the real job.
	if _, ok := svc.EncryptionKeyRotationStatus(uuid.New()); ok {
		t.Fatal("expected EncryptionKeyRotationStatus for an unrelated ID to report not found")
	}
}

func TestStartEncryptionKeyRotationRejectsBadKeyBeforeStarting(t *testing.T) {
	rotationRepo := &fakeEncryptionRotationRepository{}
	sealer, err := secret.NewSealer("")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	settings := newTestSettingsService(domain.AppSettings{})
	svc := NewCertificateService(newFakeCertificateRepo(), newFakeRootCARepo(), rotationRepo, sealer, settings, discardLogger(), CertificateOptions{})

	if _, err := svc.StartEncryptionKeyRotation("not-valid-base64-key"); err == nil {
		t.Fatal("expected an error for a malformed encryption key")
	}
	if rotationRepo.calls != 0 {
		t.Fatalf("expected no rotation attempt for a key that fails validation, got %d calls", rotationRepo.calls)
	}
}

func TestStartEncryptionKeyRotationRefusesConcurrentRotation(t *testing.T) {
	rotationRepo := &fakeEncryptionRotationRepository{block: make(chan struct{})}
	sealer, err := secret.NewSealer("")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	settings := newTestSettingsService(domain.AppSettings{})
	svc := NewCertificateService(newFakeCertificateRepo(), newFakeRootCARepo(), rotationRepo, sealer, settings, discardLogger(), CertificateOptions{})

	firstID, err := svc.StartEncryptionKeyRotation("")
	if err != nil {
		t.Fatalf("first StartEncryptionKeyRotation: %v", err)
	}

	// The fake repo is blocked inside its call right now (waiting on
	// rotationRepo.block), so the first job cannot have finished yet — a
	// second Start must be refused deterministically, not just "usually".
	if _, err := svc.StartEncryptionKeyRotation("another-key"); err == nil {
		t.Fatal("expected a second rotation to be refused while the first is still running")
	}

	close(rotationRepo.block)
	deadline := time.Now().Add(2 * time.Second)
	var status RotationStatus
	for time.Now().Before(deadline) {
		var ok bool
		status, ok = svc.EncryptionKeyRotationStatus(firstID)
		if !ok {
			t.Fatalf("EncryptionKeyRotationStatus(%s) = not found", firstID)
		}
		if status.Finished {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !status.Finished {
		t.Fatal("first rotation did not finish within the test deadline")
	}

	// Now that the first has finished, a new rotation must be accepted.
	if _, err := svc.StartEncryptionKeyRotation(""); err != nil {
		t.Fatalf("expected a rotation to be accepted once the previous one finished, got %v", err)
	}
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

// buildTestRootCAPEMs builds a self-signed, IsCA:true certificate + its PEM
// key pair — the shape UploadRootCA expects. SelfSign already produces an
// IsCA:true certificate, so it doubles as a Root CA fixture.
func buildTestRootCAPEMs(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	csrPEM, key, err := certutil.CreateCSR(certutil.CSRRequest{
		Subject: certutil.Subject{CommonName: "Test Root CA"},
		KeySpec: certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048},
	})
	if err != nil {
		t.Fatalf("CreateCSR (ca): %v", err)
	}
	csr, err := certutil.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM (ca): %v", err)
	}
	_, caCertPEM, err := certutil.SelfSign(csr, key, 3650, nil)
	if err != nil {
		t.Fatalf("SelfSign (ca): %v", err)
	}
	caKeyPEM, err := certutil.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM (ca): %v", err)
	}
	return caCertPEM, caKeyPEM
}

func TestUploadRootCARejectsKeyMismatch(t *testing.T) {
	svc := newTestCertificateService(t)
	caCertPEM, _ := buildTestRootCAPEMs(t)
	_, otherKeyPEM := buildTestRootCAPEMs(t)

	_, err := svc.UploadRootCA(context.Background(), "Mismatched CA", caCertPEM, otherKeyPEM)
	if err == nil {
		t.Fatal("expected an error uploading a certificate paired with the wrong private key")
	}
}

func TestUploadRootCARejectsNonCACertificate(t *testing.T) {
	svc := newTestCertificateService(t)
	// An ordinary self-signed leaf via CreateCSR+SelfSign IS IsCA:true (see
	// SelfSign's own doc comment), so build a non-CA cert via a plain leaf
	// signed BY a CA instead — that's what SignWithCA produces.
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := svc.UploadRootCA(context.Background(), "Valid CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA (setup): %v", err)
	}
	pending, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName: "leaf.example.com", KeyAlgorithm: "rsa", KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	signed, err := svc.SignWithRootCA(context.Background(), pending.ID, ca.ID, 30)
	if err != nil {
		t.Fatalf("SignWithRootCA (setup): %v", err)
	}
	keyPEM, err := svc.PrivateKey(signed)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}

	if _, err := svc.UploadRootCA(context.Background(), "Not actually a CA", signed.CertificatePEM, keyPEM); err == nil {
		t.Fatal("expected an error uploading a non-CA certificate as a Root CA")
	}
}

func TestGenerateRootCAPersistsAndCanSign(t *testing.T) {
	svc := newTestCertificateService(t)
	ca, err := svc.GenerateRootCA(context.Background(), "Acme Generated CA",
		certutil.Subject{CommonName: "Acme Generated Root CA", Organization: "Acme Corp"},
		certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048}, 3650)
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	if ca.Name != "Acme Generated CA" {
		t.Errorf("Name = %q, want %q", ca.Name, "Acme Generated CA")
	}
	if !strings.Contains(ca.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Error("CertificatePEM is not PEM encoded")
	}
	if ca.FingerprintSHA256 == "" {
		t.Error("expected a computed fingerprint")
	}
	if ca.PublicKeyAlgorithm != "RSA" || ca.KeySize != 2048 {
		t.Errorf("PublicKeyAlgorithm/KeySize = %s/%d, want RSA/2048", ca.PublicKeyAlgorithm, ca.KeySize)
	}

	// The generated CA must actually be usable to sign a pending CSR, the
	// same as an uploaded one — proves the persisted (sealed, then reopened)
	// key round-trips correctly.
	pending, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName: "internal.example.com", KeyAlgorithm: "rsa", KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	signed, err := svc.SignWithRootCA(context.Background(), pending.ID, ca.ID, 30)
	if err != nil {
		t.Fatalf("SignWithRootCA using a generated CA: %v", err)
	}
	if signed.SignedByRootCAID == nil || *signed.SignedByRootCAID != ca.ID {
		t.Fatalf("SignedByRootCAID = %v, want %v", signed.SignedByRootCAID, ca.ID)
	}
}

func TestGenerateRootCARejectsMissingName(t *testing.T) {
	svc := newTestCertificateService(t)
	_, err := svc.GenerateRootCA(context.Background(), "  ",
		certutil.Subject{CommonName: "Acme Generated Root CA"},
		certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048}, 3650)
	if err == nil {
		t.Fatal("expected an error generating a root CA with no name")
	}
}

func TestGenerateRootCARejectsMissingCommonName(t *testing.T) {
	svc := newTestCertificateService(t)
	_, err := svc.GenerateRootCA(context.Background(), "Acme Generated CA",
		certutil.Subject{}, certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048}, 3650)
	if err == nil {
		t.Fatal("expected an error generating a root CA with no common name")
	}
}

// TestGenerateRootCAAndSignIssuesCertificateWithNewCA is the direct
// regression test for v1.9's "create a new CA" option in the
// pending-certificate signing dropdown: one call both mints a Root CA and
// signs the pending certificate with it.
func TestGenerateRootCAAndSignIssuesCertificateWithNewCA(t *testing.T) {
	svc := newTestCertificateService(t)
	pending, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName: "inline-ca.example.com", KeyAlgorithm: "rsa", KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	ca, signed, err := svc.GenerateRootCAAndSign(context.Background(), pending.ID, "Inline Generated CA",
		certutil.Subject{CommonName: "Inline Generated Root CA", Organization: "Acme Corp"},
		certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048}, 3650, 30)
	if err != nil {
		t.Fatalf("GenerateRootCAAndSign: %v", err)
	}
	if ca == nil || ca.Name != "Inline Generated CA" {
		t.Fatalf("expected the new CA to be returned, got %+v", ca)
	}
	if signed == nil {
		t.Fatal("expected the signed certificate to be returned")
	}
	if signed.SelfSigned {
		t.Error("a certificate signed by a generated CA must not be marked SelfSigned")
	}
	if signed.SignedByRootCAID == nil || *signed.SignedByRootCAID != ca.ID {
		t.Fatalf("SignedByRootCAID = %v, want %v", signed.SignedByRootCAID, ca.ID)
	}
	if got := signed.TrustClass(); got != domain.TrustInternal {
		t.Fatalf("TrustClass() = %q, want %q", got, domain.TrustInternal)
	}

	// The generated CA must also be independently usable afterward, exactly
	// like one generated from the Issuers page — proves this didn't create
	// some special, less-capable CA record.
	listed, err := svc.ListRootCAs(context.Background())
	if err != nil {
		t.Fatalf("ListRootCAs: %v", err)
	}
	found := false
	for _, c := range listed {
		if c.ID == ca.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the generated CA to appear in ListRootCAs")
	}
}

// TestGenerateRootCAAndSignLeavesCAInPlaceWhenSigningFails covers the
// documented "two separate writes, not one transaction" design: if signing
// fails after the CA already exists, the CA is still returned (non-nil) and
// still persisted rather than being rolled back.
func TestGenerateRootCAAndSignLeavesCAInPlaceWhenSigningFails(t *testing.T) {
	svc := newTestCertificateService(t)
	missingID := uuid.New() // no pending certificate with this ID exists

	ca, signed, err := svc.GenerateRootCAAndSign(context.Background(), missingID, "Orphan-safe CA",
		certutil.Subject{CommonName: "Orphan-safe Root CA"},
		certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048}, 3650, 30)
	if err == nil {
		t.Fatal("expected an error signing a nonexistent certificate")
	}
	if signed != nil {
		t.Fatalf("expected no signed certificate on failure, got %+v", signed)
	}
	if ca == nil {
		t.Fatal("expected the generated CA to still be returned even though signing failed")
	}

	listed, err := svc.ListRootCAs(context.Background())
	if err != nil {
		t.Fatalf("ListRootCAs: %v", err)
	}
	found := false
	for _, c := range listed {
		if c.ID == ca.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the generated CA to remain persisted despite the failed sign")
	}
}

func TestSignWithRootCAMarksCertificateInternal(t *testing.T) {
	svc := newTestCertificateService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := svc.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	pending, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName: "internal.example.com", KeyAlgorithm: "rsa", KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if pending.TrustClass() != domain.TrustPending {
		t.Fatalf("a not-yet-issued certificate must be TrustPending, got %q", pending.TrustClass())
	}

	signed, err := svc.SignWithRootCA(context.Background(), pending.ID, ca.ID, 30)
	if err != nil {
		t.Fatalf("SignWithRootCA: %v", err)
	}
	if signed.SelfSigned {
		t.Error("a CA-signed certificate must not be marked SelfSigned")
	}
	if signed.SignedByRootCAID == nil || *signed.SignedByRootCAID != ca.ID {
		t.Fatalf("SignedByRootCAID = %v, want %v", signed.SignedByRootCAID, ca.ID)
	}
	if got := signed.TrustClass(); got != domain.TrustInternal {
		t.Fatalf("TrustClass() = %q, want %q", got, domain.TrustInternal)
	}
	if signed.ChainPEM != ca.CertificatePEM {
		t.Error("expected the CA's own certificate to become the issued certificate's chain")
	}
}

func TestBulkRenewInternalMixedBatch(t *testing.T) {
	svc := newTestCertificateService(t)
	caCertPEM, caKeyPEM := buildTestRootCAPEMs(t)
	ca, err := svc.UploadRootCA(context.Background(), "Acme Internal CA", caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("UploadRootCA: %v", err)
	}

	// A valid internal, issued certificate — should renew cleanly into a
	// brand-new record, leaving the original alone.
	pending, err := svc.CreateCSR(context.Background(), CreateCSRInput{
		CommonName: "renew-me.example.com", KeyAlgorithm: "rsa", KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	issued, err := svc.SignWithRootCA(context.Background(), pending.ID, ca.ID, 30)
	if err != nil {
		t.Fatalf("SignWithRootCA: %v", err)
	}

	// An externally-issued certificate: not self-signed (Subject != Issuer)
	// and not linked to an uploaded Root CA record, since Import doesn't set
	// SignedByRootCAID — exactly what "pasted in from an outside CA" looks
	// like. Out of scope for bulk renewal; must be reported as a failure
	// rather than aborting the whole batch.
	caCert, err := certutil.ParseCertificatesPEM(caCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatesPEM: %v", err)
	}
	caKey, err := certutil.ParsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	extCSRPEM, _, err := certutil.CreateCSR(certutil.CSRRequest{
		Subject: certutil.Subject{CommonName: "external.example.com"},
		KeySpec: certutil.KeySpec{Algorithm: certutil.AlgorithmRSA, Bits: 2048},
	})
	if err != nil {
		t.Fatalf("CreateCSR (external leaf): %v", err)
	}
	extCSR, err := certutil.ParseCSRPEM(extCSRPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	_, extLeafPEM, err := certutil.SignWithCA(extCSR, caCert[0], caKey, 30, nil)
	if err != nil {
		t.Fatalf("SignWithCA (external leaf): %v", err)
	}
	external, err := svc.Import(context.Background(), ImportInput{CertificatePEM: extLeafPEM})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if external.TrustClass() != domain.TrustExternal {
		t.Fatalf("test setup: expected TrustExternal, got %q", external.TrustClass())
	}

	missingID := uuid.New()

	outcomes := svc.BulkRenewInternal(context.Background(), BulkRenewInput{
		CertificateIDs: []uuid.UUID{issued.ID, external.ID, missingID},
		RootCAID:       ca.ID,
		Days:           30,
	})
	if len(outcomes) != 3 {
		t.Fatalf("expected 3 outcomes, got %d", len(outcomes))
	}

	renewed := outcomes[0]
	if renewed.CertificateID != issued.ID {
		t.Fatalf("outcomes[0].CertificateID = %v, want %v", renewed.CertificateID, issued.ID)
	}
	if renewed.Err != nil {
		t.Fatalf("expected the internal certificate to renew, got error: %v", renewed.Err)
	}
	if renewed.NewCertificate == nil {
		t.Fatal("expected a new certificate record for the successful renewal")
	}
	if renewed.NewCertificate.ID == issued.ID {
		t.Fatal("renewal must produce a fresh record, not mutate the original in place")
	}
	if got := renewed.NewCertificate.TrustClass(); got != domain.TrustInternal {
		t.Fatalf("renewed certificate TrustClass() = %q, want internal", got)
	}

	rejected := outcomes[1]
	if rejected.Err == nil {
		t.Fatal("expected renewing an external certificate to fail — bulk renewal is internal-only")
	}
	if rejected.NewCertificate != nil {
		t.Fatal("a rejected renewal must not produce a new certificate")
	}

	missing := outcomes[2]
	if missing.Err == nil {
		t.Fatal("expected a nonexistent certificate ID to fail")
	}

	// The original internal certificate must be untouched — still present,
	// still carrying its own certificate material — since renewal always
	// creates a fresh record rather than mutating history.
	original, err := svc.Get(context.Background(), issued.ID)
	if err != nil {
		t.Fatalf("Get (original): %v", err)
	}
	if original.CertificatePEM != issued.CertificatePEM {
		t.Error("the original certificate record must be left untouched by bulk renewal")
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
