// Package service holds the application's business rules. It depends on the
// domain ports only, never on pgx or net/http.
package service

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
	"github.com/ivangiovn/ssl-generator/internal/pkg/secret"
)

// Alerter is notified after a certificate is created, issued, or imported —
// and again on every periodic alert sweep — so it can decide whether the
// current state crosses a threshold worth paging someone about. Evaluate is
// fire-and-forget from the caller's side: it never returns an error, because
// a broken notification channel must never fail a certificate operation.
type Alerter interface {
	Evaluate(ctx context.Context, c *domain.Certificate)
}

// CertificateService implements the certificate vault: generating signing
// requests, importing certificates uploaded directly (PEM or PKCS#12), and
// exporting the result in whichever format the target platform wants.
type CertificateService struct {
	repo         domain.CertificateRepository
	rootCAs      domain.RootCARepository
	rotationRepo domain.EncryptionRotationRepository
	// sealer is swapped in place by RotateEncryptionKey, which is why it's
	// an atomic pointer rather than a plain field — every other method
	// reads it via currentSealer() so a rotation takes effect for the very
	// next request, no restart needed.
	sealer          atomic.Pointer[secret.Sealer]
	settings        *SettingsService
	log             *slog.Logger
	warningPercent  int
	criticalPercent int
	alerter         Alerter
}

// CertificateOptions configures the percent-of-lifetime-remaining expiry
// thresholds used for health/summary classification (the day-based
// WarningDays/CriticalDays counterparts are portal-editable — see
// SettingsService and Thresholds below — while these percent thresholds
// stay env-only; the alerting service has its own, separately configured
// set — see AlertThresholds). See domain.Certificate.HealthStatus for how
// the day and percent checks combine and why the percent check only ever
// affects externally-issued certificates.
type CertificateOptions struct {
	WarningPercent  int
	CriticalPercent int
}

// NewCertificateService builds the service. settings supplies the live,
// portal-editable day-based expiry thresholds (see Thresholds); rotationRepo
// is used only by RotateEncryptionKey.
func NewCertificateService(repo domain.CertificateRepository, rootCAs domain.RootCARepository, rotationRepo domain.EncryptionRotationRepository, sealer *secret.Sealer, settings *SettingsService, log *slog.Logger, opts CertificateOptions) *CertificateService {
	if opts.WarningPercent <= 0 {
		opts.WarningPercent = 33
	}
	if opts.CriticalPercent <= 0 {
		opts.CriticalPercent = 10
	}
	s := &CertificateService{
		repo: repo, rootCAs: rootCAs, rotationRepo: rotationRepo, settings: settings, log: log,
		warningPercent: opts.WarningPercent, criticalPercent: opts.CriticalPercent,
	}
	s.sealer.Store(sealer)
	return s
}

// SetAlerter wires an Alerter to be evaluated after every mutation and
// periodic sweep. Optional — a CertificateService with no alerter configured
// just skips notification.
func (s *CertificateService) SetAlerter(a Alerter) { s.alerter = a }

// currentSealer returns the sealer actively used to encrypt/decrypt stored
// private keys — always the live one, even immediately after a successful
// RotateEncryptionKey call from a concurrent request.
func (s *CertificateService) currentSealer() *secret.Sealer { return s.sealer.Load() }

// Thresholds exposes the configured (live, portal-editable) expiry windows
// for display.
func (s *CertificateService) Thresholds() (warning, critical int) {
	cur := s.settings.Current()
	return cur.ExpiryWarningDays, cur.ExpiryCriticalDays
}

// PercentThresholds exposes the configured percent-of-lifetime-remaining
// windows for display — the counterpart to Thresholds, kept as a separate
// method rather than widening Thresholds's return so every existing call
// site didn't need updating just to plumb these through. Unlike Thresholds,
// these are still env-only/static — see CertificateOptions.
func (s *CertificateService) PercentThresholds() (warning, critical int) {
	return s.warningPercent, s.criticalPercent
}

// KeyEncryptionEnabled reports whether private keys are encrypted at rest.
func (s *CertificateService) KeyEncryptionEnabled() bool { return s.currentSealer().Enabled() }

// RotateEncryptionKey changes the AES key that encrypts every stored
// private key — certificates and root CAs alike — to newKeyBase64 (a
// base64-encoded 32-byte key, or "" to turn encryption off and store keys
// as plaintext PEM going forward, same convention as APP_ENCRYPTION_KEY
// always had). Unlike every other portal setting, this is not a plain
// value swap: every already-stored private key was encrypted under the
// *old* key, so this decrypts each one with the sealer currently active and
// re-encrypts it with the new one, atomically, via rotationRepo — either
// every row (across both tables) and the new key setting all change
// together, or nothing does. Only once that transaction commits does the
// live sealer this service uses for every future request actually swap;
// a validation failure or a mid-rotation error leaves the vault exactly as
// it was, still readable under the old key.
func (s *CertificateService) RotateEncryptionKey(ctx context.Context, newKeyBase64 string) (domain.RotationResult, error) {
	newSealer, err := secret.NewSealer(newKeyBase64)
	if err != nil {
		return domain.RotationResult{}, domain.Invalid("encryption_key", err.Error())
	}

	oldSealer := s.currentSealer()
	result, err := s.rotationRepo.RotateEncryptionKey(ctx, oldSealer, newSealer, newKeyBase64)
	if err != nil {
		return domain.RotationResult{}, fmt.Errorf("certificate service: rotate encryption key: %w", err)
	}

	s.sealer.Store(newSealer)
	s.log.Info("encryption key rotated",
		"certificates_reencrypted", result.CertificatesReencrypted,
		"root_cas_reencrypted", result.RootCAsReencrypted,
		"encryption_now_enabled", newSealer.Enabled())
	return result, nil
}

// CreateCSRInput is the form payload for generating a new signing request.
type CreateCSRInput struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	Email              string
	SANs               string // newline / comma separated, DNS names and IPs mixed
	KeyAlgorithm       string
	KeyBits            int
	KeyCurve           string
	Owner              string
	Notes              string
	SelfSignDays       int      // > 0 also issues a self-signed certificate right away
	ExtKeyUsages       []string // e.g. certutil.EKUServerAuth — requested via the CSR, and applied if self-signed
}

// CreateCSR generates a key pair and CSR, optionally self-signing it.
func (s *CertificateService) CreateCSR(ctx context.Context, in CreateCSRInput) (*domain.Certificate, error) {
	dnsNames, ips := splitSANs(in.SANs)
	ekus, err := certutil.NormalizeExtKeyUsages(in.ExtKeyUsages)
	if err != nil {
		return nil, domain.Invalid("ext_key_usage", err.Error())
	}

	req := certutil.CSRRequest{
		Subject: certutil.Subject{
			CommonName:         in.CommonName,
			Organization:       in.Organization,
			OrganizationalUnit: in.OrganizationalUnit,
			Country:            in.Country,
			Province:           in.Province,
			Locality:           in.Locality,
			Email:              in.Email,
		},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		KeySpec:      certutil.KeySpec{Algorithm: in.KeyAlgorithm, Bits: in.KeyBits, Curve: in.KeyCurve},
		ExtKeyUsages: ekus,
	}
	if err := req.Validate(); err != nil {
		return nil, domain.Invalid("csr", err.Error())
	}

	csrPEM, key, err := certutil.CreateCSR(req)
	if err != nil {
		return nil, err
	}
	keyPEM, err := certutil.EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	stored, err := s.currentSealer().Seal(keyPEM)
	if err != nil {
		return nil, err
	}

	record := &domain.Certificate{
		CommonName:          req.CommonName,
		Organization:        req.Organization,
		OrganizationalUnit:  req.OrganizationalUnit,
		Country:             strings.ToUpper(req.Country),
		Province:            req.Province,
		Locality:            req.Locality,
		Email:               req.Email,
		DNSNames:            req.DNSNames,
		IPAddresses:         req.IPAddresses,
		Origin:              domain.OriginGenerated,
		Owner:               strings.TrimSpace(in.Owner),
		KeyAlgorithm:        req.KeySpec.Algorithm,
		KeyBits:             req.KeySpec.Bits,
		KeyCurve:            req.KeySpec.Curve,
		CSRPEM:              csrPEM,
		PrivateKeyPEM:       stored,
		PrivateKeyEncrypted: s.currentSealer().Enabled(),
		ExtKeyUsage:         ekus,
		Status:              domain.CertPending,
		Notes:               strings.TrimSpace(in.Notes),
	}

	if in.SelfSignDays > 0 {
		parsed, err := certutil.ParseCSRPEM(csrPEM)
		if err != nil {
			return nil, err
		}
		cert, certPEM, err := certutil.SelfSign(parsed, key, in.SelfSignDays, ekus)
		if err != nil {
			return nil, err
		}
		applyIssuedCert(record, cert, certPEM, "")
	}

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// ImportInput is the payload for uploading a certificate directly as PEM,
// rather than generating a CSR in-app.
type ImportInput struct {
	// CertificatePEM may contain just the leaf, or a leaf plus its full
	// chain — the first block is treated as the leaf, same convention as
	// AttachCertificate. ChainPEM is appended after whatever chain blocks
	// CertificatePEM itself carried.
	CertificatePEM string
	ChainPEM       string
	// PrivateKeyPEM is optional — a certificate can be filed for reference
	// without its key, though downloads that need the key (.key, .pfx,
	// full .zip) won't be available for it.
	PrivateKeyPEM string
	Owner         string
	Notes         string
}

// Import stores a certificate uploaded as PEM. It is rejected if a supplied
// private key does not match the certificate.
func (s *CertificateService) Import(ctx context.Context, in ImportInput) (*domain.Certificate, error) {
	blob := strings.TrimSpace(in.CertificatePEM)
	if blob == "" {
		return nil, domain.Invalid("certificate_pem", "paste the certificate PEM")
	}
	certs, err := certutil.ParseCertificatesPEM(blob)
	if err != nil {
		return nil, domain.Invalid("certificate_pem", err.Error())
	}
	chain := certs[1:]
	if extra := strings.TrimSpace(in.ChainPEM); extra != "" {
		more, err := certutil.ParseCertificatesPEM(extra)
		if err != nil {
			return nil, domain.Invalid("chain_pem", err.Error())
		}
		chain = append(chain, more...)
	}

	record := &domain.Certificate{
		Origin: domain.OriginUploaded,
		Owner:  strings.TrimSpace(in.Owner),
		Notes:  strings.TrimSpace(in.Notes),
	}

	var storedKeyPEM string
	if keyPEM := strings.TrimSpace(in.PrivateKeyPEM); keyPEM != "" {
		key, err := certutil.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, domain.Invalid("private_key_pem", err.Error())
		}
		if !certutil.MatchesKey(certs[0], key) {
			return nil, domain.Invalid("private_key_pem", "this key does not match the uploaded certificate")
		}
		sealed, err := s.currentSealer().Seal(keyPEM)
		if err != nil {
			return nil, err
		}
		storedKeyPEM = sealed
		record.PrivateKeyEncrypted = s.currentSealer().Enabled()
		alg, bits := certutil.DescribePublicKey(key.Public())
		record.KeyAlgorithm = strings.ToLower(alg)
		record.KeyBits = bits
	} else {
		alg, bits := certutil.DescribePublicKey(certs[0].PublicKey)
		record.KeyAlgorithm = strings.ToLower(alg)
		record.KeyBits = bits
	}
	record.PrivateKeyPEM = storedKeyPEM

	var chainPEM strings.Builder
	for _, c := range chain {
		chainPEM.WriteString(certutil.EncodeCertificatePEM(c))
	}
	applyIssuedCert(record, certs[0], certutil.EncodeCertificatePEM(certs[0]), chainPEM.String())
	record.ChainLength = 1 + len(chain)

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// ImportCSRInput is the payload for bringing in a signing request and its
// matching private key generated elsewhere — e.g. on an operator's own
// laptop with openssl — rather than through this app's own "Generate" flow.
type ImportCSRInput struct {
	CSRPEM        string
	PrivateKeyPEM string
	Owner         string
	Notes         string
}

// ImportCSR stores an externally-generated CSR and its private key as a
// pending certificate, ready for the same attach-the-CA's-answer or
// self-sign flow as a CSR this app generated itself. Rejected if the key
// does not match the CSR's public key.
func (s *CertificateService) ImportCSR(ctx context.Context, in ImportCSRInput) (*domain.Certificate, error) {
	csrPEM := strings.TrimSpace(in.CSRPEM)
	if csrPEM == "" {
		return nil, domain.Invalid("csr_pem", "paste the certificate signing request")
	}
	csr, err := certutil.ParseCSRPEM(csrPEM)
	if err != nil {
		return nil, domain.Invalid("csr_pem", err.Error())
	}

	keyPEM := strings.TrimSpace(in.PrivateKeyPEM)
	if keyPEM == "" {
		return nil, domain.Invalid("private_key_pem", "paste the private key that matches this signing request")
	}
	key, err := certutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, domain.Invalid("private_key_pem", err.Error())
	}
	if !certutil.MatchesCSRKey(csr, key) {
		return nil, domain.Invalid("private_key_pem", "this key does not match the pasted signing request")
	}

	sealed, err := s.currentSealer().Seal(keyPEM)
	if err != nil {
		return nil, err
	}
	spec := certutil.SpecFromPublicKey(key.Public())

	ips := make([]string, 0, len(csr.IPAddresses))
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip.String())
	}

	commonName := csr.Subject.CommonName
	if commonName == "" {
		commonName = "(no common name)"
	}

	record := &domain.Certificate{
		CommonName:          commonName,
		Organization:        firstOf(csr.Subject.Organization),
		OrganizationalUnit:  firstOf(csr.Subject.OrganizationalUnit),
		Country:             firstOf(csr.Subject.Country),
		Province:            firstOf(csr.Subject.Province),
		Locality:            firstOf(csr.Subject.Locality),
		Email:               firstOf(csr.EmailAddresses),
		DNSNames:            append([]string{}, csr.DNSNames...),
		IPAddresses:         ips,
		Origin:              domain.OriginGenerated,
		Owner:               strings.TrimSpace(in.Owner),
		KeyAlgorithm:        spec.Algorithm,
		KeyBits:             spec.Bits,
		KeyCurve:            spec.Curve,
		CSRPEM:              csrPEM,
		PrivateKeyPEM:       sealed,
		PrivateKeyEncrypted: s.currentSealer().Enabled(),
		ExtKeyUsage:         certutil.DescribeRequestedExtKeyUsage(csr),
		Status:              domain.CertPending,
		Notes:               strings.TrimSpace(in.Notes),
	}

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// firstOf returns the first element of a pkix.Name-style multi-value field,
// or "" when it's empty — a CSR's Subject fields are slices even though this
// app only ever fills in (and here, reads back) a single value each.
func firstOf(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// ImportPFXInput is the payload for uploading a PKCS#12 (.pfx/.p12) bundle.
type ImportPFXInput struct {
	Data     []byte
	Password string
	Owner    string
	Notes    string
}

// ImportPFX decodes a PKCS#12 bundle and stores the certificate, chain, and
// (when present) private key it contains.
func (s *CertificateService) ImportPFX(ctx context.Context, in ImportPFXInput) (*domain.Certificate, error) {
	key, leaf, caCerts, err := certutil.DecodePKCS12(in.Data, in.Password)
	if err != nil {
		return nil, domain.Invalid("pfx", err.Error())
	}
	if leaf == nil {
		return nil, domain.Invalid("pfx", "the bundle did not contain a certificate")
	}

	record := &domain.Certificate{
		Origin: domain.OriginUploaded,
		Owner:  strings.TrimSpace(in.Owner),
		Notes:  strings.TrimSpace(in.Notes),
	}

	if key != nil {
		keyPEM, err := certutil.EncodePrivateKeyPEM(key)
		if err != nil {
			return nil, err
		}
		sealed, err := s.currentSealer().Seal(keyPEM)
		if err != nil {
			return nil, err
		}
		record.PrivateKeyPEM = sealed
		record.PrivateKeyEncrypted = s.currentSealer().Enabled()
		alg, bits := certutil.DescribePublicKey(key.Public())
		record.KeyAlgorithm = strings.ToLower(alg)
		record.KeyBits = bits
	} else {
		alg, bits := certutil.DescribePublicKey(leaf.PublicKey)
		record.KeyAlgorithm = strings.ToLower(alg)
		record.KeyBits = bits
	}

	var chainPEM strings.Builder
	for _, c := range caCerts {
		chainPEM.WriteString(certutil.EncodeCertificatePEM(c))
	}
	applyIssuedCert(record, leaf, certutil.EncodeCertificatePEM(leaf), chainPEM.String())
	record.ChainLength = 1 + len(caCerts)

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// BulkImportResult reports the outcome of one file in a bulk PFX upload.
type BulkImportResult struct {
	Filename    string
	Certificate *domain.Certificate
	Err         error
}

// BulkImportPFX imports several PKCS#12 bundles in one request — the same
// password is tried against every file, which matches how a CA or a Windows
// export tool typically hands over a batch. Each file succeeds or fails
// independently; one bad file never aborts the rest.
func (s *CertificateService) BulkImportPFX(ctx context.Context, files map[string][]byte, password, owner, notes string) []BulkImportResult {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	results := make([]BulkImportResult, 0, len(names))
	for _, name := range names {
		cert, err := s.ImportPFX(ctx, ImportPFXInput{Data: files[name], Password: password, Owner: owner, Notes: notes})
		results = append(results, BulkImportResult{Filename: name, Certificate: cert, Err: err})
	}
	return results
}

// applyIssuedCert fills in the fields captured once a certificate is on file
// — self-signed, CA-attached, or uploaded — from the parsed leaf.
func applyIssuedCert(record *domain.Certificate, leaf *x509.Certificate, certPEM, chainPEM string) {
	notBefore, notAfter := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	record.CertificatePEM = certPEM
	record.ChainPEM = chainPEM
	record.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
	record.NotBefore = &notBefore
	record.NotAfter = &notAfter
	record.Status = domain.CertIssued
	record.Subject = leaf.Subject.String()
	record.Issuer = leaf.Issuer.String()
	record.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
	pkAlg, pkBits := certutil.DescribePublicKey(leaf.PublicKey)
	record.PublicKeyAlgorithm = pkAlg
	record.KeySize = pkBits
	record.ExtKeyUsage = certutil.DescribeExtKeyUsage(leaf)
	sum := sha256.Sum256(leaf.Raw)
	record.FingerprintSHA256 = fmt.Sprintf("%x", sum)
	if record.CommonName == "" {
		record.CommonName = leaf.Subject.CommonName
		if record.CommonName == "" {
			record.CommonName = "(no common name)"
		}
	}
	if len(record.DNSNames) == 0 {
		record.DNSNames = append([]string{}, leaf.DNSNames...)
	}
	if len(record.IPAddresses) == 0 {
		for _, ip := range leaf.IPAddresses {
			record.IPAddresses = append(record.IPAddresses, ip.String())
		}
	}
	if record.Organization == "" && len(leaf.Subject.Organization) > 0 {
		record.Organization = leaf.Subject.Organization[0]
	}
}

// Get loads one certificate.
func (s *CertificateService) Get(ctx context.Context, id uuid.UUID) (*domain.Certificate, error) {
	return s.repo.GetByID(ctx, id)
}

// List returns filtered certificates.
func (s *CertificateService) List(ctx context.Context, f domain.CertificateFilter) ([]*domain.Certificate, error) {
	return s.repo.List(ctx, f)
}

// Delete removes a certificate and its key material.
func (s *CertificateService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}

// Summary aggregates lifecycle/health for the dashboard tiles.
func (s *CertificateService) Summary(ctx context.Context) (domain.Summary, error) {
	certs, err := s.repo.List(ctx, domain.CertificateFilter{})
	if err != nil {
		return domain.Summary{}, err
	}
	var sum domain.Summary
	cur := s.settings.Current()
	for _, c := range certs {
		sum.Total++
		if c.Status != domain.CertIssued {
			sum.Pending++
			continue
		}
		switch c.HealthStatus(cur.ExpiryWarningDays, cur.ExpiryCriticalDays, s.warningPercent, s.criticalPercent) {
		case domain.StatusExpiring:
			sum.Expiring++
		case domain.StatusCritical:
			sum.Critical++
		case domain.StatusExpired:
			sum.Expired++
		default:
			sum.OK++
		}
		switch c.TrustClass() {
		case domain.TrustInternal:
			sum.Internal++
		case domain.TrustExternal:
			sum.External++
		}
	}
	return sum, nil
}

// --- internal Root CAs (v1.1) ----------------------------------------------

// UploadRootCA stores an existing Root CA's certificate and private key so
// SignWithRootCA can issue against it later. Both the key/certificate match
// and IsCA are hard-rejected, unlike chain validation elsewhere in this
// app — a chain with problems is still useful to save and inspect, but a
// "Root CA" that can't actually sign anything (wrong key) or was never a CA
// to begin with (IsCA false) isn't a Root CA, it's a mistake worth catching
// at upload time rather than at every future sign attempt.
func (s *CertificateService) UploadRootCA(ctx context.Context, name, certPEM, keyPEM string) (*domain.RootCA, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, domain.Invalid("name", "a name is required")
	}
	certs, err := certutil.ParseCertificatesPEM(certPEM)
	if err != nil {
		return nil, domain.Invalid("certificate", err.Error())
	}
	cert := certs[0]
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, domain.Invalid("certificate", "this certificate is not marked as a CA — it can't be used to sign other certificates")
	}
	key, err := certutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	if !certutil.MatchesKey(cert, key) {
		return nil, domain.Invalid("private_key", "this private key does not match the certificate")
	}

	stored, err := s.currentSealer().Seal(strings.TrimSpace(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate service: seal root ca key: %w", err)
	}
	notBefore, notAfter := cert.NotBefore.UTC(), cert.NotAfter.UTC()
	pkAlg, pkBits := certutil.DescribePublicKey(cert.PublicKey)
	sum := sha256.Sum256(cert.Raw)
	record := &domain.RootCA{
		Name:                name,
		CertificatePEM:      certutil.EncodeCertificatePEM(cert),
		PrivateKeyPEM:       stored,
		PrivateKeyEncrypted: s.currentSealer().Enabled(),
		Subject:             cert.Subject.String(),
		SignatureAlgorithm:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:  pkAlg,
		KeySize:             pkBits,
		FingerprintSHA256:   fmt.Sprintf("%x", sum),
		NotBefore:           &notBefore,
		NotAfter:            &notAfter,
	}
	if err := s.rootCAs.Create(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

// ListRootCAs returns every uploaded Root CA, newest first.
func (s *CertificateService) ListRootCAs(ctx context.Context) ([]*domain.RootCA, error) {
	return s.rootCAs.List(ctx)
}

// DeleteRootCA removes an uploaded Root CA. Certificates it already signed
// keep their SignedByRootCAID cleared to NULL by the database (ON DELETE SET
// NULL) — they stay marked internal via SelfSigned only if they happen to
// also be self-signed, otherwise they fall back to TrustExternal, which is
// an acceptable, honestly-labeled outcome for "the CA that made this is gone".
func (s *CertificateService) DeleteRootCA(ctx context.Context, id uuid.UUID) error {
	return s.rootCAs.Delete(ctx, id)
}

// rootCAKey decrypts a Root CA's stored private key and parses it — the
// Root CA analogue of CertificateService.PrivateKey.
func (s *CertificateService) rootCAKey(ca *domain.RootCA) (crypto.Signer, error) {
	if !ca.HasPrivateKey() {
		return nil, errors.New("certificate service: no private key on file for this root CA")
	}
	pemStr, err := s.currentSealer().Open(ca.PrivateKeyPEM, ca.PrivateKeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("certificate service: root ca private key unavailable: %w", err)
	}
	return certutil.ParsePrivateKeyPEM(pemStr)
}

// SignWithRootCA issues a pending CSR using one of this app's own uploaded
// Root CAs — the internal-CA counterpart to SelfSign. The Root CA's own
// certificate becomes the issued certificate's chain (so downloads that
// bundle a chain have something to include), and the certificate is marked
// SignedByRootCAID so it classifies as TrustInternal (see
// domain.Certificate.TrustClass).
func (s *CertificateService) SignWithRootCA(ctx context.Context, id, rootCAID uuid.UUID, days int) (*domain.Certificate, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	ca, err := s.rootCAs.GetByID(ctx, rootCAID)
	if err != nil {
		return nil, err
	}
	caCerts, err := certutil.ParseCertificatesPEM(ca.CertificatePEM)
	if err != nil || len(caCerts) == 0 {
		return nil, fmt.Errorf("certificate service: stored root ca certificate is unreadable: %w", err)
	}
	caKey, err := s.rootCAKey(ca)
	if err != nil {
		return nil, err
	}
	parsed, err := certutil.ParseCSRPEM(record.CSRPEM)
	if err != nil {
		return nil, err
	}
	cert, certPEM, err := certutil.SignWithCA(parsed, caCerts[0], caKey, days, record.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	applyIssuedCert(record, cert, certPEM, ca.CertificatePEM)
	record.ChainLength = 2
	record.SignedByRootCAID = &ca.ID

	if err := s.repo.Update(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// BulkRenewInput selects which existing certificates to renew, against
// which Root CA, and for how long — one Root CA and validity period for the
// whole batch, chosen once rather than per certificate.
type BulkRenewInput struct {
	CertificateIDs []uuid.UUID
	RootCAID       uuid.UUID
	Days           int
}

// BulkRenewOutcome reports what happened to one certificate in a
// BulkRenewInternal batch — exactly one of NewCertificate or Err is set.
type BulkRenewOutcome struct {
	CertificateID uuid.UUID
	// CommonName is filled in on a best-effort basis (even on failure, once
	// the original record has been loaded) so a report can name the
	// certificate a failure applies to, not just its ID.
	CommonName     string
	NewCertificate *domain.Certificate
	Err            error
}

// BulkRenewInternal renews several already-issued *internal* certificates at
// once, against one Root CA and validity period chosen for the whole batch.
// Deliberately scoped to internal certificates only: external renewal has no
// CA to call from here (see the DigiCert integration), and even once that
// exists it's a per-ticket, admin-clicked action, not a bulk one — placing a
// batch of orders with a paid public CA isn't a decision this method should
// make silently.
//
// Each certificate renews independently through the same two-step
// CreateCSR + SignWithRootCA pair ApproveInternal already uses for a ticket,
// seeded from the existing record's own subject/SAN/key fields instead of
// ticket input — producing a brand-new certificate record per input, never
// mutating the original, exactly as a renewal ticket already does (the old
// record stays on file as history). One certificate failing (wrong trust
// class, incomplete subject data, a CA problem) never aborts the rest of the
// batch — every outcome, success or failure, comes back in the returned
// slice for the caller to report.
func (s *CertificateService) BulkRenewInternal(ctx context.Context, in BulkRenewInput) []BulkRenewOutcome {
	outcomes := make([]BulkRenewOutcome, 0, len(in.CertificateIDs))
	for _, id := range in.CertificateIDs {
		outcome := BulkRenewOutcome{CertificateID: id}

		record, err := s.repo.GetByID(ctx, id)
		if err != nil {
			outcome.Err = err
			outcomes = append(outcomes, outcome)
			continue
		}
		outcome.CommonName = record.CommonName

		if record.TrustClass() != domain.TrustInternal {
			outcome.Err = domain.Invalid("trust_class", "only internal certificates can be bulk-renewed")
			outcomes = append(outcomes, outcome)
			continue
		}

		sans := strings.Join(append(append([]string{}, record.DNSNames...), record.IPAddresses...), "\n")
		fresh, err := s.CreateCSR(ctx, CreateCSRInput{
			CommonName:         record.CommonName,
			Organization:       record.Organization,
			OrganizationalUnit: record.OrganizationalUnit,
			Country:            record.Country,
			Province:           record.Province,
			Locality:           record.Locality,
			Email:              record.Email,
			SANs:               sans,
			KeyAlgorithm:       record.KeyAlgorithm,
			KeyBits:            record.KeyBits,
			KeyCurve:           record.KeyCurve,
			Owner:              record.Owner,
			Notes:              fmt.Sprintf("Bulk renewal of certificate %s", record.ID),
			ExtKeyUsages:       record.ExtKeyUsage,
		})
		if err != nil {
			outcome.Err = fmt.Errorf("generate renewal CSR: %w", err)
			outcomes = append(outcomes, outcome)
			continue
		}

		signed, err := s.SignWithRootCA(ctx, fresh.ID, in.RootCAID, in.Days)
		if err != nil {
			outcome.Err = fmt.Errorf("sign renewal: %w", err)
			outcomes = append(outcomes, outcome)
			continue
		}
		outcome.NewCertificate = signed
		outcomes = append(outcomes, outcome)
	}
	return outcomes
}

// SetDigiCertOrderID records that a certificate was ordered through the
// DigiCert integration (Phase 6) — see domain.Certificate.DigiCertOrderID
// and DigiCertService.CheckStatus, the only caller.
func (s *CertificateService) SetDigiCertOrderID(ctx context.Context, id uuid.UUID, orderID string) (*domain.Certificate, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	record.DigiCertOrderID = strings.TrimSpace(orderID)
	if err := s.repo.Update(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

// AttachCertificate stores the certificate the CA issued for a pending
// request. The input may be a single certificate or a full chain; the first
// block is treated as the leaf and the remainder becomes the chain.
func (s *CertificateService) AttachCertificate(ctx context.Context, id uuid.UUID, pemBlob string) (*domain.Certificate, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	certs, err := certutil.ParseCertificatesPEM(pemBlob)
	if err != nil {
		return nil, domain.Invalid("certificate", err.Error())
	}

	keyPEM, err := s.PrivateKey(record)
	if err != nil {
		return nil, err
	}
	key, err := certutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	if !certutil.MatchesKey(certs[0], key) {
		return nil, domain.Invalid("certificate", "this certificate was not issued for the stored private key")
	}

	var chain strings.Builder
	for _, c := range certs[1:] {
		chain.WriteString(certutil.EncodeCertificatePEM(c))
	}
	applyIssuedCert(record, certs[0], certutil.EncodeCertificatePEM(certs[0]), chain.String())
	record.ChainLength = len(certs)

	if err := s.repo.Update(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// UpdateChain replaces a certificate's stored intermediate chain and reports
// whether the result actually validates: does each intermediate sign the
// one before it, is each marked as a CA, and is nothing expired. The save
// itself is not blocked on that result — an admin editing the chain by hand
// (say, to fix a CA's incomplete bundle) needs to see what's wrong with
// what they pasted, not be locked out of saving it — but a chain that
// doesn't even parse as PEM certificates is rejected outright, same as
// every other certificate-shaped input in this app.
func (s *CertificateService) UpdateChain(ctx context.Context, id uuid.UUID, chainPEM string) (*domain.Certificate, certutil.ChainValidation, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, certutil.ChainValidation{}, err
	}
	if !record.HasCertificate() {
		return nil, certutil.ChainValidation{}, domain.Invalid("chain", "attach or issue a certificate before editing its chain")
	}

	chainPEM = strings.TrimSpace(chainPEM)
	var chainCerts []*x509.Certificate
	normalized := ""
	if chainPEM != "" {
		chainCerts, err = certutil.ParseCertificatesPEM(chainPEM)
		if err != nil {
			return nil, certutil.ChainValidation{}, domain.Invalid("chain", "could not parse as PEM certificates: "+err.Error())
		}
		var b strings.Builder
		for _, c := range chainCerts {
			b.WriteString(certutil.EncodeCertificatePEM(c))
		}
		normalized = b.String()
	}

	leafCerts, err := certutil.ParseCertificatesPEM(record.CertificatePEM)
	if err != nil || len(leafCerts) == 0 {
		return nil, certutil.ChainValidation{}, fmt.Errorf("certificate service: stored leaf certificate is unreadable: %w", err)
	}
	result := certutil.ValidateChain(leafCerts[0], chainCerts)

	record.ChainPEM = normalized
	record.ChainLength = 1 + len(chainCerts)
	if err := s.repo.Update(ctx, record); err != nil {
		return nil, certutil.ChainValidation{}, err
	}
	return record, result, nil
}

// IntegrityReport is the result of ValidateIntegrity: everything that was
// actually checked (Checks, only populated when there was something on file
// to check it against) and anything found wrong (Issues — a non-empty list
// means Valid is false). Unlike ChainValidation this can speak to material
// ValidateChain never sees: the private key and the signing request.
type IntegrityReport struct {
	Valid  bool
	Checks []string
	Issues []string
}

// ValidateIntegrity re-derives whether everything on file for a certificate
// record is mutually consistent — private key against certificate and CSR,
// each intermediate against the one before it, the chain's terminal entry
// against being a self-signed root — without writing anything back. It is a
// pure read, safe to run on demand as often as an operator wants a fresh
// answer, unlike UpdateChain which only re-validates as a side effect of a
// save.
func (s *CertificateService) ValidateIntegrity(ctx context.Context, id uuid.UUID) (IntegrityReport, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return IntegrityReport{}, err
	}

	var report IntegrityReport
	note := func(format string, args ...any) {
		report.Issues = append(report.Issues, fmt.Sprintf(format, args...))
	}
	check := func(format string, args ...any) {
		report.Checks = append(report.Checks, fmt.Sprintf(format, args...))
	}

	var key crypto.Signer
	if record.HasPrivateKey() {
		keyPEM, err := s.PrivateKey(record)
		if err != nil {
			note("private key could not be decrypted: %s", err)
		} else if k, err := certutil.ParsePrivateKeyPEM(keyPEM); err != nil {
			note("stored private key does not parse: %s", err)
		} else {
			key = k
			check("private key parses correctly")
		}
	}

	var csr *x509.CertificateRequest
	if csrPEM := strings.TrimSpace(record.CSRPEM); csrPEM != "" {
		if c, err := certutil.ParseCSRPEM(csrPEM); err != nil {
			note("signing request does not parse or its signature does not verify: %s", err)
		} else {
			csr = c
			check("signing request's own signature verifies")
			if key != nil {
				if certutil.MatchesCSRKey(csr, key) {
					check("private key matches the signing request")
				} else {
					note("the private key on file does not match the signing request's public key")
				}
			}
		}
	}

	if record.HasCertificate() {
		leafCerts, err := certutil.ParseCertificatesPEM(record.CertificatePEM)
		if err != nil || len(leafCerts) == 0 {
			note("stored certificate does not parse: %v", err)
			report.Valid = len(report.Issues) == 0
			return report, nil
		}
		leaf := leafCerts[0]
		check("certificate parses correctly")

		if key != nil {
			if certutil.MatchesKey(leaf, key) {
				check("private key matches the issued certificate")
			} else {
				note("the private key on file does not match the issued certificate's public key")
			}
		}

		var chainCerts []*x509.Certificate
		if chainPEM := strings.TrimSpace(record.ChainPEM); chainPEM != "" {
			chainCerts, err = certutil.ParseCertificatesPEM(chainPEM)
			if err != nil {
				note("stored chain does not parse: %s", err)
			}
		}

		chainResult := certutil.ValidateChain(leaf, chainCerts)
		if chainResult.Valid {
			if len(chainCerts) == 0 {
				check("no intermediates on file — nothing further to check the certificate against")
			} else {
				check("all %d intermediate(s) sign the one before them and are valid CAs", len(chainCerts))
			}
		} else {
			report.Issues = append(report.Issues, chainResult.Issues...)
		}

		if len(chainCerts) > 0 {
			root := chainCerts[len(chainCerts)-1]
			rootLabel := root.Subject.CommonName
			if rootLabel == "" {
				rootLabel = root.Subject.String()
			}
			if root.CheckSignatureFrom(root) == nil && root.BasicConstraintsValid && root.IsCA {
				check("chain ends in a self-signed root (%s)", rootLabel)
			} else {
				check("chain does not end in a self-signed root (%s) — fine for an internal PKI whose root isn't distributed here, just noting it", rootLabel)
			}
		}
	}

	if len(report.Checks) == 0 && len(report.Issues) == 0 {
		note("nothing is on file yet for this certificate — add a private key, signing request, or certificate first")
	}

	report.Valid = len(report.Issues) == 0
	return report, nil
}

// SelfSign issues a self-signed certificate for an existing pending request.
func (s *CertificateService) SelfSign(ctx context.Context, id uuid.UUID, days int) (*domain.Certificate, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	keyPEM, err := s.PrivateKey(record)
	if err != nil {
		return nil, err
	}
	key, err := certutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	parsed, err := certutil.ParseCSRPEM(record.CSRPEM)
	if err != nil {
		return nil, err
	}
	cert, certPEM, err := certutil.SelfSign(parsed, key, days, record.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	applyIssuedCert(record, cert, certPEM, "")
	record.ChainLength = 1

	if err := s.repo.Update(ctx, record); err != nil {
		return nil, err
	}
	s.evaluate(ctx, record)
	return record, nil
}

// PrivateKey decrypts the stored key material. Returns an error if this
// record never had one on file — callers must check HasPrivateKey first
// when a missing key is an expected, handleable case.
func (s *CertificateService) PrivateKey(record *domain.Certificate) (string, error) {
	if !record.HasPrivateKey() {
		return "", errors.New("certificate service: no private key on file for this certificate")
	}
	pemStr, err := s.currentSealer().Open(record.PrivateKeyPEM, record.PrivateKeyEncrypted)
	if err != nil {
		return "", fmt.Errorf("certificate service: private key unavailable: %w", err)
	}
	return pemStr, nil
}

// SharedFingerprint returns other certificates already on file with the same
// fingerprint as c.
func (s *CertificateService) SharedFingerprint(ctx context.Context, c *domain.Certificate) ([]*domain.Certificate, error) {
	if c == nil || c.FingerprintSHA256 == "" {
		return nil, nil
	}
	return s.repo.FindSharingFingerprint(ctx, c.FingerprintSHA256, c.ID)
}

// IssuerGroup buckets certificates sharing an issuing CA, largest first.
type IssuerGroup struct {
	Issuer       string
	Certificates []*domain.Certificate
}

// GroupByIssuer buckets already-loaded, issued certificates by their
// issuer's common name. Anything still pending lands in "Not yet issued".
func GroupByIssuer(certs []*domain.Certificate) []IssuerGroup {
	index := map[string]int{}
	var groups []IssuerGroup
	for _, c := range certs {
		key := "Not yet issued"
		if c.HasCertificate() {
			if cn := c.IssuerCommonName(); cn != "" {
				key = cn
			}
		}
		if i, ok := index[key]; ok {
			groups[i].Certificates = append(groups[i].Certificates, c)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, IssuerGroup{Issuer: key, Certificates: []*domain.Certificate{c}})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return len(groups[i].Certificates) > len(groups[j].Certificates)
	})
	return groups
}

// AlertSweep re-evaluates every issued certificate against the configured
// alerting thresholds — the periodic half of alerting, catching a
// certificate that quietly crossed a threshold without any create/update
// action of its own. Evaluate() at mutation time (Create/Attach/SelfSign/
// Import) is the immediate half.
func (s *CertificateService) AlertSweep(ctx context.Context) (int, error) {
	certs, err := s.repo.List(ctx, domain.CertificateFilter{Status: domain.CertIssued})
	if err != nil {
		return 0, err
	}
	for _, c := range certs {
		s.evaluate(ctx, c)
	}
	return len(certs), nil
}

func (s *CertificateService) evaluate(ctx context.Context, c *domain.Certificate) {
	if s.alerter != nil {
		s.alerter.Evaluate(ctx, c)
	}
}

// ExportOptions tunes a download.
type ExportOptions struct {
	Format      string
	PFXPassword string
	PFXLegacy   bool
}

// Export renders the requested artefact for a certificate.
func (s *CertificateService) Export(ctx context.Context, id uuid.UUID, opts ExportOptions) (*certutil.ExportResult, error) {
	record, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	in := certutil.ExportInput{
		BaseName:    baseNameFor(record),
		CSRPEM:      record.CSRPEM,
		PFXPassword: opts.PFXPassword,
		PFXLegacy:   opts.PFXLegacy,
	}

	needsKey := opts.Format == certutil.FormatKEY || opts.Format == certutil.FormatPFX || opts.Format == certutil.FormatZIP
	if needsKey && record.HasPrivateKey() {
		keyPEM, err := s.PrivateKey(record)
		if err != nil {
			return nil, err
		}
		key, err := certutil.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, err
		}
		in.PrivateKey = key
	}

	if record.HasCertificate() {
		certs, err := certutil.ParseCertificatesPEM(record.CertificatePEM)
		if err != nil {
			return nil, err
		}
		in.Leaf = certs[0]
		in.Chain = append(in.Chain, certs[1:]...)
		if strings.TrimSpace(record.ChainPEM) != "" {
			chain, err := certutil.ParseCertificatesPEM(record.ChainPEM)
			if err != nil {
				return nil, err
			}
			in.Chain = append(in.Chain, chain...)
		}
	}
	return certutil.Export(in, opts.Format)
}

func baseNameFor(c *domain.Certificate) string {
	if strings.TrimSpace(c.CommonName) != "" {
		return c.CommonName
	}
	return "certificate"
}

// splitSANs sorts a free-form SAN blob into DNS names and IP addresses.
func splitSANs(raw string) (dnsNames, ips []string) {
	for _, v := range certutil.SplitLines(raw) {
		if isIP(v) {
			ips = append(ips, v)
		} else {
			dnsNames = append(dnsNames, v)
		}
	}
	return dnsNames, ips
}

func isIP(v string) bool {
	digits, dots, colons := 0, 0, 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		case r == ':':
			colons++
		}
	}
	if colons > 1 {
		return true
	}
	return dots == 3 && digits+dots == len(v)
}

// IsNotFound is a small helper for the delivery layer.
func IsNotFound(err error) bool { return errors.Is(err, domain.ErrNotFound) }
