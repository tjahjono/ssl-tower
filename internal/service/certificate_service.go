// Package service holds the application's business rules. It depends on the
// domain ports only, never on pgx or net/http.
package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

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
	sealer       *secret.Sealer
	log          *slog.Logger
	warningDays  int
	criticalDays int
	alerter      Alerter
}

// CertificateOptions configures expiry thresholds used for health/summary
// classification (the alerting service has its own, separately configured
// thresholds — see AlertThresholds).
type CertificateOptions struct {
	WarningDays  int
	CriticalDays int
}

// NewCertificateService builds the service.
func NewCertificateService(repo domain.CertificateRepository, sealer *secret.Sealer, log *slog.Logger, opts CertificateOptions) *CertificateService {
	if opts.WarningDays <= 0 {
		opts.WarningDays = 30
	}
	if opts.CriticalDays <= 0 {
		opts.CriticalDays = 7
	}
	return &CertificateService{repo: repo, sealer: sealer, log: log, warningDays: opts.WarningDays, criticalDays: opts.CriticalDays}
}

// SetAlerter wires an Alerter to be evaluated after every mutation and
// periodic sweep. Optional — a CertificateService with no alerter configured
// just skips notification.
func (s *CertificateService) SetAlerter(a Alerter) { s.alerter = a }

// Thresholds exposes the configured expiry windows for display.
func (s *CertificateService) Thresholds() (warning, critical int) {
	return s.warningDays, s.criticalDays
}

// KeyEncryptionEnabled reports whether private keys are encrypted at rest.
func (s *CertificateService) KeyEncryptionEnabled() bool { return s.sealer.Enabled() }

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
	stored, err := s.sealer.Seal(keyPEM)
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
		PrivateKeyEncrypted: s.sealer.Enabled(),
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
		sealed, err := s.sealer.Seal(keyPEM)
		if err != nil {
			return nil, err
		}
		storedKeyPEM = sealed
		record.PrivateKeyEncrypted = s.sealer.Enabled()
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

	sealed, err := s.sealer.Seal(keyPEM)
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
		PrivateKeyEncrypted: s.sealer.Enabled(),
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
		sealed, err := s.sealer.Seal(keyPEM)
		if err != nil {
			return nil, err
		}
		record.PrivateKeyPEM = sealed
		record.PrivateKeyEncrypted = s.sealer.Enabled()
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
	for _, c := range certs {
		sum.Total++
		if c.Status != domain.CertIssued {
			sum.Pending++
			continue
		}
		switch c.HealthStatus(s.warningDays, s.criticalDays) {
		case domain.StatusExpiring:
			sum.Expiring++
		case domain.StatusCritical:
			sum.Critical++
		case domain.StatusExpired:
			sum.Expired++
		default:
			sum.OK++
		}
	}
	return sum, nil
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
	pemStr, err := s.sealer.Open(record.PrivateKeyPEM, record.PrivateKeyEncrypted)
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
