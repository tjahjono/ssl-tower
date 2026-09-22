package domain

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CertOrigin distinguishes a certificate whose lifecycle still runs through
// a CSR — one this app generated itself, or one an operator generated
// elsewhere (e.g. on their own laptop with openssl) and imported with its
// matching private key — from one an operator uploaded directly as an
// already-issued certificate. The distinction that matters is "is there a
// pending-CSR stage" (self-sign, attach-the-CA's-answer), not which machine
// actually ran the keygen.
type CertOrigin string

// Origins a certificate record can have.
const (
	OriginGenerated CertOrigin = "generated"
	OriginUploaded  CertOrigin = "uploaded"
)

// Label renders the origin for humans.
func (o CertOrigin) Label() string {
	if o == OriginUploaded {
		return "Uploaded"
	}
	return "Generated"
}

// CertLifecycle tracks whether a certificate has actually been issued yet.
// Only a generated-but-not-yet-signed CSR is ever "pending" — every uploaded
// certificate arrives already issued, by definition.
type CertLifecycle string

// Lifecycle states.
const (
	CertPending CertLifecycle = "pending"
	CertIssued  CertLifecycle = "issued"
)

// Label renders the lifecycle state for humans.
func (s CertLifecycle) Label() string {
	if s == CertIssued {
		return "Issued"
	}
	return "Awaiting certificate"
}

// CheckStatus is the expiry health of an issued certificate. It is left blank
// for a certificate that has no issued cert yet (a pending CSR) — there is
// nothing to grade.
type CheckStatus string

// Expiry health states, ordered from healthy to broken. There is no "error"
// state any more — that belonged to a live TLS handshake failing, and the
// vault has no live handshake left to fail.
const (
	StatusOK       CheckStatus = "ok"
	StatusExpiring CheckStatus = "expiring"
	StatusCritical CheckStatus = "critical"
	StatusExpired  CheckStatus = "expired"
)

// Label renders the status for humans.
func (s CheckStatus) Label() string {
	switch s {
	case StatusOK:
		return "Healthy"
	case StatusExpiring:
		return "Expiring soon"
	case StatusCritical:
		return "Critical"
	case StatusExpired:
		return "Expired"
	default:
		return "Unknown"
	}
}

// Severity orders statuses so the worst certificates float to the top of a list.
func (s CheckStatus) Severity() int {
	switch s {
	case StatusExpired:
		return 4
	case StatusCritical:
		return 2
	case StatusExpiring:
		return 1
	default:
		return 0
	}
}

// Certificate is one entry in the certificate vault: either a signing
// request this app generated (its key pair minted in-app, pending the CA's
// response, or already self-signed) or a certificate an operator uploaded
// directly, key material included or not.
type Certificate struct {
	ID                 uuid.UUID
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	Email              string
	DNSNames           []string
	IPAddresses        []string

	// Origin and Owner are the Phase 10 additions: Origin records how the
	// certificate entered the vault, Owner is a free-text team/owner tag so
	// an IT team can tell at a glance who to ask about a given certificate.
	Origin CertOrigin
	Owner  string

	KeyAlgorithm string // best-effort label: "rsa", "ecdsa", "ed25519", "unknown"
	KeyBits      int
	KeyCurve     string
	CSRPEM       string // empty for an uploaded certificate
	// ExtKeyUsage holds certutil's EKU keys (e.g. "server_auth"), rendered for
	// humans via the "ekuLabel"/"ekuSummary" template funcs. While the
	// certificate is still pending, this is what was requested at CSR time;
	// once issued (self-signed, CA-attached, imported, or PFX-imported) it is
	// overwritten with whatever the issued leaf actually carries — the ground
	// truth, which a CA is free to have honoured, ignored, or overridden.
	ExtKeyUsage         []string
	PrivateKeyPEM       string // ciphertext when PrivateKeyEncrypted is true; empty if never held
	PrivateKeyEncrypted bool
	CertificatePEM      string
	ChainPEM            string
	SelfSigned          bool
	// SignedByRootCAID is set when CertificateService.SignWithRootCA issued
	// this certificate against one of this app's own uploaded Root CAs — nil
	// for everything else (self-signed, uploaded/attached from an outside
	// CA, or still pending). See TrustClass.
	SignedByRootCAID *uuid.UUID

	// Subject/Issuer and the fields below are captured once, at the moment a
	// certificate becomes issued (self-signed, CA-attached, or uploaded) —
	// this is what Phase 11's health findings are computed from, rather than
	// re-parsing the PEM on every read.
	Subject            string
	Issuer             string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize            int
	// ChainLength is how many certificates ship with this record, leaf
	// included — 1 means no intermediates were provided.
	ChainLength       int
	FingerprintSHA256 string

	NotBefore *time.Time
	NotAfter  *time.Time
	Status    CertLifecycle
	Notes     string
	CreatedAt time.Time
	UpdatedAt time.Time

	// DigiCertOrderID is set once this certificate has actually been ordered
	// through the DigiCert integration (Phase 6) — empty for every
	// certificate obtained any other way (self-signed, Root-CA-signed,
	// manually pasted from a CA, PFX-imported). When a certificate with a
	// DigiCertOrderID is later renewed through DigiCertService, that order
	// ID is what lets the renewal use DigiCert's faster reissue path instead
	// of placing a brand-new order — see DigiCertService.Submit.
	DigiCertOrderID string

	// SignedByADCS marks a certificate issued through the ADCS (Active
	// Directory Certificate Services) CES/CEP integration — see
	// CertificateService.SignWithADCS and internal/pkg/adcs. A dedicated
	// bool rather than reusing SignedByRootCAID: unlike an uploaded/
	// generated Root CA, there is no in-app CA record to point a foreign
	// key at — ADCS's own CA lives entirely outside this app. TrustClass
	// treats this the same as a self-signed or Root-CA-signed certificate:
	// internal, since it was issued by the organization's own CA, not a
	// publicly-trusted one.
	SignedByADCS bool
	// ADCSRequestID is the request/serial ID ADCS's RSTR response reported
	// for this issuance, if any — purely informational (for looking the
	// request up on the CA server), never used to decide trust class or
	// gate any behavior. Empty whenever SignedByADCS is false, and may
	// still be empty even when true if the server's response didn't carry
	// one.
	ADCSRequestID string
}

// HasPrivateKey reports whether this record holds key material at all —
// true for every generated certificate, and for an uploaded one only when
// the key was actually supplied alongside the certificate.
func (c *Certificate) HasPrivateKey() bool {
	return c != nil && strings.TrimSpace(c.PrivateKeyPEM) != ""
}

// HasCertificate reports whether an issued certificate is on file.
func (c *Certificate) HasCertificate() bool {
	return c != nil && strings.TrimSpace(c.CertificatePEM) != ""
}

// KeyLabel renders the key algorithm for display, e.g. "RSA 2048".
func (c *Certificate) KeyLabel() string {
	switch strings.ToLower(c.KeyAlgorithm) {
	case "ecdsa":
		return "ECDSA " + c.KeyCurve
	case "rsa":
		if c.KeyBits > 0 {
			return "RSA " + itoa(c.KeyBits)
		}
	case "":
		// fall through to the generic case below
	default:
		if c.KeyBits > 0 {
			return strings.ToUpper(c.KeyAlgorithm) + " " + itoa(c.KeyBits)
		}
		return strings.ToUpper(c.KeyAlgorithm)
	}
	if c.KeyBits > 0 {
		return "RSA " + itoa(c.KeyBits)
	}
	return "Unknown"
}

// SANSummary renders the subject alternative names on one line.
func (c *Certificate) SANSummary() string {
	all := append(append([]string{}, c.DNSNames...), c.IPAddresses...)
	if len(all) == 0 {
		return "—"
	}
	if len(all) <= 3 {
		return strings.Join(all, ", ")
	}
	return strings.Join(all[:3], ", ") + " +" + itoa(len(all)-3) + " more"
}

// CoversMultiple reports whether the SAN list reaches beyond a single name —
// the wildcard-covers-many-websites case worth calling out.
func (c *Certificate) CoversMultiple() bool {
	return c != nil && len(c.DNSNames) > 1
}

// DaysRemaining is days until the issued certificate expires, nil when
// nothing has been issued yet.
func (c *Certificate) DaysRemaining() *int {
	if c == nil || c.NotAfter == nil {
		return nil
	}
	d := int(time.Until(*c.NotAfter).Hours() / 24)
	return &d
}

// ExpiresIn renders the remaining lifetime for humans.
func (c *Certificate) ExpiresIn() string {
	days := c.DaysRemaining()
	if days == nil {
		return "—"
	}
	d := *days
	switch {
	case d < 0:
		return fmt.Sprintf("expired %d days ago", -d)
	case d == 0:
		return "expires today"
	case d == 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", d)
	}
}

// HealthStatus classifies the issued certificate's expiry against the
// configured thresholds. It is "" for a certificate that hasn't been issued
// yet — there's nothing to grade until then.
//
// Two kinds of threshold are checked, and either can trip a tier on its own:
// an absolute day count (warningDays/criticalDays, unchanged since Phase 10)
// and a percentage of the certificate's own total lifetime remaining
// (warningPercent/criticalPercent — see LifetimePercentRemaining). The
// percent check only applies to externally-issued certificates
// (TrustClass() == TrustExternal): those are the ones actually bound by the
// CA/Browser Forum's shrinking public max-validity schedule (200 days today,
// dropping to 100 in 2027 and 47 in 2029), so a shorter total lifetime
// should mean earlier relative warning. An internal certificate's validity
// period is a value this app's own operator chose — often years — so a
// percentage of it is meaningless for urgency and would otherwise flag a
// long-lived internal certificate "expiring" for a large fraction of its
// life; internal certificates are deliberately exempt and keep behaving
// exactly as before, graded on the day-based thresholds alone. For a
// concrete case: a 200-day external certificate hits a 33%-remaining
// warning at 66 days left, well before the fixed 30-day threshold would
// fire — real, meaningfully earlier notice. Once the public ceiling reaches
// 47 days, 33% remaining is only ~15.5 days, so the fixed 30-day threshold
// (still the more conservative of the two, since the check fires on
// whichever trips first) keeps providing the same lead time it does today.
func (c *Certificate) HealthStatus(warningDays, criticalDays, warningPercent, criticalPercent int) CheckStatus {
	days := c.DaysRemaining()
	if c == nil || c.Status != CertIssued || days == nil {
		return ""
	}
	pct := 100.0
	if c.TrustClass() == TrustExternal {
		pct = c.LifetimePercentRemaining()
	}
	switch {
	case *days < 0:
		return StatusExpired
	case *days <= criticalDays || pct <= float64(criticalPercent):
		return StatusCritical
	case *days <= warningDays || pct <= float64(warningPercent):
		return StatusExpiring
	default:
		return StatusOK
	}
}

// LifetimePercentRemaining returns the percentage of a certificate's total
// validity window (NotBefore..NotAfter) still remaining, as of now. It
// returns 100 — a value that never trips a percent-based threshold — when
// the window can't be computed (NotBefore or NotAfter missing, or a
// zero/negative window), so percent-based thresholds are purely additive
// and never misfire on incomplete data such as older records issued before
// NotBefore was tracked.
func (c *Certificate) LifetimePercentRemaining() float64 {
	if c == nil || c.NotBefore == nil || c.NotAfter == nil {
		return 100
	}
	total := c.NotAfter.Sub(*c.NotBefore)
	if total <= 0 {
		return 100
	}
	pct := float64(time.Until(*c.NotAfter)) / float64(total) * 100
	switch {
	case pct < 0:
		return 0
	case pct > 100:
		return 100
	default:
		return pct
	}
}

// IsSelfSigned reports whether the certificate's subject and issuer match.
func (c *Certificate) IsSelfSigned() bool {
	return c != nil && c.Subject != "" && c.Subject == c.Issuer
}

// CertTrustClass separates a certificate signed within this app (by its own
// key, or by one of its uploaded Root CAs) from one that came from an
// outside CA — the v1.1 dashboard/list split. It's derived, not stored:
// nothing about it is persisted beyond the fields it's computed from.
type CertTrustClass string

// Trust classes. TrustPending is deliberately distinct from TrustExternal —
// a CSR with no certificate yet hasn't earned either label.
const (
	TrustInternal CertTrustClass = "internal"
	TrustExternal CertTrustClass = "external"
	TrustPending  CertTrustClass = ""
)

// Label renders the trust class for humans.
func (t CertTrustClass) Label() string {
	switch t {
	case TrustInternal:
		return "Internal"
	case TrustExternal:
		return "External"
	default:
		return "Pending"
	}
}

// TrustClass classifies an issued certificate as internal (self-signed,
// signed by a Root CA this app holds, or issued by ADCS) or external
// (uploaded/attached from an outside CA) — empty for anything not yet
// issued.
func (c *Certificate) TrustClass() CertTrustClass {
	if c == nil || !c.HasCertificate() {
		return TrustPending
	}
	if c.SelfSigned || c.SignedByRootCAID != nil || c.SignedByADCS {
		return TrustInternal
	}
	return TrustExternal
}

// SubjectCommonName pulls the CN out of the stored subject DN.
func (c *Certificate) SubjectCommonName() string {
	if c == nil {
		return ""
	}
	return commonNameOf(c.Subject)
}

// IssuerCommonName pulls the CN out of the stored issuer DN.
func (c *Certificate) IssuerCommonName() string {
	if c == nil {
		return ""
	}
	return commonNameOf(c.Issuer)
}

func commonNameOf(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if cn, ok := strings.CutPrefix(part, "CN="); ok {
			return cn
		}
	}
	return dn
}

// HealthSeverity ranks how much attention a health finding deserves.
type HealthSeverity string

// Severities for certificate health findings, from merely informational to a
// real weakness worth fixing.
const (
	HealthInfo    HealthSeverity = "info"
	HealthWarning HealthSeverity = "warning"
)

// HealthFinding is one certificate-hygiene observation independent of expiry.
type HealthFinding struct {
	Severity HealthSeverity
	Label    string
	Detail   string
}

// HealthFindings inspects the issued certificate for hygiene problems
// independent of its expiry: signature strength, key size, and whether
// intermediates were supplied. Ported from the endpoint-monitoring model's
// Check.HealthFindings (Phase 11) — the "issuer changed" finding is dropped,
// since it only made sense when a periodic re-check could notice a change;
// a certificate record here is simply replaced by a new one.
func (c *Certificate) HealthFindings() []HealthFinding {
	if c == nil || !c.HasCertificate() {
		return nil
	}
	var findings []HealthFinding

	if isWeakSignature(c.SignatureAlgorithm) {
		findings = append(findings, HealthFinding{
			Severity: HealthWarning,
			Label:    "Weak signature",
			Detail:   c.SignatureAlgorithm + " is considered breakable — most CAs no longer issue it.",
		})
	}
	if isWeakKey(c.PublicKeyAlgorithm, c.KeySize) {
		findings = append(findings, HealthFinding{
			Severity: HealthWarning,
			Label:    "Undersized key",
			Detail:   fmt.Sprintf("%s %d-bit is below the modern minimum.", c.PublicKeyAlgorithm, c.KeySize),
		})
	}
	if c.IsSelfSigned() {
		findings = append(findings, HealthFinding{
			Severity: HealthInfo,
			Label:    "Self-signed",
			Detail:   "Not issued by a CA — browsers and most clients will not trust it automatically.",
		})
	} else if c.ChainLength <= 1 {
		findings = append(findings, HealthFinding{
			Severity: HealthInfo,
			Label:    "No intermediates supplied",
			Detail:   "Only the leaf certificate is on file. Most clients still work via cached or fetched intermediates, but keeping the full chain here is more reliable.",
		})
	}
	return findings
}

func isWeakSignature(alg string) bool {
	upper := strings.ToUpper(alg)
	return strings.Contains(upper, "MD2") || strings.Contains(upper, "MD5") || strings.Contains(upper, "SHA1")
}

func isWeakKey(publicKeyAlgorithm string, keySize int) bool {
	switch publicKeyAlgorithm {
	case "RSA":
		return keySize < 2048
	case "ECDSA":
		return keySize < 256
	default:
		return false
	}
}

// CertificateFilter narrows a certificate listing.
type CertificateFilter struct {
	Search string
	Status CertLifecycle
	Origin CertOrigin
	// Trust filters by CertTrustClass ("internal"/"external"). Empty means
	// no filtering by trust class — this is deliberately not the same zero
	// value as TrustPending, which is why the repository matches it against
	// the raw string rather than the CertTrustClass type.
	Trust string
}

// Summary powers the dashboard tiles. Computed in Go from a loaded list
// rather than a stored per-check status — there is no periodic check left
// to maintain one, and an internal certificate vault's row count is small
// enough that this is simpler than dynamic SQL aggregation.
type Summary struct {
	Total    int
	OK       int
	Expiring int
	Critical int
	Expired  int
	Pending  int
	// Internal/External split issued certificates by CertTrustClass — they
	// don't include Pending, so Internal+External+Pending == Total.
	Internal int
	External int
}

// CertificateRepository is the persistence port for the certificate vault.
type CertificateRepository interface {
	Create(ctx context.Context, c *Certificate) error
	Update(ctx context.Context, c *Certificate) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*Certificate, error)
	List(ctx context.Context, f CertificateFilter) ([]*Certificate, error)
	// FindSharingFingerprint returns other certificates with the same
	// SHA-256 fingerprint, excluding excludeID — flags "you already have
	// this exact certificate on file" on upload.
	FindSharingFingerprint(ctx context.Context, fingerprint string, excludeID uuid.UUID) ([]*Certificate, error)
	// AlertLevel/SetAlertLevel back the alerting service's per-certificate
	// "level last notified" bookkeeping.
	AlertLevel(ctx context.Context, id uuid.UUID) (int, error)
	SetAlertLevel(ctx context.Context, id uuid.UUID, level int) error
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
