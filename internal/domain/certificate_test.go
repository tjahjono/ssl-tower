package domain

import (
	"testing"
	"time"
)

func nowPlusDays(d int) time.Time {
	return time.Now().Add(time.Duration(d)*24*time.Hour + time.Hour)
}

func TestHasCertificate(t *testing.T) {
	withoutPEM := &Certificate{CertificatePEM: "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----"}
	if !withoutPEM.HasCertificate() {
		t.Fatal("expected HasCertificate to be true once CertificatePEM is set")
	}

	var nilCert *Certificate
	if nilCert.HasCertificate() {
		t.Fatal("expected a nil certificate to report no certificate")
	}

	empty := &Certificate{}
	if empty.HasCertificate() {
		t.Fatal("expected a certificate with no PEM to report no certificate")
	}
}

func TestCertificateIsSelfSigned(t *testing.T) {
	selfSigned := &Certificate{Subject: "CN=example.com", Issuer: "CN=example.com"}
	if !selfSigned.IsSelfSigned() {
		t.Fatal("expected matching subject and issuer to be flagged self-signed")
	}

	caSigned := &Certificate{Subject: "CN=example.com", Issuer: "CN=Some CA"}
	if caSigned.IsSelfSigned() {
		t.Fatal("expected a CA-issued cert not to be flagged self-signed")
	}

	blank := &Certificate{}
	if blank.IsSelfSigned() {
		t.Fatal("expected an empty subject/issuer not to be flagged self-signed")
	}
}

func TestCertificateHealthFindings(t *testing.T) {
	issued := func(sigAlg, pubAlg string, keySize, chainLen int, issuer string) *Certificate {
		return &Certificate{
			CertificatePEM:     "present",
			Subject:            "CN=example.com",
			Issuer:             issuer,
			SignatureAlgorithm: sigAlg,
			PublicKeyAlgorithm: pubAlg,
			KeySize:            keySize,
			ChainLength:        chainLen,
		}
	}

	t.Run("healthy certificate has no findings", func(t *testing.T) {
		c := issued("SHA256-RSA", "RSA", 2048, 3, "CN=Trusted CA")
		if got := c.HealthFindings(); len(got) != 0 {
			t.Fatalf("expected no findings for a healthy cert, got %+v", got)
		}
	})

	t.Run("weak signature algorithm is flagged", func(t *testing.T) {
		c := issued("SHA1-RSA", "RSA", 2048, 3, "CN=Trusted CA")
		findings := c.HealthFindings()
		if !hasFinding(findings, "Weak signature") {
			t.Fatalf("expected a weak-signature finding, got %+v", findings)
		}
	})

	t.Run("undersized RSA key is flagged", func(t *testing.T) {
		c := issued("SHA256-RSA", "RSA", 1024, 3, "CN=Trusted CA")
		findings := c.HealthFindings()
		if !hasFinding(findings, "Undersized key") {
			t.Fatalf("expected an undersized-key finding, got %+v", findings)
		}
	})

	t.Run("undersized ECDSA key is flagged", func(t *testing.T) {
		c := issued("ECDSA-SHA256", "ECDSA", 224, 3, "CN=Trusted CA")
		findings := c.HealthFindings()
		if !hasFinding(findings, "Undersized key") {
			t.Fatalf("expected an undersized-key finding for a 224-bit ECDSA key, got %+v", findings)
		}
	})

	t.Run("self-signed takes precedence over no-intermediates", func(t *testing.T) {
		c := issued("SHA256-RSA", "RSA", 2048, 1, "CN=example.com")
		findings := c.HealthFindings()
		if !hasFinding(findings, "Self-signed") {
			t.Fatalf("expected a self-signed finding, got %+v", findings)
		}
		if hasFinding(findings, "No intermediates supplied") {
			t.Fatalf("self-signed and no-intermediates should be mutually exclusive, got %+v", findings)
		}
	})

	t.Run("CA-signed leaf with only itself on file is flagged no-intermediates", func(t *testing.T) {
		c := issued("SHA256-RSA", "RSA", 2048, 1, "CN=Trusted CA")
		findings := c.HealthFindings()
		if !hasFinding(findings, "No intermediates supplied") {
			t.Fatalf("expected a no-intermediates finding, got %+v", findings)
		}
	})

	t.Run("a pending certificate has no findings at all", func(t *testing.T) {
		var c *Certificate
		if got := c.HealthFindings(); got != nil {
			t.Fatalf("expected nil findings for a nil certificate, got %+v", got)
		}
		empty := &Certificate{}
		if got := empty.HealthFindings(); got != nil {
			t.Fatalf("expected nil findings for a certificate with nothing issued yet, got %+v", got)
		}
	})
}

func TestHealthStatusClassification(t *testing.T) {
	pending := &Certificate{Status: CertPending}
	if got := pending.HealthStatus(30, 7, 33, 10); got != "" {
		t.Fatalf("expected a pending certificate to have no health status, got %q", got)
	}

	days := func(d int) *Certificate {
		na := nowPlusDays(d)
		return &Certificate{Status: CertIssued, NotAfter: &na}
	}

	cases := []struct {
		name string
		c    *Certificate
		want CheckStatus
	}{
		{"healthy, far from expiry", days(90), StatusOK},
		{"just inside warning window", days(30), StatusExpiring},
		{"just inside critical window", days(7), StatusCritical},
		{"already past notAfter", days(-3), StatusExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.HealthStatus(30, 7, 33, 10); got != tc.want {
				t.Fatalf("HealthStatus() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHealthStatusPercentThreshold covers the percent-of-lifetime-remaining
// threshold added alongside the fixed day-count ones: it must add earlier
// warning for a short-lived (e.g. 47-day) *external* certificate, while
// leaving a long-lived *internal* certificate's classification exactly as
// it was before percent thresholds existed — internal certificates are
// deliberately exempt (see HealthStatus's doc comment for why a single
// fixed percentage can't otherwise avoid re-flagging long-lived certs
// early).
func TestHealthStatusPercentThreshold(t *testing.T) {
	// issuedWithLifetime builds an issued certificate whose total validity
	// window is exactly totalDays, with daysRemaining left in it.
	issuedWithLifetime := func(totalDays, daysRemaining int, external bool) *Certificate {
		nb := nowPlusDays(-(totalDays - daysRemaining))
		na := nowPlusDays(daysRemaining)
		c := &Certificate{
			Status: CertIssued, NotBefore: &nb, NotAfter: &na,
			// CertificatePEM must be non-empty for HasCertificate() (and so
			// TrustClass()) to resolve to anything but TrustPending.
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----",
		}
		if !external {
			c.SelfSigned = true // TrustClass() == TrustInternal
		}
		return c
	}

	t.Run("47-day external certificate: percent threshold fires earlier than the day threshold would", func(t *testing.T) {
		// 35 days remaining out of 47 total = ~74.5% remaining — above the
		// day-based warning (30 days) but below a 75% warning percent, so
		// this only trips via the percent check, earlier (more days left)
		// than day-based alone would ever manage on a cert this short.
		c := issuedWithLifetime(47, 35, true)
		if got := c.HealthStatus(30, 7, 75, 10); got != StatusExpiring {
			t.Fatalf("HealthStatus() = %v, want %v (percent threshold should have tripped)", got, StatusExpiring)
		}
		if got := c.HealthStatus(30, 7, 50, 10); got != StatusOK {
			t.Fatalf("HealthStatus() = %v, want %v (50%% warning threshold not yet crossed at 35/47 days)", got, StatusOK)
		}
	})

	t.Run("long-lived internal certificate: percent threshold never trips, day-based behavior unchanged", func(t *testing.T) {
		// A 3-year (1095 day) internal certificate with 66 days remaining is
		// ~94% used / 6% remaining — well past even an aggressive percent
		// threshold. If percent thresholds applied to internal certificates
		// the same way they do to external ones, this would already be
		// StatusCritical; because HealthStatus exempts internal
		// certificates, it must classify purely on the day-based windows,
		// exactly as it did before percent thresholds existed.
		c := issuedWithLifetime(1095, 66, false)
		if got := c.HealthStatus(30, 7, 33, 10); got != StatusOK {
			t.Fatalf("HealthStatus() = %v, want %v (internal certificate must ignore percent thresholds)", got, StatusOK)
		}
	})

	t.Run("long-lived external certificate: day-based threshold still fires first at the usual point (regression)", func(t *testing.T) {
		// A 200-day external certificate with 30 days remaining (15%
		// remaining) is right at the day-based warning boundary. With the
		// plan's suggested defaults (33% warning / 10% critical), 15% is
		// below the warning percent too, so this is still classified
		// StatusExpiring — the same tier today's day-only logic already
		// produces at exactly 30 days remaining, just reached by either
		// check now instead of only one.
		c := issuedWithLifetime(200, 30, true)
		if got := c.HealthStatus(30, 7, 33, 10); got != StatusExpiring {
			t.Fatalf("HealthStatus() = %v, want %v", got, StatusExpiring)
		}
		// One day later (29 remaining / 14.5%%), still just Expiring, not
		// yet Critical under either check.
		c2 := issuedWithLifetime(200, 29, true)
		if got := c2.HealthStatus(30, 7, 33, 10); got != StatusExpiring {
			t.Fatalf("HealthStatus() = %v, want %v", got, StatusExpiring)
		}
	})
}

func hasFinding(findings []HealthFinding, label string) bool {
	for _, f := range findings {
		if f.Label == label {
			return true
		}
	}
	return false
}
