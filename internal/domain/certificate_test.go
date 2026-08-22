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
	if got := pending.HealthStatus(30, 7); got != "" {
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
			if got := tc.c.HealthStatus(30, 7); got != tc.want {
				t.Fatalf("HealthStatus() = %v, want %v", got, tc.want)
			}
		})
	}
}

func hasFinding(findings []HealthFinding, label string) bool {
	for _, f := range findings {
		if f.Label == label {
			return true
		}
	}
	return false
}
