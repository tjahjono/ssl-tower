package certutil

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func newRequest() CSRRequest {
	return CSRRequest{
		Subject: Subject{
			CommonName:   "www.example.com",
			Organization: "Example Pte Ltd",
			Country:      "ID",
			Email:        "ops@example.com",
		},
		DNSNames:    []string{"example.com", "*.example.com"},
		IPAddresses: []string{"10.0.0.5"},
		KeySpec:     KeySpec{Algorithm: AlgorithmRSA, Bits: 2048},
	}
}

func TestCreateCSRIncludesCommonNameInSANs(t *testing.T) {
	csrPEM, key, err := CreateCSR(newRequest())
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	if got := csr.Subject.CommonName; got != "www.example.com" {
		t.Errorf("common name = %q", got)
	}
	want := []string{"www.example.com", "example.com", "*.example.com"}
	if len(csr.DNSNames) != len(want) {
		t.Fatalf("dns names = %v, want %v", csr.DNSNames, want)
	}
	for i, w := range want {
		if csr.DNSNames[i] != w {
			t.Errorf("dns[%d] = %q, want %q", i, csr.DNSNames[i], w)
		}
	}
	if len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("ip addresses = %v", csr.IPAddresses)
	}
	if _, err := EncodePrivateKeyPEM(key); err != nil {
		t.Errorf("EncodePrivateKeyPEM: %v", err)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := map[string]func(*CSRRequest){
		"empty common name": func(r *CSRRequest) { r.CommonName = "" },
		"long country":      func(r *CSRRequest) { r.Country = "IDN" },
		"bad ip":            func(r *CSRRequest) { r.IPAddresses = []string{"999.1.1.1"} },
		"bad key size":      func(r *CSRRequest) { r.KeySpec = KeySpec{Algorithm: AlgorithmRSA, Bits: 512} },
		"bad curve":         func(r *CSRRequest) { r.KeySpec = KeySpec{Algorithm: AlgorithmECDSA, Curve: "P-192"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := newRequest()
			mutate(&req)
			if err := req.Validate(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSelfSignAndKeyMatching(t *testing.T) {
	csrPEM, key, err := CreateCSR(newRequest())
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	cert, certPEM, err := SelfSign(csr, key, 30, nil)
	if err != nil {
		t.Fatalf("SelfSign: %v", err)
	}
	if !MatchesKey(cert, key) {
		t.Error("self-signed certificate does not match its own key")
	}
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Error("certPEM is not PEM encoded")
	}

	// A certificate from a different key must not match.
	_, otherKey, err := CreateCSR(newRequest())
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if MatchesKey(cert, otherKey) {
		t.Error("certificate matched an unrelated key")
	}
}

func TestExportFormats(t *testing.T) {
	csrPEM, key, err := CreateCSR(newRequest())
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	cert, _, err := SelfSign(csr, key, 30, nil)
	if err != nil {
		t.Fatalf("SelfSign: %v", err)
	}

	in := ExportInput{
		BaseName:    "www.example.com",
		Leaf:        cert,
		PrivateKey:  key,
		CSRPEM:      csrPEM,
		PFXPassword: "s3cret",
	}

	t.Run("pem", func(t *testing.T) {
		res, err := Export(in, FormatPEM)
		if err != nil {
			t.Fatal(err)
		}
		if res.Filename != "www.example.com.pem" {
			t.Errorf("filename = %q", res.Filename)
		}
		if _, err := ParseCertificatesPEM(string(res.Data)); err != nil {
			t.Errorf("round trip: %v", err)
		}
	})

	t.Run("der", func(t *testing.T) {
		res, err := Export(in, FormatDER)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x509.ParseCertificate(res.Data); err != nil {
			t.Errorf("der does not parse: %v", err)
		}
	})

	t.Run("pfx", func(t *testing.T) {
		res, err := Export(in, FormatPFX)
		if err != nil {
			t.Fatal(err)
		}
		gotKey, gotCert, err := pkcs12.Decode(res.Data, "s3cret")
		if err != nil {
			t.Fatalf("pkcs12 decode: %v", err)
		}
		if gotCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Error("pkcs12 carried the wrong certificate")
		}
		if gotKey == nil {
			t.Error("pkcs12 carried no private key")
		}
	})

	t.Run("p7b", func(t *testing.T) {
		res, err := Export(in, FormatP7B)
		if err != nil {
			t.Fatal(err)
		}
		certs, err := DecodePKCS7Certificates(res.Data)
		if err != nil {
			t.Fatalf("pkcs7 does not parse: %v", err)
		}
		if len(certs) != 1 || certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Errorf("pkcs7 carried %d certificates", len(certs))
		}
	})

	t.Run("zip", func(t *testing.T) {
		res, err := Export(in, FormatZIP)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(res.Data), int64(len(res.Data)))
		if err != nil {
			t.Fatalf("zip: %v", err)
		}
		want := map[string]bool{
			"www.example.com.crt": false,
			"www.example.com.der": false,
			"www.example.com.pem": false,
			"www.example.com.p7b": false,
			"www.example.com.pfx": false,
			"www.example.com.key": false,
			"www.example.com.csr": false,
		}
		for _, f := range zr.File {
			want[f.Name] = true
		}
		for name, found := range want {
			if !found {
				t.Errorf("bundle is missing %s", name)
			}
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		if _, err := Export(in, "docx"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("no certificate yet", func(t *testing.T) {
		pending := ExportInput{BaseName: "pending", PrivateKey: key, CSRPEM: csrPEM}
		if _, err := Export(pending, FormatPEM); err == nil {
			t.Fatal("expected an error for a request without a certificate")
		}
		if _, err := Export(pending, FormatCSR); err != nil {
			t.Errorf("csr export should still work: %v", err)
		}
	})
}

func TestSelfSignDefaultsExtKeyUsage(t *testing.T) {
	csrPEM, key, err := CreateCSR(newRequest())
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	cert, _, err := SelfSign(csr, key, 30, nil)
	if err != nil {
		t.Fatalf("SelfSign: %v", err)
	}
	got := DescribeExtKeyUsage(cert)
	want := []string{EKUServerAuth, EKUClientAuth}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("default EKU = %v, want %v", got, want)
	}
}

func TestSelfSignHonoursRequestedExtKeyUsage(t *testing.T) {
	csrPEM, key, err := CreateCSR(newRequest())
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	cert, _, err := SelfSign(csr, key, 30, []string{EKUCodeSigning})
	if err != nil {
		t.Fatalf("SelfSign: %v", err)
	}
	got := DescribeExtKeyUsage(cert)
	if len(got) != 1 || got[0] != EKUCodeSigning {
		t.Errorf("EKU = %v, want [%s]", got, EKUCodeSigning)
	}
}

func TestCreateCSRRequestsExtKeyUsage(t *testing.T) {
	req := newRequest()
	req.ExtKeyUsages = []string{EKUClientAuth, EKUServerAuth} // deliberately out of canonical order
	csrPEM, _, err := CreateCSR(req)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	var found bool
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(extKeyUsageExtOID) {
			found = true
		}
	}
	if !found {
		t.Error("csr does not carry an extended-key-usage extension request")
	}
}

func TestNormalizeExtKeyUsagesRejectsUnknown(t *testing.T) {
	if _, err := NormalizeExtKeyUsages([]string{"bogus"}); err == nil {
		t.Fatal("expected an error for an unrecognised EKU key")
	}
	got, err := NormalizeExtKeyUsages([]string{"", "  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("blank entries should be dropped, got %v", got)
	}
}

func TestSanitizeBase(t *testing.T) {
	cases := map[string]string{
		"":                 "certificate",
		"*.example.com":    "wildcard.example.com",
		"../../etc/passwd": "etc-passwd",
		"host:8443":        "host-8443",
	}
	for in, want := range cases {
		if got := sanitizeBase(in); got != want {
			t.Errorf("sanitizeBase(%q) = %q, want %q", in, got, want)
		}
	}
}
