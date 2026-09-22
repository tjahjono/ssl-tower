package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// buildChainCert makes a minimal certificate for chain-validation tests.
// When signer/signerKey are nil, the certificate signs itself (a root CA).
func buildChainCert(t *testing.T, cn string, isCA bool, notBefore, notAfter time.Time, signer *x509.Certificate, signerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	parent, parentKey := tmpl, key
	if signer != nil {
		parent, parentKey = signer, signerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

func TestValidateChainAcceptsProperlySignedChain(t *testing.T) {
	now := time.Now()
	root, rootKey := buildChainCert(t, "Test Root CA", true, now.Add(-time.Hour), now.Add(10*365*24*time.Hour), nil, nil)
	intermediate, intKey := buildChainCert(t, "Test Issuing CA", true, now.Add(-time.Hour), now.Add(5*365*24*time.Hour), root, rootKey)
	leaf, _ := buildChainCert(t, "www.example.com", false, now.Add(-time.Hour), now.Add(90*24*time.Hour), intermediate, intKey)

	result := ValidateChain(leaf, []*x509.Certificate{intermediate, root})
	if !result.Valid {
		t.Fatalf("expected a properly signed chain to validate, got issues: %v", result.Issues)
	}
}

func TestValidateChainRejectsWrongOrder(t *testing.T) {
	now := time.Now()
	root, rootKey := buildChainCert(t, "Test Root CA", true, now.Add(-time.Hour), now.Add(10*365*24*time.Hour), nil, nil)
	intermediate, intKey := buildChainCert(t, "Test Issuing CA", true, now.Add(-time.Hour), now.Add(5*365*24*time.Hour), root, rootKey)
	leaf, _ := buildChainCert(t, "www.example.com", false, now.Add(-time.Hour), now.Add(90*24*time.Hour), intermediate, intKey)

	// Root listed before the intermediate that actually signed the leaf —
	// the leaf-to-first-link signature check should fail.
	result := ValidateChain(leaf, []*x509.Certificate{root, intermediate})
	if result.Valid {
		t.Fatal("expected a chain in the wrong order to fail validation")
	}
	if len(result.Issues) == 0 {
		t.Fatal("expected at least one issue to be reported")
	}
}

func TestValidateChainRejectsExpiredIntermediate(t *testing.T) {
	now := time.Now()
	root, rootKey := buildChainCert(t, "Test Root CA", true, now.Add(-2*time.Hour), now.Add(10*365*24*time.Hour), nil, nil)
	intermediate, intKey := buildChainCert(t, "Test Issuing CA", true, now.Add(-2*time.Hour), now.Add(-time.Hour), root, rootKey)
	leaf, _ := buildChainCert(t, "www.example.com", false, now.Add(-time.Hour), now.Add(90*24*time.Hour), intermediate, intKey)

	result := ValidateChain(leaf, []*x509.Certificate{intermediate, root})
	if result.Valid {
		t.Fatal("expected an expired intermediate to fail validation")
	}
}

func TestValidateChainEmptyChainIsValid(t *testing.T) {
	now := time.Now()
	leaf, _ := buildChainCert(t, "www.example.com", false, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil, nil)
	result := ValidateChain(leaf, nil)
	if !result.Valid {
		t.Fatalf("expected an empty chain to be trivially valid, got issues: %v", result.Issues)
	}
}
