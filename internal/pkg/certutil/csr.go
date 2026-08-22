package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Recognised extended-key-usage keys. These are plain strings (rather than
// x509.ExtKeyUsage values) so the domain and delivery layers can store and
// render a certificate's EKU without importing crypto/x509 themselves — the
// OID/enum mapping stays entirely inside this package.
const (
	EKUServerAuth      = "server_auth"
	EKUClientAuth      = "client_auth"
	EKUCodeSigning     = "code_signing"
	EKUEmailProtection = "email_protection"
	EKUTimeStamping    = "timestamping"
	EKUOCSPSigning     = "ocsp_signing"
)

// ekuOrder is the canonical display/encoding order for every EKU-keyed slice
// this package produces, independent of map iteration or user input order.
var ekuOrder = []string{EKUServerAuth, EKUClientAuth, EKUCodeSigning, EKUEmailProtection, EKUTimeStamping, EKUOCSPSigning}

var ekuLabels = map[string]string{
	EKUServerAuth:      "Server Authentication",
	EKUClientAuth:      "Client Authentication",
	EKUCodeSigning:     "Code Signing",
	EKUEmailProtection: "Email Protection (S/MIME)",
	EKUTimeStamping:    "Timestamping",
	EKUOCSPSigning:     "OCSP Signing",
}

var ekuToX509 = map[string]x509.ExtKeyUsage{
	EKUServerAuth:      x509.ExtKeyUsageServerAuth,
	EKUClientAuth:      x509.ExtKeyUsageClientAuth,
	EKUCodeSigning:     x509.ExtKeyUsageCodeSigning,
	EKUEmailProtection: x509.ExtKeyUsageEmailProtection,
	EKUTimeStamping:    x509.ExtKeyUsageTimeStamping,
	EKUOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
}

var x509ToEKU = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      EKUServerAuth,
	x509.ExtKeyUsageClientAuth:      EKUClientAuth,
	x509.ExtKeyUsageCodeSigning:     EKUCodeSigning,
	x509.ExtKeyUsageEmailProtection: EKUEmailProtection,
	x509.ExtKeyUsageTimeStamping:    EKUTimeStamping,
	x509.ExtKeyUsageOCSPSigning:     EKUOCSPSigning,
}

var ekuOIDs = map[string]asn1.ObjectIdentifier{
	EKUServerAuth:      {1, 3, 6, 1, 5, 5, 7, 3, 1},
	EKUClientAuth:      {1, 3, 6, 1, 5, 5, 7, 3, 2},
	EKUCodeSigning:     {1, 3, 6, 1, 5, 5, 7, 3, 3},
	EKUEmailProtection: {1, 3, 6, 1, 5, 5, 7, 3, 4},
	EKUTimeStamping:    {1, 3, 6, 1, 5, 5, 7, 3, 8},
	EKUOCSPSigning:     {1, 3, 6, 1, 5, 5, 7, 3, 9},
}

// extKeyUsageExtOID is the standard X.509 extended-key-usage extension OID
// (2.5.29.37), used both on an issued certificate and, as a CSR "extension
// request" attribute, to ask a CA to issue with these usages.
var extKeyUsageExtOID = asn1.ObjectIdentifier{2, 5, 29, 37}

// defaultExtKeyUsages is applied when nothing was explicitly requested,
// matching this app's historical self-sign behaviour (server + client auth).
var defaultExtKeyUsages = []string{EKUServerAuth, EKUClientAuth}

// ExtKeyUsageOption is one selectable extended key usage, for rendering a
// form's checkbox list.
type ExtKeyUsageOption struct {
	Key   string
	Label string
}

// ExtKeyUsageOptions lists every EKU the vault offers, in display order.
func ExtKeyUsageOptions() []ExtKeyUsageOption {
	out := make([]ExtKeyUsageOption, 0, len(ekuOrder))
	for _, k := range ekuOrder {
		out = append(out, ExtKeyUsageOption{Key: k, Label: ekuLabels[k]})
	}
	return out
}

// ExtKeyUsageLabel renders one key for humans, falling back to the raw key
// for anything unrecognised — defensive against data from an older version.
func ExtKeyUsageLabel(key string) string {
	if l, ok := ekuLabels[key]; ok {
		return l
	}
	return key
}

// NormalizeExtKeyUsages validates a set of requested EKU keys, de-duplicates
// them, and returns them in canonical display order. An empty or nil input
// is valid — it means "no specific EKU requested".
func NormalizeExtKeyUsages(keys []string) ([]string, error) {
	want := map[string]bool{}
	for _, k := range keys {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if _, ok := ekuLabels[k]; !ok {
			return nil, fmt.Errorf("certutil: unknown extended key usage %q", k)
		}
		want[k] = true
	}
	out := make([]string, 0, len(want))
	for _, k := range ekuOrder {
		if want[k] {
			out = append(out, k)
		}
	}
	return out, nil
}

// extKeyUsageExtension builds the extended-key-usage certificate extension
// as a CSR would carry it in its "extension request" attribute. Many public
// CAs decide EKU from their own product/profile and ignore this, but an
// internal or private CA reading the request directly can honour it.
func extKeyUsageExtension(keys []string) (pkix.Extension, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(keys))
	for _, k := range keys {
		oid, ok := ekuOIDs[k]
		if !ok {
			return pkix.Extension{}, fmt.Errorf("certutil: unknown extended key usage %q", k)
		}
		oids = append(oids, oid)
	}
	der, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("certutil: marshal extended key usage: %w", err)
	}
	return pkix.Extension{Id: extKeyUsageExtOID, Value: der}, nil
}

// x509ExtKeyUsages converts our keys to the standard library's enum, for
// issuing a real certificate (self-sign). Falls back to the historical
// server+client default when the input is empty.
func x509ExtKeyUsages(keys []string) []x509.ExtKeyUsage {
	if len(keys) == 0 {
		keys = defaultExtKeyUsages
	}
	out := make([]x509.ExtKeyUsage, 0, len(keys))
	for _, k := range keys {
		if eku, ok := ekuToX509[k]; ok {
			out = append(out, eku)
		}
	}
	return out
}

// DescribeRequestedExtKeyUsage reads the extended key usages a CSR itself
// requests via its extension-request attribute (OID 2.5.29.37) — used when
// importing a CSR generated elsewhere, where nothing else records what was
// asked for. Returns nil if the CSR carries no such extension.
func DescribeRequestedExtKeyUsage(csr *x509.CertificateRequest) []string {
	if csr == nil {
		return nil
	}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(extKeyUsageExtOID) {
			continue
		}
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			return nil
		}
		seen := map[string]bool{}
		for _, oid := range oids {
			for k, want := range ekuOIDs {
				if want.Equal(oid) {
					seen[k] = true
				}
			}
		}
		out := make([]string, 0, len(seen))
		for _, k := range ekuOrder {
			if seen[k] {
				out = append(out, k)
			}
		}
		return out
	}
	return nil
}

// DescribeExtKeyUsage reads the extended key usages actually present on an
// issued certificate — the ground truth once a CA (or this app's own
// self-sign path) has signed a request, which may differ from whatever was
// originally asked for.
func DescribeExtKeyUsage(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, eku := range cert.ExtKeyUsage {
		if k, ok := x509ToEKU[eku]; ok {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for _, k := range ekuOrder {
		if seen[k] {
			out = append(out, k)
		}
	}
	return out
}

// Subject carries the distinguished name fields of a CSR.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	Email              string
}

// CSRRequest is everything needed to mint a key plus a signing request.
type CSRRequest struct {
	Subject
	DNSNames     []string
	IPAddresses  []string
	KeySpec      KeySpec
	ExtKeyUsages []string // e.g. EKUServerAuth — requested via the CSR's extension-request attribute
}

// Validate checks the request before any expensive key generation happens.
func (r *CSRRequest) Validate() error {
	r.CommonName = strings.TrimSpace(r.CommonName)
	if r.CommonName == "" {
		return errors.New("common name is required")
	}
	if len(r.Country) > 0 && len(r.Country) != 2 {
		return errors.New("country must be a two letter ISO code")
	}
	r.DNSNames = cleanList(r.DNSNames)
	r.IPAddresses = cleanList(r.IPAddresses)
	for _, ip := range r.IPAddresses {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("%q is not a valid IP address", ip)
		}
	}
	spec, err := r.KeySpec.Normalize()
	if err != nil {
		return err
	}
	r.KeySpec = spec
	ekus, err := NormalizeExtKeyUsages(r.ExtKeyUsages)
	if err != nil {
		return err
	}
	r.ExtKeyUsages = ekus
	return nil
}

// pkixName builds the x509 distinguished name, omitting empty fields.
func (s Subject) pkixName() pkix.Name {
	name := pkix.Name{CommonName: strings.TrimSpace(s.CommonName)}
	if v := strings.TrimSpace(s.Organization); v != "" {
		name.Organization = []string{v}
	}
	if v := strings.TrimSpace(s.OrganizationalUnit); v != "" {
		name.OrganizationalUnit = []string{v}
	}
	if v := strings.TrimSpace(s.Country); v != "" {
		name.Country = []string{strings.ToUpper(v)}
	}
	if v := strings.TrimSpace(s.Province); v != "" {
		name.Province = []string{v}
	}
	if v := strings.TrimSpace(s.Locality); v != "" {
		name.Locality = []string{v}
	}
	return name
}

// CreateCSR generates a key pair and the matching PEM-encoded signing request.
// The common name is always included in the SAN list, as required by browsers.
func CreateCSR(req CSRRequest) (csrPEM string, key crypto.Signer, err error) {
	if err = req.Validate(); err != nil {
		return "", nil, err
	}
	key, err = GenerateKey(req.KeySpec)
	if err != nil {
		return "", nil, fmt.Errorf("certutil: generate key: %w", err)
	}

	dnsNames := req.DNSNames
	if net.ParseIP(req.CommonName) == nil && !contains(dnsNames, req.CommonName) {
		dnsNames = append([]string{req.CommonName}, dnsNames...)
	}
	ips := make([]net.IP, 0, len(req.IPAddresses))
	for _, raw := range req.IPAddresses {
		ips = append(ips, net.ParseIP(raw))
	}

	tmpl := &x509.CertificateRequest{
		Subject:            req.pkixName(),
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		SignatureAlgorithm: signatureAlgorithmFor(key),
	}
	if email := strings.TrimSpace(req.Email); email != "" {
		tmpl.EmailAddresses = []string{email}
	}
	if len(req.ExtKeyUsages) > 0 {
		ext, err := extKeyUsageExtension(req.ExtKeyUsages)
		if err != nil {
			return "", nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", nil, fmt.Errorf("certutil: create csr: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key, nil
}

// ParseCSRPEM decodes and checks the signature of a PEM-encoded CSR.
func ParseCSRPEM(data string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("certutil: input is not PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certutil: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certutil: csr signature invalid: %w", err)
	}
	return csr, nil
}

// ParseCertificatesPEM decodes every CERTIFICATE block in the input, in order.
func ParseCertificatesPEM(data string) ([]*x509.Certificate, error) {
	var (
		out  []*x509.Certificate
		rest = []byte(strings.TrimSpace(data))
	)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certutil: parse certificate: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("certutil: no PEM certificate found in input")
	}
	return out, nil
}

// EncodeCertificatePEM renders a parsed certificate back to PEM.
func EncodeCertificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// SelfSign issues a self-signed certificate from a CSR, useful for staging and
// internal endpoints while waiting for a real CA to sign the request. ekuKeys
// selects the issued certificate's extended key usages (e.g. EKUServerAuth);
// an empty/nil list falls back to the historical server+client default.
func SelfSign(csr *x509.CertificateRequest, key crypto.Signer, validDays int, ekuKeys []string) (*x509.Certificate, string, error) {
	if validDays <= 0 {
		validDays = 365
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("certutil: serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           x509ExtKeyUsages(ekuKeys),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, key)
	if err != nil {
		return nil, "", fmt.Errorf("certutil: self sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("certutil: parse self signed: %w", err)
	}
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// MatchesKey reports whether a certificate's public key belongs to the key.
func MatchesKey(cert *x509.Certificate, key crypto.Signer) bool {
	return publicKeyMatches(cert.PublicKey, key)
}

// MatchesCSRKey reports whether a signing request's public key belongs to
// the key — used when importing a CSR generated elsewhere (e.g. on an
// operator's own laptop via openssl), to catch a pasted key that doesn't
// actually pair with the pasted CSR.
func MatchesCSRKey(csr *x509.CertificateRequest, key crypto.Signer) bool {
	return publicKeyMatches(csr.PublicKey, key)
}

func publicKeyMatches(pub crypto.PublicKey, key crypto.Signer) bool {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		other, ok := key.Public().(*rsa.PublicKey)
		return ok && p.Equal(other)
	case *ecdsa.PublicKey:
		other, ok := key.Public().(*ecdsa.PublicKey)
		return ok && p.Equal(other)
	default:
		return false
	}
}

func signatureAlgorithmFor(key crypto.Signer) x509.SignatureAlgorithm {
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 384:
			return x509.ECDSAWithSHA384
		case 521:
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA256
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

func cleanList(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// SplitLines turns a textarea / comma separated blob into a clean slice.
func SplitLines(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	return cleanList(fields)
}
