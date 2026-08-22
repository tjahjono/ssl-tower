package certutil

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// DecodePKCS12 decodes a PKCS#12 (.pfx/.p12) bundle, the inverse of the
// pkcs12() encoder below — used to import a certificate an operator uploads
// rather than generates in-app. The private key is nil when the bundle is a
// trust-store-only export (certificates but no key), which is a valid bundle
// to import, just one with fewer download formats available afterwards.
func DecodePKCS12(data []byte, password string) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	rawKey, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certutil: decode pkcs12: %w", err)
	}
	if rawKey == nil {
		return nil, cert, caCerts, nil
	}
	signer, ok := rawKey.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("certutil: pkcs12 private key does not implement crypto.Signer")
	}
	return signer, cert, caCerts, nil
}

// Supported download formats.
const (
	FormatPEM = "pem" // leaf + intermediates, PEM ("fullchain")
	FormatCRT = "crt" // leaf only, PEM
	FormatDER = "der" // leaf only, binary DER (also .cer)
	FormatKEY = "key" // private key, PKCS#8 PEM
	FormatCSR = "csr" // signing request, PEM
	FormatP7B = "p7b" // PKCS#7 certificates-only, DER
	FormatPFX = "pfx" // PKCS#12 key + chain, binary
	FormatZIP = "zip" // everything above in one archive
)

// ExportInput is the material available for a download.
type ExportInput struct {
	BaseName    string              // file name stem, e.g. "example.com"
	Leaf        *x509.Certificate   // nil when only a CSR exists
	Chain       []*x509.Certificate // intermediates, leaf excluded
	PrivateKey  crypto.Signer       // nil for monitored endpoints
	CSRPEM      string              // empty for monitored endpoints
	PFXPassword string
	PFXLegacy   bool // encode PKCS#12 with legacy RC2/3DES for old Windows/Java
}

// ExportResult is a ready-to-serve download.
type ExportResult struct {
	Filename    string
	ContentType string
	Data        []byte
}

// AvailableFormats lists the formats that can actually be produced from the input.
func (in ExportInput) AvailableFormats() []string {
	var out []string
	if in.Leaf != nil {
		out = append(out, FormatPEM, FormatCRT, FormatDER, FormatP7B, FormatPFX)
	}
	if in.PrivateKey != nil {
		out = append(out, FormatKEY)
	}
	if strings.TrimSpace(in.CSRPEM) != "" {
		out = append(out, FormatCSR)
	}
	if len(out) > 0 {
		out = append(out, FormatZIP)
	}
	return out
}

// Export renders the requested format.
func Export(in ExportInput, format string) (*ExportResult, error) {
	base := sanitizeBase(in.BaseName)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatPEM:
		data, err := in.fullChainPEM()
		if err != nil {
			return nil, err
		}
		return &ExportResult{base + ".pem", "application/x-pem-file", data}, nil

	case FormatCRT:
		if in.Leaf == nil {
			return nil, errNoCertificate
		}
		return &ExportResult{base + ".crt", "application/x-x509-ca-cert",
			[]byte(EncodeCertificatePEM(in.Leaf))}, nil

	case FormatDER:
		if in.Leaf == nil {
			return nil, errNoCertificate
		}
		return &ExportResult{base + ".der", "application/x-x509-ca-cert", in.Leaf.Raw}, nil

	case FormatKEY:
		data, err := in.keyPEM()
		if err != nil {
			return nil, err
		}
		return &ExportResult{base + ".key", "application/x-pem-file", data}, nil

	case FormatCSR:
		if strings.TrimSpace(in.CSRPEM) == "" {
			return nil, errors.New("certutil: no signing request available")
		}
		return &ExportResult{base + ".csr", "application/pkcs10", []byte(in.CSRPEM)}, nil

	case FormatP7B:
		data, err := in.pkcs7()
		if err != nil {
			return nil, err
		}
		return &ExportResult{base + ".p7b", "application/x-pkcs7-certificates", data}, nil

	case FormatPFX, "p12", "pkcs12":
		data, err := in.pkcs12()
		if err != nil {
			return nil, err
		}
		return &ExportResult{base + ".pfx", "application/x-pkcs12", data}, nil

	case FormatZIP:
		return in.bundle(base)

	default:
		return nil, fmt.Errorf("certutil: unknown export format %q", format)
	}
}

var errNoCertificate = errors.New("certutil: no certificate available yet")

func (in ExportInput) fullChainPEM() ([]byte, error) {
	if in.Leaf == nil {
		return nil, errNoCertificate
	}
	var sb strings.Builder
	sb.WriteString(EncodeCertificatePEM(in.Leaf))
	for _, c := range in.Chain {
		sb.WriteString(EncodeCertificatePEM(c))
	}
	return []byte(sb.String()), nil
}

func (in ExportInput) keyPEM() ([]byte, error) {
	if in.PrivateKey == nil {
		return nil, errors.New("certutil: no private key available")
	}
	s, err := EncodePrivateKeyPEM(in.PrivateKey)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func (in ExportInput) pkcs12() ([]byte, error) {
	if in.Leaf == nil {
		return nil, errNoCertificate
	}
	password := in.PFXPassword
	encoder := pkcs12.Modern
	if in.PFXLegacy {
		encoder = pkcs12.LegacyRC2
	}
	if in.PrivateKey == nil {
		// No key: emit a trust store containing the observed chain instead.
		certs := append([]*x509.Certificate{in.Leaf}, in.Chain...)
		if password == "" {
			return pkcs12.Passwordless.EncodeTrustStore(certs, "")
		}
		return encoder.EncodeTrustStore(certs, password)
	}
	if password == "" {
		return pkcs12.Passwordless.Encode(in.PrivateKey, in.Leaf, in.Chain, "")
	}
	return encoder.Encode(in.PrivateKey, in.Leaf, in.Chain, password)
}

func (in ExportInput) bundle(base string) (*ExportResult, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	if in.Leaf != nil {
		if err := add(base+".crt", []byte(EncodeCertificatePEM(in.Leaf))); err != nil {
			return nil, err
		}
		if err := add(base+".der", in.Leaf.Raw); err != nil {
			return nil, err
		}
		if full, err := in.fullChainPEM(); err == nil {
			if err := add(base+".pem", full); err != nil {
				return nil, err
			}
		}
		if p7, err := in.pkcs7(); err == nil {
			if err := add(base+".p7b", p7); err != nil {
				return nil, err
			}
		}
		if pfx, err := in.pkcs12(); err == nil {
			if err := add(base+".pfx", pfx); err != nil {
				return nil, err
			}
		}
		if len(in.Chain) > 0 {
			var sb strings.Builder
			for _, c := range in.Chain {
				sb.WriteString(EncodeCertificatePEM(c))
			}
			if err := add(base+"-chain.pem", []byte(sb.String())); err != nil {
				return nil, err
			}
		}
	}
	if in.PrivateKey != nil {
		key, err := in.keyPEM()
		if err != nil {
			return nil, err
		}
		if err := add(base+".key", key); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(in.CSRPEM) != "" {
		if err := add(base+".csr", []byte(in.CSRPEM)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &ExportResult{base + "-bundle.zip", "application/zip", buf.Bytes()}, nil
}

// --- Minimal PKCS#7 "certs only" (degenerate SignedData) encoder ------------
//
// Go has no PKCS#7 support in the standard library, and .p7b files are just a
// SignedData with no signers whose only payload is the certificate set, so the
// structure is short enough to build directly with encoding/asn1.

var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// Content carries the explicit [0] wrapper in its own Class/Tag rather than in a
// struct tag: encoding/asn1 emits a RawValue's Bytes under the tag the value
// declares, and ignores struct-tag wrapping for raw values.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

type pkcs7EncapsulatedContent struct {
	ContentType asn1.ObjectIdentifier
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	ContentInfo      pkcs7EncapsulatedContent
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// pkcs7 encodes leaf + chain as a DER PKCS#7 certificate bag (.p7b).
func (in ExportInput) pkcs7() ([]byte, error) {
	if in.Leaf == nil {
		return nil, errNoCertificate
	}
	certs := append([]*x509.Certificate{in.Leaf}, in.Chain...)

	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}

	signed := pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{},
		ContentInfo:      pkcs7EncapsulatedContent{ContentType: oidPKCS7Data},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      raw,
		},
		SignerInfos: []asn1.RawValue{},
	}
	signedDER, err := asn1.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("certutil: marshal pkcs7 signed data: %w", err)
	}

	out, err := asn1.Marshal(pkcs7ContentInfo{
		ContentType: oidPKCS7SignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDER,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("certutil: marshal pkcs7 content info: %w", err)
	}
	return out, nil
}

// DecodePKCS7Certificates reads the certificates back out of a DER PKCS#7 bag.
// It is the inverse of pkcs7 and is used to verify exports.
func DecodePKCS7Certificates(der []byte) ([]*x509.Certificate, error) {
	var outer pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, fmt.Errorf("certutil: parse pkcs7: %w", err)
	}
	if !outer.ContentType.Equal(oidPKCS7SignedData) {
		return nil, errors.New("certutil: pkcs7 blob is not signed data")
	}

	var signed struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &signed); err != nil {
		return nil, fmt.Errorf("certutil: parse pkcs7 signed data: %w", err)
	}
	if len(signed.Certificates.Bytes) == 0 {
		return nil, errors.New("certutil: pkcs7 blob carries no certificates")
	}
	return x509.ParseCertificates(signed.Certificates.Bytes)
}

// PKCS7PEM wraps a DER PKCS#7 blob in a PEM envelope, the form OpenSSL emits.
func PKCS7PEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
}

func sanitizeBase(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "certificate"
	}
	replacer := strings.NewReplacer("*", "wildcard", "/", "-", "\\", "-", " ", "-", ":", "-", "..", "-")
	name = replacer.Replace(name)
	name = strings.Trim(name, ".-")
	if name == "" {
		name = "certificate"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}
