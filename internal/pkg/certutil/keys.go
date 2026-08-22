// Package certutil wraps the crypto/x509 primitives used by the application:
// key generation, CSR building, endpoint inspection and export encoding.
package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Key algorithms understood by the application.
const (
	AlgorithmRSA   = "rsa"
	AlgorithmECDSA = "ecdsa"
)

// KeySpec describes the private key to generate for a CSR.
type KeySpec struct {
	Algorithm string // "rsa" or "ecdsa"
	Bits      int    // RSA only: 2048, 3072 or 4096
	Curve     string // ECDSA only: P-256, P-384 or P-521
}

// Normalize validates the spec and fills in defaults.
func (s KeySpec) Normalize() (KeySpec, error) {
	out := KeySpec{Algorithm: strings.ToLower(strings.TrimSpace(s.Algorithm))}
	switch out.Algorithm {
	case "", AlgorithmRSA:
		out.Algorithm = AlgorithmRSA
		out.Bits = s.Bits
		if out.Bits == 0 {
			out.Bits = 2048
		}
		switch out.Bits {
		case 2048, 3072, 4096:
		default:
			return out, fmt.Errorf("certutil: unsupported RSA key size %d (use 2048, 3072 or 4096)", out.Bits)
		}
	case AlgorithmECDSA:
		out.Curve = strings.ToUpper(strings.TrimSpace(s.Curve))
		if out.Curve == "" {
			out.Curve = "P-256"
		}
		switch out.Curve {
		case "P-256", "P-384", "P-521":
		default:
			return out, fmt.Errorf("certutil: unsupported curve %q (use P-256, P-384 or P-521)", out.Curve)
		}
	default:
		return out, fmt.Errorf("certutil: unsupported key algorithm %q", s.Algorithm)
	}
	return out, nil
}

// Label renders the spec for display, e.g. "RSA 2048" or "ECDSA P-256".
func (s KeySpec) Label() string {
	if s.Algorithm == AlgorithmECDSA {
		return "ECDSA " + s.Curve
	}
	return fmt.Sprintf("RSA %d", s.Bits)
}

// GenerateKey creates a new private key matching the spec.
func GenerateKey(spec KeySpec) (crypto.Signer, error) {
	spec, err := spec.Normalize()
	if err != nil {
		return nil, err
	}
	switch spec.Algorithm {
	case AlgorithmECDSA:
		var curve elliptic.Curve
		switch spec.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return rsa.GenerateKey(rand.Reader, spec.Bits)
	}
}

// EncodePrivateKeyPEM serialises a key as an unencrypted PKCS#8 PEM block.
func EncodePrivateKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("certutil: marshal private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParsePrivateKeyPEM accepts PKCS#8, PKCS#1 and SEC1 EC private key PEM blocks.
func ParsePrivateKeyPEM(data string) (crypto.Signer, error) {
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("certutil: no private key found in PEM input")
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, errors.New("certutil: private key does not implement crypto.Signer")
			}
			return signer, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errors.New("certutil: unrecognised private key encoding")
	}
}

// DescribePublicKey reports a human readable algorithm name and key size in bits.
func DescribePublicKey(pub crypto.PublicKey) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "unknown", 0
	}
}

// SpecFromPublicKey derives the KeySpec that produced a given public key.
func SpecFromPublicKey(pub crypto.PublicKey) KeySpec {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return KeySpec{Algorithm: AlgorithmRSA, Bits: k.N.BitLen()}
	case *ecdsa.PublicKey:
		return KeySpec{Algorithm: AlgorithmECDSA, Curve: k.Curve.Params().Name}
	default:
		return KeySpec{}
	}
}
