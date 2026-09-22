package domain

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RootCA is an internal certificate authority this app can sign with
// directly — either an admin uploads an existing CA's certificate and
// private key, or (v1.6) the app mints a brand-new self-signed one in-app
// (CertificateService.GenerateRootCA) — after which a pending CSR can be
// issued against it (CertificateService's SignWithRootCA) instead of only
// ever self-signing or waiting on an outside CA.
type RootCA struct {
	ID   uuid.UUID
	Name string // operator-chosen label, e.g. "Acme Internal CA"

	CertificatePEM      string
	PrivateKeyPEM       string // ciphertext when PrivateKeyEncrypted is true
	PrivateKeyEncrypted bool

	// The fields below are captured once at upload time, the same way
	// Certificate captures Subject/Issuer/etc. at issuance — display data,
	// not re-parsed from the PEM on every read.
	Subject            string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize            int
	FingerprintSHA256  string

	NotBefore *time.Time
	NotAfter  *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// HasPrivateKey reports whether this CA can actually sign anything — always
// true for a properly uploaded CA, but a defensive check mirrors
// Certificate.HasPrivateKey rather than assuming it.
func (r *RootCA) HasPrivateKey() bool {
	return r != nil && strings.TrimSpace(r.PrivateKeyPEM) != ""
}

// CommonName pulls the CN out of the stored subject DN, for display.
func (r *RootCA) CommonName() string {
	if r == nil {
		return ""
	}
	return commonNameOf(r.Subject)
}

// DaysRemaining is days until the CA's own certificate expires, nil if
// unknown.
func (r *RootCA) DaysRemaining() *int {
	if r == nil || r.NotAfter == nil {
		return nil
	}
	d := int(time.Until(*r.NotAfter).Hours() / 24)
	return &d
}

// ExpiresIn renders the CA's remaining lifetime for humans, the same way
// Certificate.ExpiresIn does.
func (r *RootCA) ExpiresIn() string {
	days := r.DaysRemaining()
	if days == nil {
		return "—"
	}
	d := *days
	switch {
	case d < 0:
		return "expired " + itoa(-d) + " days ago"
	case d == 0:
		return "expires today"
	case d == 1:
		return "1 day"
	default:
		return itoa(d) + " days"
	}
}

// RootCARepository is the persistence port for uploaded Root CAs.
type RootCARepository interface {
	Create(ctx context.Context, r *RootCA) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*RootCA, error)
	List(ctx context.Context) ([]*RootCA, error)
}
