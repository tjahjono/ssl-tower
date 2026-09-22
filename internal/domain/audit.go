package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Audit action identifiers. Kept as plain strings (not a closed enum) so a
// future action never requires a migration — the admin filter UI just lists
// whatever DistinctAuditActions returns.
const (
	AuditLoginSuccess           = "login_success"
	AuditLoginFailed            = "login_failed"
	AuditLogout                 = "logout"
	AuditPasswordChanged        = "password_changed"
	AuditMFAEnrolled            = "mfa_enrolled"
	AuditUserCreated            = "user_created"
	AuditUserRoleChanged        = "user_role_changed"
	AuditUserPasswordReset      = "user_password_reset"
	AuditUserMFAReset           = "user_mfa_reset"
	AuditUserDeleted            = "user_deleted"
	AuditCertificateCreated     = "certificate_created"
	AuditCertificateImported    = "certificate_imported"
	AuditCertificateCSRImported = "certificate_csr_imported"
	AuditCertificateDeleted     = "certificate_deleted"
	AuditCertificateAttached    = "certificate_attached"
	AuditCertificateSelfSigned  = "certificate_self_signed"
	AuditKeyDownloaded          = "private_key_downloaded"
	AuditHelpContentUpdated     = "help_content_updated"
	AuditCertificateChainEdited = "certificate_chain_edited"
	AuditCertificateSignedByCA  = "certificate_signed_by_root_ca"
	AuditRootCAUploaded         = "root_ca_uploaded"
	AuditRootCAGenerated        = "root_ca_generated"
	AuditRootCADeleted          = "root_ca_deleted"

	AuditRequestSubmitted = "certificate_request_submitted"
	AuditRequestApproved  = "certificate_request_approved"
	AuditRequestRejected  = "certificate_request_rejected"
	AuditRequestFulfilled = "certificate_request_fulfilled"
	AuditRequestDelivered = "certificate_request_delivered"
	AuditRequestCancelled = "certificate_request_cancelled"
	AuditRequestEmailed   = "certificate_request_emailed"

	// AuditDigiCertSubmitted records a ticket being submitted to the
	// DigiCert integration (Phase 6). Actual fulfillment once DigiCert
	// issues the certificate reuses the existing AuditRequestFulfilled —
	// DigiCert is just a different source for the certificate, not a
	// separate fulfillment event worth its own audit action.
	AuditDigiCertSubmitted = "certificate_digicert_submitted"

	// AuditSettingsUpdated records a save on the general /settings form
	// (expiry thresholds, SMTP, Teams, ticket SLA) — v1.5. Deliberately
	// separate from AuditEncryptionKeyRotated below: this is a routine,
	// low-stakes edit, while rotating the encryption key re-encrypts every
	// stored private key and deserves its own, more prominent audit action.
	AuditSettingsUpdated = "settings_updated"
	// AuditEncryptionKeyRotated records a successful call to
	// CertificateService.RotateEncryptionKey — the one settings change that
	// re-encrypts every stored private key. Detail carries the counts from
	// domain.RotationResult so the audit trail shows the blast radius, not
	// just "it happened."
	AuditEncryptionKeyRotated = "encryption_key_rotated"
)

// AuditEntry is one recorded action in the admin-facing audit trail. Actor
// fields are denormalized — captured at write time rather than joined from
// users — so a record stays readable even after the account is deleted.
type AuditEntry struct {
	ID         uuid.UUID
	ActorID    *uuid.UUID
	ActorEmail string
	Action     string
	TargetType string
	TargetID   string
	Detail     string
	IP         string
	CreatedAt  time.Time
}

// AuditFilter narrows the admin audit view. Zero values mean "no filter" for
// that field.
type AuditFilter struct {
	ActorEmail string
	Action     string
	Since      time.Time
	Until      time.Time
	Limit      int
}

// AuditRepository is the persistence port for the audit trail.
type AuditRepository interface {
	RecordAudit(ctx context.Context, e *AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
	DistinctAuditActions(ctx context.Context) ([]string, error)
}
