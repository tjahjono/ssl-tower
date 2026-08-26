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
	AuditRootCADeleted          = "root_ca_deleted"

	AuditRequestSubmitted = "certificate_request_submitted"
	AuditRequestApproved  = "certificate_request_approved"
	AuditRequestRejected  = "certificate_request_rejected"
	AuditRequestFulfilled = "certificate_request_fulfilled"
	AuditRequestDelivered = "certificate_request_delivered"
	AuditRequestCancelled = "certificate_request_cancelled"
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
