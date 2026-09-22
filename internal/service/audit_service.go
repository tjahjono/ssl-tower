package service

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// AuditService records and lists the admin-facing audit trail.
type AuditService struct {
	repo domain.AuditRepository
	log  *slog.Logger
}

// NewAuditService wires the service to its repository.
func NewAuditService(repo domain.AuditRepository, log *slog.Logger) *AuditService {
	return &AuditService{repo: repo, log: log}
}

// Record appends one entry. It never returns an error to the caller — a
// logging failure must not undo, or even flash an error over, the real
// action it's describing; a failure is only ever logged for an operator to
// notice separately. actorID may be nil (an anonymous failed login, or a
// system-triggered action).
func (s *AuditService) Record(ctx context.Context, actorID *uuid.UUID, actorEmail, action, targetType, targetID, detail, ip string) {
	entry := &domain.AuditEntry{
		ActorID:    actorID,
		ActorEmail: actorEmail,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Detail:     detail,
		IP:         ip,
	}
	if err := s.repo.RecordAudit(ctx, entry); err != nil {
		s.log.Error("audit log write failed", "action", action, "error", err)
	}
}

// List returns the audit trail matching filter, newest first.
func (s *AuditService) List(ctx context.Context, filter domain.AuditFilter) ([]*domain.AuditEntry, error) {
	return s.repo.ListAudit(ctx, filter)
}

// Actions lists every action ever recorded, for the filter dropdown.
func (s *AuditService) Actions(ctx context.Context) ([]string, error) {
	return s.repo.DistinctAuditActions(ctx)
}
