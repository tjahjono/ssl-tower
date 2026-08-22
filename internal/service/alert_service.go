package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
)

// AlertLevel ranks how urgent a certificate's expiry is. Comparing the
// current level to the level last notified is what lets a steady-state
// condition go quiet after the first notification, instead of re-notifying
// forever.
type AlertLevel int

// Alert levels, from healthy to expired.
const (
	AlertNone AlertLevel = iota
	AlertWarning
	AlertCritical
	AlertFinal
)

// String renders the level for alert subject lines and bodies.
func (l AlertLevel) String() string {
	switch l {
	case AlertWarning:
		return "expiring soon"
	case AlertCritical:
		return "critical"
	case AlertFinal:
		return "expiring within a day, or already expired"
	default:
		return "healthy"
	}
}

// tag is the short uppercase label used in alert subject lines.
func (l AlertLevel) tag() string {
	switch l {
	case AlertWarning:
		return "WARNING"
	case AlertCritical:
		return "CRITICAL"
	case AlertFinal:
		return "FINAL NOTICE"
	default:
		return "OK"
	}
}

// color is the Teams MessageCard accent (a bare hex triplet), roughly
// matching the severity tones already used for status badges in the UI.
func (l AlertLevel) color() string {
	switch l {
	case AlertWarning:
		return "F2C744"
	case AlertCritical:
		return "FF8C00"
	case AlertFinal:
		return "D13438"
	default:
		return "6B7280"
	}
}

// AlertThresholds configures the day-count boundaries that promote a
// certificate from one alert level to the next.
type AlertThresholds struct {
	WarningDays  int
	CriticalDays int
	FinalDays    int
}

// AlertRepository is the narrow persistence port alerting needs: just enough
// to remember the level last notified per certificate. CertificateRepository
// satisfies this directly.
type AlertRepository interface {
	AlertLevel(ctx context.Context, certificateID uuid.UUID) (int, error)
	SetAlertLevel(ctx context.Context, certificateID uuid.UUID, level int) error
}

// AlertService evaluates a certificate's expiry against configured
// thresholds and notifies over email and/or Microsoft Teams — at most once
// per state change, never once per evaluation.
type AlertService struct {
	repo       AlertRepository
	email      *notify.EmailNotifier
	teams      *notify.TeamsNotifier
	log        *slog.Logger
	thresholds AlertThresholds
}

// NewAlertService builds the alerting service. email and teams may be
// notifiers built from empty configuration — Send/Enabled on both handle
// that as a no-op, so callers never need to check for nil channels here.
func NewAlertService(repo AlertRepository, email *notify.EmailNotifier, teams *notify.TeamsNotifier, log *slog.Logger, thresholds AlertThresholds) *AlertService {
	if thresholds.WarningDays <= 0 {
		thresholds.WarningDays = 30
	}
	if thresholds.CriticalDays <= 0 {
		thresholds.CriticalDays = 7
	}
	if thresholds.FinalDays <= 0 {
		thresholds.FinalDays = 1
	}
	return &AlertService{repo: repo, email: email, teams: teams, log: log, thresholds: thresholds}
}

// Enabled reports whether at least one notification channel is configured —
// useful for a boot-time log line so a silently misconfigured deployment
// isn't discovered only when the first certificate actually expires.
func (a *AlertService) Enabled() bool {
	return a != nil && (a.email.Enabled() || a.teams.Enabled())
}

func (a *AlertService) levelFor(c *domain.Certificate) AlertLevel {
	days := c.DaysRemaining()
	if days == nil {
		return AlertNone
	}
	d := *days
	switch {
	case d <= a.thresholds.FinalDays:
		return AlertFinal
	case d <= a.thresholds.CriticalDays:
		return AlertCritical
	case d <= a.thresholds.WarningDays:
		return AlertWarning
	default:
		return AlertNone
	}
}

// Evaluate is called after a certificate is created, issued, or imported,
// and again on every periodic alert sweep. It notifies once when the alert
// level first reaches a given severity (never re-notifying while it holds
// steady), and resets quietly on recovery so a future re-degradation alerts
// again — recovery here almost always means the certificate was replaced by
// a fresh one, since nothing un-expires on its own.
func (a *AlertService) Evaluate(ctx context.Context, c *domain.Certificate) {
	if a == nil || c == nil || c.Status != domain.CertIssued {
		return
	}

	level := a.levelFor(c)
	prevRaw, err := a.repo.AlertLevel(ctx, c.ID)
	if err != nil {
		a.log.Warn("alert: read last level failed", "certificate", c.ID, "error", err)
		return
	}
	prev := AlertLevel(prevRaw)
	if level == prev {
		return
	}
	if err := a.repo.SetAlertLevel(ctx, c.ID, int(level)); err != nil {
		a.log.Warn("alert: persist level failed", "certificate", c.ID, "error", err)
	}
	if level == AlertNone {
		// Recovered — reset silently, no "all clear" notification requested.
		return
	}

	subject := fmt.Sprintf("[%s] %s is %s", level.tag(), c.CommonName, level.String())
	body := fmt.Sprintf("%s %s. Issuer: %s.", c.CommonName, c.ExpiresIn(), c.IssuerCommonName())
	a.notify(ctx, subject, body, level.color())
}

// notify fans one alert out to every configured channel. A channel failing
// is logged and otherwise ignored — a broken webhook or SMTP relay must
// never block certificate operations, and the other channel might still get
// through.
func (a *AlertService) notify(ctx context.Context, subject, body, color string) {
	if a.email.Enabled() {
		if err := a.email.Send(subject, body); err != nil {
			a.log.Warn("alert: email send failed", "error", err)
		}
	}
	if a.teams.Enabled() {
		if err := a.teams.Send(ctx, subject, body, color); err != nil {
			a.log.Warn("alert: teams send failed", "error", err)
		}
	}
}
