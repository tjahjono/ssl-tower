package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
)

// SettingsService owns every portal-editable operational setting except the
// encryption key (see domain.SettingEncryptionKey and
// CertificateService.RotateEncryptionKey) — the day/percent expiry alert
// thresholds, SMTP, Microsoft Teams, and the ticket SLA window. These used
// to be .env-only values, required at boot and fixed until a restart; now
// an admin edits them from the /settings page and the change takes effect
// immediately, because every consumer reads Current() at the moment it
// needs a value rather than being handed a frozen struct at construction.
//
// current is a plain field guarded by a mutex would work just as well here
// — the update rate is "an admin clicks save" — but atomic.Pointer keeps
// every read (which happens on every certificate health check, every alert
// evaluation, every ticket SLA check) lock-free.
type SettingsService struct {
	repo    domain.SettingsRepository
	log     *slog.Logger
	current atomic.Pointer[domain.AppSettings]
}

// NewSettingsService wires the service to its repository. Callers must call
// Bootstrap then Reload (or just Bootstrap, which calls Reload itself)
// before Current returns anything meaningful — until then it returns a
// zero-value AppSettings.
func NewSettingsService(repo domain.SettingsRepository, log *slog.Logger) *SettingsService {
	s := &SettingsService{repo: repo, log: log}
	s.current.Store(&domain.AppSettings{})
	return s
}

// SeedValues carries the env-sourced values Bootstrap uses to populate
// app_settings the very first time this app boots against a fresh
// database — mirrors AuthService.Bootstrap's shape (plain values, not a
// *config.Config, so this package never imports internal/config).
type SeedValues struct {
	Settings      domain.AppSettings
	EncryptionKey string
}

// settingKeys lists every domain.Setting* key that belongs to
// AppSettings's generic get/all/update surface — deliberately excludes
// domain.SettingEncryptionKey, which Bootstrap seeds directly and
// Update/Reload never touch.
var settingKeys = []string{
	domain.SettingExpiryWarningDays, domain.SettingExpiryCriticalDays, domain.SettingExpiryFinalDays,
	domain.SettingSMTPHost, domain.SettingSMTPPort, domain.SettingSMTPUsername, domain.SettingSMTPPassword,
	domain.SettingAlertEmailFrom, domain.SettingAlertEmailTo,
	domain.SettingTeamsWebhookURL,
	domain.SettingTicketSLADays,
}

// Bootstrap seeds app_settings from seed, but only for keys that don't
// already have a row — safe to call on every boot, exactly like
// AuthService.Bootstrap: a fresh database gets its initial values from
// whatever's in .env at that moment (see config.Load's now-optional
// EXPIRY_*/SMTP_*/ALERT_EMAIL_*/TEAMS_WEBHOOK_URL/TICKET_SLA_DAYS/
// APP_ENCRYPTION_KEY fields), and every later boot leaves already-seeded
// keys alone — the portal, not .env, is authoritative for them from that
// point on. A deployment that adds a brand-new setting key in a future
// version still gets that one key seeded from its env fallback (if any)
// without disturbing values an admin already edited for every other key,
// since each key's presence is checked independently.
func (s *SettingsService) Bootstrap(ctx context.Context, seed SeedValues) error {
	existing, err := s.repo.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("settings: bootstrap: %w", err)
	}

	toSeed := map[string]string{}
	seedIfMissing := func(key, value string) {
		if _, ok := existing[key]; !ok {
			toSeed[key] = value
		}
	}
	seedIfMissing(domain.SettingExpiryWarningDays, strconv.Itoa(seed.Settings.ExpiryWarningDays))
	seedIfMissing(domain.SettingExpiryCriticalDays, strconv.Itoa(seed.Settings.ExpiryCriticalDays))
	seedIfMissing(domain.SettingExpiryFinalDays, strconv.Itoa(seed.Settings.ExpiryFinalDays))
	seedIfMissing(domain.SettingSMTPHost, seed.Settings.SMTPHost)
	seedIfMissing(domain.SettingSMTPPort, strconv.Itoa(seed.Settings.SMTPPort))
	seedIfMissing(domain.SettingSMTPUsername, seed.Settings.SMTPUsername)
	seedIfMissing(domain.SettingSMTPPassword, seed.Settings.SMTPPassword)
	seedIfMissing(domain.SettingAlertEmailFrom, seed.Settings.AlertEmailFrom)
	seedIfMissing(domain.SettingAlertEmailTo, strings.Join(seed.Settings.AlertEmailTo, ","))
	seedIfMissing(domain.SettingTeamsWebhookURL, seed.Settings.TeamsWebhookURL)
	seedIfMissing(domain.SettingTicketSLADays, strconv.Itoa(seed.Settings.TicketSLADays))
	seedIfMissing(domain.SettingEncryptionKey, seed.EncryptionKey)

	if len(toSeed) > 0 {
		if err := s.repo.SetMany(ctx, toSeed, "bootstrap"); err != nil {
			return fmt.Errorf("settings: bootstrap: %w", err)
		}
		s.log.Info("settings: seeded initial values from .env — edit them from /settings from now on", "keys", len(toSeed))
	}
	return s.Reload(ctx)
}

// Current returns the live settings snapshot. Always safe to call, even
// before Bootstrap/Reload — returns a zero-value AppSettings until then.
func (s *SettingsService) Current() domain.AppSettings {
	return *s.current.Load()
}

// Reload re-reads every setting from storage and atomically swaps the live
// snapshot. Called after every successful Update, and once at boot via
// Bootstrap.
func (s *SettingsService) Reload(ctx context.Context) error {
	values, err := s.repo.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("settings: reload: %w", err)
	}
	next := domain.AppSettings{
		ExpiryWarningDays:  parseIntSetting(s.log, values, domain.SettingExpiryWarningDays),
		ExpiryCriticalDays: parseIntSetting(s.log, values, domain.SettingExpiryCriticalDays),
		ExpiryFinalDays:    parseIntSetting(s.log, values, domain.SettingExpiryFinalDays),
		SMTPHost:           values[domain.SettingSMTPHost],
		SMTPPort:           parseIntSetting(s.log, values, domain.SettingSMTPPort),
		SMTPUsername:       values[domain.SettingSMTPUsername],
		SMTPPassword:       values[domain.SettingSMTPPassword],
		AlertEmailFrom:     values[domain.SettingAlertEmailFrom],
		AlertEmailTo:       splitTrimmed(values[domain.SettingAlertEmailTo]),
		TeamsWebhookURL:    values[domain.SettingTeamsWebhookURL],
		TicketSLADays:      parseIntSetting(s.log, values, domain.SettingTicketSLADays),
	}
	s.current.Store(&next)
	return nil
}

// Update validates patch, persists every field in one transaction, and
// reloads the live snapshot — updatedBy is the editing admin's email, for
// the app_settings rows' own updated_by column (the audit trail entry
// itself is recorded by the delivery handler, same convention as
// AuthService's user-management methods).
func (s *SettingsService) Update(ctx context.Context, patch domain.AppSettings, updatedBy string) error {
	if patch.ExpiryCriticalDays > patch.ExpiryWarningDays {
		return domain.Invalid("expiry_critical_days", "must be less than or equal to the warning threshold")
	}
	if patch.ExpiryFinalDays > patch.ExpiryCriticalDays {
		return domain.Invalid("expiry_final_days", "must be less than or equal to the critical threshold")
	}

	values := map[string]string{
		domain.SettingExpiryWarningDays:  strconv.Itoa(patch.ExpiryWarningDays),
		domain.SettingExpiryCriticalDays: strconv.Itoa(patch.ExpiryCriticalDays),
		domain.SettingExpiryFinalDays:    strconv.Itoa(patch.ExpiryFinalDays),
		domain.SettingSMTPHost:           strings.TrimSpace(patch.SMTPHost),
		domain.SettingSMTPPort:           strconv.Itoa(patch.SMTPPort),
		domain.SettingSMTPUsername:       strings.TrimSpace(patch.SMTPUsername),
		domain.SettingSMTPPassword:       patch.SMTPPassword,
		domain.SettingAlertEmailFrom:     strings.TrimSpace(patch.AlertEmailFrom),
		domain.SettingAlertEmailTo:       strings.Join(patch.AlertEmailTo, ","),
		domain.SettingTeamsWebhookURL:    strings.TrimSpace(patch.TeamsWebhookURL),
		domain.SettingTicketSLADays:      strconv.Itoa(patch.TicketSLADays),
	}
	if err := s.repo.SetMany(ctx, values, updatedBy); err != nil {
		return err
	}
	return s.Reload(ctx)
}

// EncryptionKeyValue reads the current APP_ENCRYPTION_KEY value directly —
// deliberately bypassing the cached AppSettings snapshot, since this value
// is sensitive enough that it shouldn't sit in a struct that gets copied
// around and logged/rendered as casually as every other setting. Only
// CertificateService (at boot, and inside RotateEncryptionKey) should ever
// call this.
func (s *SettingsService) EncryptionKeyValue(ctx context.Context) (string, error) {
	value, _, err := s.repo.Get(ctx, domain.SettingEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("settings: read encryption key: %w", err)
	}
	return value, nil
}

// EmailNotifier builds a fresh notify.EmailNotifier from the current
// settings snapshot. Deliberately built on demand rather than cached — the
// notifier is a cheap, stateless config holder (no persistent SMTP
// connection), so "always current" costs nothing and needs no invalidation
// logic when an admin changes SMTP settings.
func (s *SettingsService) EmailNotifier() *notify.EmailNotifier {
	cur := s.Current()
	return notify.NewEmailNotifier(notify.EmailConfig{
		Host: cur.SMTPHost, Port: cur.SMTPPort,
		Username: cur.SMTPUsername, Password: cur.SMTPPassword,
		From: cur.AlertEmailFrom, To: cur.AlertEmailTo,
	})
}

// TeamsNotifier builds a fresh notify.TeamsNotifier from the current
// settings snapshot — see EmailNotifier's doc comment for why "on demand"
// rather than cached.
func (s *SettingsService) TeamsNotifier() *notify.TeamsNotifier {
	return notify.NewTeamsNotifier(s.Current().TeamsWebhookURL)
}

func parseIntSetting(log *slog.Logger, values map[string]string, key string) int {
	raw, ok := values[key]
	if !ok || raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		log.Warn("settings: stored value isn't a valid integer, using 0", "key", key, "value", raw, "error", err)
		return 0
	}
	return n
}

func splitTrimmed(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
