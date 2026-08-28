package domain

import (
	"context"

	"github.com/ivangiovn/ssl-generator/internal/pkg/secret"
)

// Setting keys stored in app_settings. Deliberately plain string constants,
// not a closed enum type — that matches how the underlying table actually
// works (any key is a valid row) and mirrors SiteContentHelp's shape.
const (
	SettingExpiryWarningDays  = "expiry_warning_days"
	SettingExpiryCriticalDays = "expiry_critical_days"
	SettingExpiryFinalDays    = "expiry_final_days"

	SettingSMTPHost       = "smtp_host"
	SettingSMTPPort       = "smtp_port"
	SettingSMTPUsername   = "smtp_username"
	SettingSMTPPassword   = "smtp_password"
	SettingAlertEmailFrom = "alert_email_from"
	SettingAlertEmailTo   = "alert_email_to"

	SettingTeamsWebhookURL = "teams_webhook_url"

	SettingTicketSLADays = "ticket_sla_days"

	// SettingEncryptionKey is persisted in this same table — there is
	// nowhere else durable to put it once it's portal-editable — but it is
	// deliberately NOT part of AppSettings/SettingsService's generic
	// get-all/update surface. Rotating it is a fundamentally different,
	// much higher-stakes operation (it re-encrypts every stored private
	// key) than saving any other setting here, and is handled entirely by
	// CertificateService.RotateEncryptionKey instead. See CLAUDE.md's
	// locked decision on why.
	SettingEncryptionKey = "app_encryption_key"
)

// AppSettings is the live, typed snapshot of every portal-editable
// operational setting except the encryption key (see SettingEncryptionKey
// above) — SettingsService.Current returns one of these, cached in memory
// and refreshed on every successful Update, so the rest of the app never
// has to hit the database just to check a threshold or an SMTP host.
type AppSettings struct {
	ExpiryWarningDays  int
	ExpiryCriticalDays int
	ExpiryFinalDays    int

	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	AlertEmailFrom string
	AlertEmailTo   []string

	TeamsWebhookURL string

	TicketSLADays int
}

// SettingsRepository is the persistence port for admin-editable operational
// settings — a plain key/value store. SettingsService is what gives it
// typed structure, validation, and a live in-memory cache.
type SettingsRepository interface {
	// Get returns a single key's stored value. found is false when no row
	// exists for key yet — not an error, since that's the normal state for
	// any key before it's ever been written.
	Get(ctx context.Context, key string) (value string, found bool, err error)
	// GetAll returns every stored key/value pair — used by
	// SettingsService.Reload to rebuild the typed live snapshot in one
	// round trip rather than one query per field.
	GetAll(ctx context.Context) (map[string]string, error)
	// SetMany atomically writes every key in values in a single
	// transaction, so a multi-field form save can never leave some fields
	// updated and others not.
	SetMany(ctx context.Context, values map[string]string, updatedBy string) error
}

// RotationResult reports how many stored private keys were re-encrypted by
// a successful CertificateService.RotateEncryptionKey call — surfaced to
// the admin and the audit trail so a rotation's blast radius is visible,
// not just "it worked."
type RotationResult struct {
	CertificatesReencrypted int
	RootCAsReencrypted      int
}

// EncryptionRotationRepository is the persistence port for rotating the
// vault's private-key encryption key: re-encrypting every stored private
// key from oldSealer to newSealer and persisting newKeyValue as the new
// SettingEncryptionKey row, atomically. See CertificateService.
// RotateEncryptionKey, the only caller — this is deliberately its own
// narrow interface rather than a method on CertificateRepository or
// SettingsRepository, since it's the one operation in this app that can
// corrupt every stored private key if it goes wrong.
type EncryptionRotationRepository interface {
	RotateEncryptionKey(ctx context.Context, oldSealer, newSealer *secret.Sealer, newKeyValue string) (RotationResult, error)
}
