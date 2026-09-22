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

	// LDAP settings (v1.8) — portal-editable, same "empty URL = off"
	// convention every other optional integration in this table already
	// follows. See CLAUDE.md's v1.8 locked decision for the full model;
	// AppSettings' own field doc comments below cover the individual
	// fields' semantics (carried over unchanged from the old env-only
	// config.Config fields of the same names).
	SettingLDAPURL          = "ldap_url"
	SettingLDAPBindDN       = "ldap_bind_dn"
	SettingLDAPBindPassword = "ldap_bind_password"
	SettingLDAPBaseDN       = "ldap_base_dn"
	SettingLDAPUserFilter   = "ldap_user_filter"
	SettingLDAPGroupFilter  = "ldap_group_filter"

	SettingLDAPRoleMapEditor    = "ldap_role_map_editor"
	SettingLDAPRoleMapViewer    = "ldap_role_map_viewer"
	SettingLDAPRoleMapRequester = "ldap_role_map_requester"

	// ADCS settings (v1.16) — portal-editable, same "empty endpoint = off"
	// convention LDAP/SMTP/Teams already follow. See CLAUDE.md's v1.16
	// locked decision; AppSettings' own field doc comments below cover the
	// individual fields' semantics (carried over unchanged from the old
	// env-only config.Config fields of the same names, v1.14).
	SettingADCSEndpoint = "adcs_endpoint"
	SettingADCSUsername = "adcs_username"
	SettingADCSPassword = "adcs_password"
	SettingADCSTemplate = "adcs_template"

	// Email transport (v1.18) — "smtp" (the default, and the only behavior
	// that existed before this) or "graph" (Microsoft Graph API). Portal-
	// editable, same table as everything else here. See
	// EmailTransportSMTP/EmailTransportGraph below and CLAUDE.md's v1.18
	// locked decision: Microsoft is retiring SMTP AUTH with a plain
	// username and password for Exchange Online/Microsoft 365 — Basic
	// Authentication disabled by default for existing tenants by the end
	// of December 2026, OAuth-only for every tenant created after that —
	// so a deployment sending alert/ticket email through M365 needs a way
	// off plain SMTP auth before then. Selecting "graph" here requires the
	// Graph fields below to actually be configured (enforced by
	// SettingsService.Update's validateGraphPatch, not here).
	SettingEmailTransport = "email_transport"

	// Microsoft Graph API email (v1.18) — the OAuth2/app-registration
	// alternative to SMTP username+password. GraphTenantID is this
	// section's own "empty = off" toggle (independent of whether Graph is
	// actually the *active* transport — see SettingEmailTransport above):
	// once set, GraphClientID/GraphClientSecret/GraphSenderAddress become
	// required.
	SettingGraphTenantID      = "graph_tenant_id"
	SettingGraphClientID      = "graph_client_id"
	SettingGraphClientSecret  = "graph_client_secret"
	SettingGraphSenderAddress = "graph_sender_address"

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

// Email transport values for AppSettings.EmailTransport /
// SettingEmailTransport — see that field's doc comment.
const (
	EmailTransportSMTP  = "smtp"
	EmailTransportGraph = "graph"
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

	// LDAP authentication (v1.8, portal-editable — env-only as of v1.4).
	// LDAPURL is the "empty = off" toggle: every account authenticates with
	// a local password when it's empty, exactly as if LDAP had never been
	// configured. Once set, LDAPBindDN/LDAPBindPassword/LDAPBaseDN/
	// LDAPUserFilter/LDAPGroupFilter become required and at least one of
	// LDAPRoleMapEditor/Viewer/Requester must be non-empty — enforced by
	// SettingsService.Update, not here (this struct carries no validation
	// of its own, matching every other field in it). See CLAUDE.md's LDAP
	// locked decisions for the full authentication model.
	LDAPURL          string
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPBaseDN       string
	LDAPUserFilter   string
	LDAPGroupFilter  string

	// LDAPRoleMapEditor/Viewer/Requester each list the LDAP group DNs whose
	// members hold that role, checked in this order (most privileged
	// matching group wins). No LDAPRoleMapAdmin field, deliberately: admin
	// is always locally-granted, never LDAP-derived.
	LDAPRoleMapEditor    []string
	LDAPRoleMapViewer    []string
	LDAPRoleMapRequester []string

	// ADCS CES/CEP integration (v1.16, portal-editable — env-only as of
	// v1.14). ADCSEndpoint is the "empty = off" toggle: empty means the
	// pending-certificate detail page's "Sign with" dropdown simply doesn't
	// offer "Submit to ADCS". Once set, ADCSUsername/ADCSPassword/
	// ADCSTemplate become required — enforced by SettingsService.Update,
	// not here. See CLAUDE.md's ADCS locked decisions for the full model.
	ADCSEndpoint string
	ADCSUsername string
	ADCSPassword string
	ADCSTemplate string

	// EmailTransport picks which channel SettingsService.Mailer returns —
	// EmailTransportSMTP (the default, and every behavior that existed
	// before v1.18) or EmailTransportGraph. See CLAUDE.md's v1.18 locked
	// decision.
	EmailTransport string

	// Microsoft Graph API email (v1.18) — the OAuth2/app-registration
	// alternative to plain SMTP username+password, which Microsoft is
	// retiring for Exchange Online/Microsoft 365. GraphTenantID is the
	// "empty = off" toggle for this section's own required-fields check;
	// once set, GraphClientID/GraphClientSecret/GraphSenderAddress become
	// required — enforced by SettingsService.Update, not here. The app
	// registration needs the Mail.Send *application* permission, admin-
	// consented; GraphSenderAddress is the mailbox Graph sends as (POSTed
	// to /v1.0/users/{GraphSenderAddress}/sendMail — see
	// internal/pkg/graphmail).
	GraphTenantID      string
	GraphClientID      string
	GraphClientSecret  string
	GraphSenderAddress string
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
//
// progress, when non-nil, is called synchronously from inside the still-open
// transaction: once with (0, total) as soon as the total row count across
// both tables is known, then once more after each row is re-encrypted. This
// is what lets the caller show a real, live progress bar (v1.7) rather than
// a fake animation — but the callback runs before commit, so a progress
// report of e.g. "30 of 47" is only ever a report of work done inside the
// pending transaction, not a durability guarantee; a failure after that
// point still rolls everything back, same as before this existed.
type EncryptionRotationRepository interface {
	RotateEncryptionKey(ctx context.Context, oldSealer, newSealer *secret.Sealer, newKeyValue string, progress func(done, total int)) (RotationResult, error)
}
