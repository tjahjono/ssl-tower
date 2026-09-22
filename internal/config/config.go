// Package config loads runtime configuration. Load reads a .env file from
// the current working directory itself (no shell sourcing or dotenv
// tooling required) and layers it beneath whatever is already in the
// process environment — a real environment variable (from the shell,
// Docker, or a scheduler) always wins over .env, and .env fills in the
// rest. There are no other built-in defaults: every setting that isn't
// optional by design must resolve to a real value from one of those two
// sources, or Load fails fast with a list of what's missing.
// .env.example is the single source of truth for what a value should be —
// copy it to .env and adjust, rather than relying on this package to fill
// in gaps silently.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds every knob the application needs at boot.
type Config struct {
	AppEnv   string
	HTTPAddr string

	DatabaseURL     string
	DBMaxConns      int32
	DBConnectTimout time.Duration

	// AlertSweepInterval is how often the background sweeper re-evaluates
	// every issued certificate's expiry against the alert thresholds below —
	// catching a certificate that quietly crosses a threshold with no
	// create/import/attach action of its own to trigger an immediate check.
	AlertSweepInterval time.Duration
	// ExpiryWarningDays/ExpiryCriticalDays/ExpiryFinalDays are, as of v1.5,
	// only a first-boot SEED for service.SettingsService.Bootstrap — once
	// app_settings has a row for these keys (any boot after the very first
	// against a given database), the portal is authoritative and these env
	// values are ignored entirely. Optional by design now: an empty value
	// seeds 0, which SettingsService.Bootstrap only ever writes if nothing
	// was ever configured through /settings either — an operator who wants
	// specific starting values still sets these in .env before the first
	// boot, exactly as before, but is no longer required to.
	ExpiryWarningDays  int
	ExpiryCriticalDays int
	ExpiryFinalDays    int
	// ExpiryWarningPercent and ExpiryCriticalPercent are the percent-of-
	// total-lifetime-remaining counterparts to ExpiryWarningDays/
	// ExpiryCriticalDays — whichever of the two (absolute days, or percent
	// of the certificate's own validity window) trips a tier first is what
	// promotes it. They only ever apply to externally-issued certificates:
	// those are the ones actually bound by the CA/Browser Forum's shrinking
	// public max-validity schedule (200 days today, 100 from 2027, 47 from
	// 2029), so a shorter total lifetime should mean earlier relative
	// warning. An internal certificate's validity period is a value this
	// app's own operator chose, often years, so a percentage of it doesn't
	// mean the same thing and would otherwise flag a long-lived internal
	// certificate "expiring" for a large fraction of its life — see
	// domain.Certificate.HealthStatus's doc comment for the full reasoning
	// and a worked example. Required, not defaulted, same as the day-based
	// thresholds above.
	ExpiryWarningPercent  int
	ExpiryCriticalPercent int

	// EncryptionKey (base64 std encoding, 32 bytes) is, as of v1.5, only the
	// first-boot seed for app_settings' app_encryption_key row — see
	// service.SettingsService.Bootstrap and CertificateService.
	// RotateEncryptionKey, which is the only supported way to change it once
	// a database has ever booted. Empty still means "store private keys as
	// plaintext" on that first boot, same as always. CLAUDE.md documents the
	// security tradeoff of this value now living in the same database it
	// protects — read that before assuming this is a purely cosmetic change.
	EncryptionKey string

	// SMTP settings for expiry/health alert emails. As of v1.5, only a
	// first-boot seed for service.SettingsService — see the
	// ExpiryWarningDays doc comment above for the seed-once-then-portal-
	// authoritative model this and every other field in this block follows.
	// Empty SMTPHost still means "email channel off" once seeded.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	AlertFrom    string
	AlertTo      []string

	// TeamsWebhookURL is a Microsoft Teams incoming webhook URL — as of
	// v1.5, only a first-boot seed for service.SettingsService (see
	// ExpiryWarningDays above). Empty still means "Teams channel off" once
	// seeded.
	TeamsWebhookURL string

	// Email transport settings (v1.18: portal-editable from /settings, same
	// seed-once-then-portal-authoritative model as everything else in this
	// block). Microsoft is retiring SMTP AUTH Basic Authentication (a plain
	// username/password) for Exchange Online / Microsoft 365 — see
	// CLAUDE.md's v1.18 locked decision — so alert/notification email can
	// now be sent either via the SMTP settings above or via the Microsoft
	// Graph API's sendMail endpoint (OAuth2 client-credentials, app-only
	// auth) configured below. EmailTransport selects which one is active;
	// "smtp" is the default seed value when empty, preserving pre-v1.18
	// behavior for every existing deployment. See internal/pkg/graphmail.
	EmailTransport string
	// GraphTenantID is the "empty = off" toggle for the Graph transport —
	// empty means EmailTransport can still be set to "graph" as a live
	// portal edit, but SettingsService.Update rejects it until a tenant ID
	// (and the other three Graph fields below) are supplied. This is the
	// Entra ID (Azure AD) directory (tenant) ID or verified domain name the
	// app registration below lives in.
	GraphTenantID string
	// GraphClientID is the Entra ID application (client) ID of an app
	// registration granted the Mail.Send *application* permission with
	// admin consent — app-only auth, not delegated, since this app sends as
	// a shared mailbox with no signed-in user.
	GraphClientID string
	// GraphClientSecret is that app registration's client secret value.
	GraphClientSecret string
	// GraphSenderAddress is the mailbox Graph's sendMail call sends as —
	// e.g. "alerts@example.com" — the app registration's Mail.Send
	// permission must be able to act as this address (optionally scoped via
	// an application access policy in Exchange Online).
	GraphSenderAddress string

	// SessionSecret signs the short-lived "password verified, awaiting MFA"
	// token. Optional by design: an empty value only survives boot with an
	// ephemeral, restart-sensitive secret (see cmd/server/main.go).
	SessionSecret string
	// SessionIdleTimeout is how long a session survives without activity.
	SessionIdleTimeout time.Duration
	// SessionAbsoluteTimeout is the hard cap on a session's lifetime.
	SessionAbsoluteTimeout time.Duration
	// CookieSecure marks the session/CSRF cookies Secure (HTTPS-only). Must
	// be set explicitly — false for local HTTP development, true once behind TLS.
	CookieSecure bool

	// AdminEmail and AdminInitialPassword bootstrap the very first account
	// when the users table is empty. Optional by design: ignored once any
	// account exists, and bootstrap is simply skipped (with a logged
	// warning) when either is left empty.
	AdminEmail           string
	AdminInitialPassword string

	// TicketSLADays is the age (in days, counted from approval, not
	// submission) after which an open certificate request ticket is flagged
	// overdue on the ticket queue. As of v1.5, only a first-boot seed for
	// service.SettingsService (see ExpiryWarningDays above) — an empty value
	// seeds 0, and CertificateRequestService.SLADays falls back to 3 if the
	// live setting is ever 0, so a never-configured deployment still gets a
	// sane default rather than "every ticket is instantly overdue."
	TicketSLADays int

	// RenewalSweepInterval is how often the background sweeper drafts
	// pending renewal tickets for internal certificates approaching expiry
	// (see service.CertificateRequestService.AutoDraftRenewals). Optional by
	// design, same "empty = off" convention as the SMTP/Teams settings above:
	// leave it unset to keep the app purely reactive (an editor/admin renews
	// only when they notice a certificate is close to expiring), or set it
	// (e.g. "12h") to have the app proactively draft renewal tickets on the
	// original requester's behalf.
	RenewalSweepInterval time.Duration

	// DigiCertAPIKey enables the DigiCert renewal integration (Phase 6) —
	// submitting an external renewal ticket to DigiCert's CertCentral API
	// instead of an admin/editor pasting a certificate a CA issued outside
	// the app. Optional by design: empty disables the whole integration,
	// same "empty = off" convention as SMTP_HOST/TEAMS_WEBHOOK_URL/
	// RENEWAL_SWEEP_INTERVAL above — the existing manual paste flow
	// (FulfillExternal) is always available regardless of this setting.
	DigiCertAPIKey string
	// DigiCertBaseURL is DigiCert's CertCentral API base URL. Required
	// whenever DigiCertAPIKey is set — deliberately not defaulted in Go
	// even though DigiCert's own base URL rarely changes, so a stale or
	// wrong value can never hide behind an assumed default; .env.example
	// ships the current documented value to copy as-is.
	DigiCertBaseURL string

	// ADCS settings (v1.16: portal-editable from /settings, the same v1.8
	// move LDAP already got — these fields are now only a first-boot SEED,
	// exactly like LDAPURL below; see SettingsService's doc comment).
	// ADCSEndpoint is the "empty = off" toggle: empty means the pending-
	// certificate detail page's "Sign with" dropdown simply doesn't offer
	// "Submit to ADCS". Once set (here, as a seed, or later from the
	// portal), ADCSUsername/ADCSPassword/ADCSTemplate become required —
	// enforced by SettingsService.Update on a live edit, not here on a
	// boot-time seed, same reasoning as LDAP's cross-field check below. This
	// is the full URL of ADCS's Certificate Enrollment Web Service (CES)
	// endpoint configured for username/password authentication — e.g.
	// "https://adcs.corp.example.com/ADPolicyProvider_CEP_UsernamePassword/service.svc/CES" —
	// not a bare hostname; ADCS's own admin console (or the
	// certutil -config command) is where that URL comes from. See
	// internal/pkg/adcs and CLAUDE.md's ADCS section for what is and isn't
	// verified against a real server.
	ADCSEndpoint string
	// ADCSUsername/ADCSPassword authenticate to the CES endpoint above via
	// a WS-Security UsernameToken — the account needs Enroll permission on
	// whichever certificate template ADCSTemplate names.
	ADCSUsername string
	ADCSPassword string
	// ADCSTemplate is the certificate template name (its short "common"
	// name, e.g. "WebServer", not its display name) ADCS should issue
	// against — sent as a WS-Trust AdditionalContext item, since a
	// from-scratch PKCS#10 request built by this app carries no Microsoft
	// template extension of its own.
	ADCSTemplate string

	// LDAP settings (v1.8: portal-editable from /settings — these fields are
	// now only a first-boot SEED, exactly like ExpiryWarningDays and the
	// other settings SettingsService.Bootstrap seeds; see that type's doc
	// comment). LDAPURL is the "empty = off" toggle: empty means every
	// account authenticates with a local password exactly as before this
	// feature existed. Once set (here, as a seed, or later from the
	// portal), LDAPBindDN/LDAPBindPassword/LDAPBaseDN/LDAPUserFilter/
	// LDAPGroupFilter become required and at least one role mapping must be
	// non-empty — enforced by SettingsService.Update on a live edit, not
	// here on a boot-time seed (a bad seed shouldn't block boot once the
	// portal is what actually governs the live value from the second boot
	// onward). See CLAUDE.md's LDAP locked decisions for the authentication
	// model this enables: admin accounts keep using a local password
	// regardless of this setting; every other role authenticates via LDAP
	// once it's set.
	LDAPURL string
	// LDAPBindDN and LDAPBindPassword are the service account LDAPClient
	// uses to search the directory — never an end user's own credentials.
	LDAPBindDN       string
	LDAPBindPassword string
	// LDAPBaseDN is the search base for both the user and group lookups.
	LDAPBaseDN string
	// LDAPUserFilter finds a user's entry by the email they submit at
	// login — exactly one "%s" placeholder, e.g. "(mail=%s)".
	LDAPUserFilter string
	// LDAPGroupFilter finds every group a user's entry belongs to —
	// exactly one "%s" placeholder standing in for the user's DN, e.g.
	// "(&(objectClass=groupOfNames)(member=%s))".
	LDAPGroupFilter string
	// LDAPRoleMapEditor, LDAPRoleMapViewer, and LDAPRoleMapRequester each
	// list the LDAP group DNs (semicolon-separated — a DN's own RDN
	// components are comma-separated, so comma can't double as the
	// list delimiter here the way it does for ALERT_EMAIL_TO) whose
	// members are JIT-provisioned with, and re-synced to, that role. All
	// optional — leaving all three empty means every LDAP login is denied
	// and logged (fail-closed), not silently provisioned at a default
	// role. There is deliberately no LDAPRoleMapAdmin: admin is always
	// locally-granted, never LDAP-derived.
	LDAPRoleMapEditor    []string
	LDAPRoleMapViewer    []string
	LDAPRoleMapRequester []string
}

// Load reads configuration from the environment, loading .env into the
// process first (see loadDotEnv). Every field below is either required —
// present and valid in .env or the real environment, or Load returns an
// error naming it — or explicitly optional by design (a feature toggle
// whose empty value is itself meaningful, documented on the Config field
// above). There is no third category: nothing here is silently filled in
// with a value that isn't in .env or the environment.
func Load() (*Config, error) {
	if err := applySecretFiles(secretFileKeys); err != nil {
		return nil, fmt.Errorf("config: reading secret files: %w", err)
	}
	if err := loadDotEnv(".env"); err != nil {
		return nil, fmt.Errorf("config: reading .env: %w", err)
	}

	var errs []error
	reqStr := func(key string) string {
		v, err := requireString(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}
	reqInt := func(key string) int {
		v, err := requireInt(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}
	reqDuration := func(key string) time.Duration {
		v, err := requireDuration(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}
	reqBool := func(key string) bool {
		v, err := requireBool(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}
	optDuration := func(key string) time.Duration {
		v, err := optionalDuration(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}
	optInt := func(key string) int {
		v, err := optionalInt(key)
		if err != nil {
			errs = append(errs, err)
		}
		return v
	}

	cfg := &Config{
		AppEnv:   reqStr("APP_ENV"),
		HTTPAddr: reqStr("HTTP_ADDR"),

		DatabaseURL:     reqStr("DATABASE_URL"),
		DBMaxConns:      int32(reqInt("DB_MAX_CONNS")),
		DBConnectTimout: reqDuration("DB_CONNECT_TIMEOUT"),

		AlertSweepInterval:    reqDuration("ALERT_SWEEP_INTERVAL"),
		ExpiryWarningDays:     optInt("EXPIRY_WARNING_DAYS"),
		ExpiryCriticalDays:    optInt("EXPIRY_CRITICAL_DAYS"),
		ExpiryFinalDays:       optInt("EXPIRY_FINAL_DAYS"),
		ExpiryWarningPercent:  reqInt("EXPIRY_WARNING_PERCENT"),
		ExpiryCriticalPercent: reqInt("EXPIRY_CRITICAL_PERCENT"),

		EncryptionKey: optionalString("APP_ENCRYPTION_KEY"),

		SMTPHost:     optionalString("SMTP_HOST"),
		SMTPPort:     optInt("SMTP_PORT"),
		SMTPUsername: optionalString("SMTP_USERNAME"),
		SMTPPassword: optionalString("SMTP_PASSWORD"),
		AlertFrom:    optionalString("ALERT_EMAIL_FROM"),
		AlertTo:      optionalList("ALERT_EMAIL_TO"),

		TeamsWebhookURL: optionalString("TEAMS_WEBHOOK_URL"),

		EmailTransport:     optionalString("EMAIL_TRANSPORT"),
		GraphTenantID:      optionalString("GRAPH_TENANT_ID"),
		GraphClientID:      optionalString("GRAPH_CLIENT_ID"),
		GraphClientSecret:  optionalString("GRAPH_CLIENT_SECRET"),
		GraphSenderAddress: optionalString("GRAPH_SENDER_ADDRESS"),

		SessionSecret:          optionalString("SESSION_SECRET"),
		SessionIdleTimeout:     reqDuration("SESSION_IDLE_TIMEOUT"),
		SessionAbsoluteTimeout: reqDuration("SESSION_ABSOLUTE_TIMEOUT"),
		CookieSecure:           reqBool("COOKIE_SECURE"),

		AdminEmail:           optionalString("ADMIN_EMAIL"),
		AdminInitialPassword: optionalString("ADMIN_INITIAL_PASSWORD"),

		TicketSLADays: optInt("TICKET_SLA_DAYS"),

		RenewalSweepInterval: optDuration("RENEWAL_SWEEP_INTERVAL"),

		DigiCertAPIKey:  optionalString("DIGICERT_API_KEY"),
		DigiCertBaseURL: optionalString("DIGICERT_BASE_URL"),

		ADCSEndpoint: optionalString("ADCS_ENDPOINT"),
		ADCSUsername: optionalString("ADCS_USERNAME"),
		ADCSPassword: optionalString("ADCS_PASSWORD"),
		ADCSTemplate: optionalString("ADCS_TEMPLATE"),

		LDAPURL:          optionalString("LDAP_URL"),
		LDAPBindDN:       optionalString("LDAP_BIND_DN"),
		LDAPBindPassword: optionalString("LDAP_BIND_PASSWORD"),
		LDAPBaseDN:       optionalString("LDAP_BASE_DN"),
		LDAPUserFilter:   optionalString("LDAP_USER_FILTER"),
		LDAPGroupFilter:  optionalString("LDAP_GROUP_FILTER"),

		LDAPRoleMapEditor:    optionalListSep("LDAP_ROLE_MAP_EDITOR", ";"),
		LDAPRoleMapViewer:    optionalListSep("LDAP_ROLE_MAP_VIEWER", ";"),
		LDAPRoleMapRequester: optionalListSep("LDAP_ROLE_MAP_REQUESTER", ";"),
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("config: missing or invalid settings — copy .env.example to .env and fill it in:\n%w", errors.Join(errs...))
	}

	if cfg.DigiCertAPIKey != "" && cfg.DigiCertBaseURL == "" {
		return nil, fmt.Errorf("config: DIGICERT_BASE_URL is required when DIGICERT_API_KEY is set")
	}

	// ADCS_ENDPOINT's own cross-field check (the other ADCS_* fields
	// required once it's set) moved to service.SettingsService.Update — see
	// the ADCSEndpoint field's doc comment above; same v1.16 move applied
	// to LDAP_URL's own cross-field check below in v1.8.

	// LDAP_URL's own cross-field check (the other LDAP_* fields required
	// once it's set, filter placeholder counts, at least one role mapping)
	// moved to service.SettingsService.Update, the same v1.8 move the
	// EXPIRY_*_DAYS check just below made in v1.5 — these are only a
	// first-boot seed now (see the Config field doc comments above), and a
	// bad seed value shouldn't block boot when the portal is what actually
	// governs the live LDAP configuration from the second boot onward.

	// EXPIRY_*_DAYS's own cross-field check (critical <= warning, final <=
	// critical) moved to service.SettingsService.Update — these are only a
	// first-boot seed now (see the Config field doc comments above), and a
	// bad seed value shouldn't block boot when the portal is what actually
	// governs the live thresholds from the second boot onward.
	if cfg.ExpiryCriticalPercent > cfg.ExpiryWarningPercent {
		return nil, fmt.Errorf("config: EXPIRY_CRITICAL_PERCENT must be <= EXPIRY_WARNING_PERCENT")
	}
	if cfg.ExpiryWarningPercent < 0 || cfg.ExpiryWarningPercent > 100 {
		return nil, fmt.Errorf("config: EXPIRY_WARNING_PERCENT must be between 0 and 100")
	}
	if cfg.ExpiryCriticalPercent < 0 || cfg.ExpiryCriticalPercent > 100 {
		return nil, fmt.Errorf("config: EXPIRY_CRITICAL_PERCENT must be between 0 and 100")
	}
	return cfg, nil
}

// secretFileKeys lists every config key that may be supplied via Docker
// secrets instead of a plain environment variable — the credential-bearing
// values in this app: the vault's own encryption key, the database
// connection string (it carries the DB password inline — there is no
// separate DB_PASSWORD field), the session-signing secret, the bootstrap
// admin password, the SMTP password, the Teams webhook URL (a bearer
// credential in URL form), the LDAP service account's bind password, the
// ADCS service account's password, and the Graph API app registration's
// client secret (v1.18).
// Everything else (ports, thresholds, hostnames, the admin email, LDAP's
// bind DN and filters) is plain configuration, not a secret, and stays a
// normal env var.
var secretFileKeys = []string{
	"DATABASE_URL",
	"APP_ENCRYPTION_KEY",
	"SESSION_SECRET",
	"ADMIN_INITIAL_PASSWORD",
	"SMTP_PASSWORD",
	"TEAMS_WEBHOOK_URL",
	"LDAP_BIND_PASSWORD",
	"ADCS_PASSWORD",
	"GRAPH_CLIENT_SECRET",
}

// applySecretFiles implements the standard Docker/Kubernetes secrets-as-files
// convention: for each key in keys, if <KEY>_FILE names a file (e.g.
// /run/secrets/app_encryption_key, the path Docker mounts a swarm secret
// at), its trimmed contents become the value of KEY — but only when KEY
// itself isn't already set. That ordering matters: it means a real
// environment variable set directly (by the shell, `docker compose`'s
// environment: block, systemd, whatever) always wins outright, exactly as
// loadDotEnv's own env-wins-over-.env rule works below; a *_FILE secret
// beats .env, since running this before loadDotEnv means loadDotEnv's own
// "skip if already set" check will leave whatever this function wrote
// alone. A container that sets neither the plain var nor *_FILE falls
// through to .env or a required-value error exactly as before — this is
// purely additive, no existing deployment's behavior changes.
func applySecretFiles(keys []string) error {
	for _, key := range keys {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		path := strings.TrimSpace(os.Getenv(key + "_FILE"))
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s_FILE=%s: %w", key, path, err)
		}
		if err := os.Setenv(key, strings.TrimSpace(string(data))); err != nil {
			return fmt.Errorf("setting %s from %s_FILE: %w", key, key, err)
		}
	}
	return nil
}

// loadDotEnv reads a .env file at path, if one exists, and copies each key
// it defines into the process environment via os.Setenv — but only for a
// key that isn't already set. That makes precedence explicit and simple: a
// real environment variable (set by the shell, `docker compose`'s
// environment: block, systemd, a scheduler, whatever actually launched the
// process) always wins; .env exists purely to make a bare `go run
// ./cmd/server` or `./bin/server` self-sufficient without any of that.
//
// A missing file is not an error — the app may be getting every setting
// from the real environment instead (that's exactly what happens inside
// the Docker image, which deliberately never contains a .env file; see
// .dockerignore). Path is resolved relative to the process's current
// working directory, same as every other reference to ".env" in this repo
// (the Makefile, docker-compose.yml, .gitignore).
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if n := len(value); n >= 2 {
			if (value[0] == '"' && value[n-1] == '"') || (value[0] == '\'' && value[n-1] == '\'') {
				value = value[1 : n-1]
			}
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("setting %s from .env: %w", key, err)
		}
	}
	return nil
}

// requireString reads a setting that must be present — no built-in fallback.
func requireString(key string) (string, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return "", fmt.Errorf("%s is not set", key)
	}
	return v, nil
}

// optionalString reads a setting whose empty value is itself meaningful
// (a feature toggle left off), so an absent value is not an error.
func optionalString(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func requireInt(key string) (int, error) {
	v, err := requireString(key)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid integer", key, v)
	}
	return n, nil
}

func requireBool(key string) (bool, error) {
	v, err := requireString(key)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s: %q is not a valid boolean (use true/false)", key, v)
	}
}

func requireDuration(key string) (time.Duration, error) {
	v, err := requireString(key)
	if err != nil {
		return 0, err
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration (e.g. \"15m\", \"12h\")", key, v)
	}
	return d, nil
}

// optionalDuration reads a duration setting whose empty value disables the
// feature it controls entirely, same convention as optionalString/
// optionalList. Returns 0 (and no error) when unset; an unparseable non-empty
// value is still a hard error, since that's a typo, not "off".
func optionalDuration(key string) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration (e.g. \"15m\", \"12h\")", key, v)
	}
	return d, nil
}

// optionalInt reads an integer setting whose empty value is itself
// meaningful — same convention as optionalString/optionalDuration. Returns
// 0 (and no error) when unset; an unparseable non-empty value is still a
// hard error, since that's a typo, not "off". Used for settings that
// became first-boot-only seeds for SettingsService in v1.5 (EXPIRY_*_DAYS,
// SMTP_PORT, TICKET_SLA_DAYS) — a genuinely required integer still uses
// requireInt.
func optionalInt(key string) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid integer", key, v)
	}
	return n, nil
}

// optionalList splits a comma-separated env var into trimmed, non-empty
// entries. Returns nil (not an empty slice) when unset, so callers can treat
// a nil recipient list as "email alerts disabled" — this is a feature
// toggle, not a required setting.
func optionalList(key string) []string {
	return optionalListSep(key, ",")
}

// optionalListSep is optionalList with a configurable delimiter — needed for
// LDAP_ROLE_MAP_* (see Config.LDAPRoleMapEditor), whose entries are DNs that
// already contain commas as part of their own syntax.
func optionalListSep(key, sep string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, sep) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
