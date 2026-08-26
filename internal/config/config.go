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
	// ExpiryWarningDays marks a certificate as "expiring" this many days before notAfter.
	ExpiryWarningDays int
	// ExpiryCriticalDays marks a certificate as "critical" this many days before notAfter.
	ExpiryCriticalDays int
	// ExpiryFinalDays is the last-chance alert threshold before notAfter — a
	// notification tier distinct from "critical", for the day something is
	// truly about to break.
	ExpiryFinalDays int

	// EncryptionKey (base64 std encoding, 32 bytes) encrypts private keys at rest.
	// Optional by design: empty means private keys are stored as plaintext PEM.
	EncryptionKey string

	// SMTP settings for expiry/health alert emails. Optional by design:
	// empty SMTPHost disables the email channel entirely — Teams can still
	// fire on its own.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	AlertFrom    string
	AlertTo      []string

	// TeamsWebhookURL is a Microsoft Teams incoming webhook URL. Optional by
	// design: empty disables the Teams channel entirely — email can still
	// fire on its own.
	TeamsWebhookURL string

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
	// overdue on the ticket queue. Confirmed at 3 days for both internal and
	// external tickets — required, not defaulted, so an operator has to make
	// a deliberate choice rather than silently inherit a value they never saw.
	TicketSLADays int
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

	cfg := &Config{
		AppEnv:   reqStr("APP_ENV"),
		HTTPAddr: reqStr("HTTP_ADDR"),

		DatabaseURL:     reqStr("DATABASE_URL"),
		DBMaxConns:      int32(reqInt("DB_MAX_CONNS")),
		DBConnectTimout: reqDuration("DB_CONNECT_TIMEOUT"),

		AlertSweepInterval: reqDuration("ALERT_SWEEP_INTERVAL"),
		ExpiryWarningDays:  reqInt("EXPIRY_WARNING_DAYS"),
		ExpiryCriticalDays: reqInt("EXPIRY_CRITICAL_DAYS"),
		ExpiryFinalDays:    reqInt("EXPIRY_FINAL_DAYS"),

		EncryptionKey: optionalString("APP_ENCRYPTION_KEY"),

		SMTPHost:     optionalString("SMTP_HOST"),
		SMTPPort:     reqInt("SMTP_PORT"),
		SMTPUsername: optionalString("SMTP_USERNAME"),
		SMTPPassword: optionalString("SMTP_PASSWORD"),
		AlertFrom:    optionalString("ALERT_EMAIL_FROM"),
		AlertTo:      optionalList("ALERT_EMAIL_TO"),

		TeamsWebhookURL: optionalString("TEAMS_WEBHOOK_URL"),

		SessionSecret:          optionalString("SESSION_SECRET"),
		SessionIdleTimeout:     reqDuration("SESSION_IDLE_TIMEOUT"),
		SessionAbsoluteTimeout: reqDuration("SESSION_ABSOLUTE_TIMEOUT"),
		CookieSecure:           reqBool("COOKIE_SECURE"),

		AdminEmail:           optionalString("ADMIN_EMAIL"),
		AdminInitialPassword: optionalString("ADMIN_INITIAL_PASSWORD"),

		TicketSLADays: reqInt("TICKET_SLA_DAYS"),
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("config: missing or invalid settings — copy .env.example to .env and fill it in:\n%w", errors.Join(errs...))
	}

	if cfg.ExpiryCriticalDays > cfg.ExpiryWarningDays {
		return nil, fmt.Errorf("config: EXPIRY_CRITICAL_DAYS must be <= EXPIRY_WARNING_DAYS")
	}
	if cfg.ExpiryFinalDays > cfg.ExpiryCriticalDays {
		return nil, fmt.Errorf("config: EXPIRY_FINAL_DAYS must be <= EXPIRY_CRITICAL_DAYS")
	}
	return cfg, nil
}

// secretFileKeys lists every config key that may be supplied via Docker
// secrets instead of a plain environment variable — the credential-bearing
// values in this app: the vault's own encryption key, the database
// connection string (it carries the DB password inline — there is no
// separate DB_PASSWORD field), the session-signing secret, the bootstrap
// admin password, the SMTP password, and the Teams webhook URL (a bearer
// credential in URL form). Everything else (ports, thresholds, hostnames,
// the admin email) is plain configuration, not a secret, and stays a normal
// env var.
var secretFileKeys = []string{
	"DATABASE_URL",
	"APP_ENCRYPTION_KEY",
	"SESSION_SECRET",
	"ADMIN_INITIAL_PASSWORD",
	"SMTP_PASSWORD",
	"TEAMS_WEBHOOK_URL",
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

// optionalList splits a comma-separated env var into trimmed, non-empty
// entries. Returns nil (not an empty slice) when unset, so callers can treat
// a nil recipient list as "email alerts disabled" — this is a feature
// toggle, not a required setting.
func optionalList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
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
