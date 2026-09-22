package config

import (
	"os"
	"path/filepath"
	"testing"
)

// clearEnv removes every key this test might have touched, so tests don't
// leak state into each other via the process environment.
func clearEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		orig, had := os.LookupEnv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, orig)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestApplySecretFilesReadsFileIntoKey(t *testing.T) {
	clearEnv(t, "APP_ENCRYPTION_KEY", "APP_ENCRYPTION_KEY_FILE")

	dir := t.TempDir()
	path := filepath.Join(dir, "encryption_key")
	if err := os.WriteFile(path, []byte("  secret-from-file\n"), 0o600); err != nil {
		t.Fatalf("writing secret file: %v", err)
	}
	os.Setenv("APP_ENCRYPTION_KEY_FILE", path)

	if err := applySecretFiles([]string{"APP_ENCRYPTION_KEY"}); err != nil {
		t.Fatalf("applySecretFiles: %v", err)
	}
	if got := os.Getenv("APP_ENCRYPTION_KEY"); got != "secret-from-file" {
		t.Fatalf("APP_ENCRYPTION_KEY = %q, want trimmed file contents", got)
	}
}

func TestApplySecretFilesRealEnvVarWins(t *testing.T) {
	clearEnv(t, "APP_ENCRYPTION_KEY", "APP_ENCRYPTION_KEY_FILE")

	dir := t.TempDir()
	path := filepath.Join(dir, "encryption_key")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("writing secret file: %v", err)
	}
	os.Setenv("APP_ENCRYPTION_KEY_FILE", path)
	os.Setenv("APP_ENCRYPTION_KEY", "from-real-env")

	if err := applySecretFiles([]string{"APP_ENCRYPTION_KEY"}); err != nil {
		t.Fatalf("applySecretFiles: %v", err)
	}
	if got := os.Getenv("APP_ENCRYPTION_KEY"); got != "from-real-env" {
		t.Fatalf("APP_ENCRYPTION_KEY = %q, want the pre-existing real env var to win", got)
	}
}

func TestApplySecretFilesNoFileVarIsNoop(t *testing.T) {
	clearEnv(t, "APP_ENCRYPTION_KEY", "APP_ENCRYPTION_KEY_FILE")

	if err := applySecretFiles([]string{"APP_ENCRYPTION_KEY"}); err != nil {
		t.Fatalf("applySecretFiles: %v", err)
	}
	if got := os.Getenv("APP_ENCRYPTION_KEY"); got != "" {
		t.Fatalf("APP_ENCRYPTION_KEY = %q, want unset", got)
	}
}

func TestOptionalDurationEmptyIsOffNotError(t *testing.T) {
	clearEnv(t, "RENEWAL_SWEEP_INTERVAL")

	d, err := optionalDuration("RENEWAL_SWEEP_INTERVAL")
	if err != nil {
		t.Fatalf("optionalDuration: unexpected error for an unset key: %v", err)
	}
	if d != 0 {
		t.Fatalf("optionalDuration = %v, want 0 (disabled) for an unset key", d)
	}
}

func TestOptionalDurationParsesWhenSet(t *testing.T) {
	clearEnv(t, "RENEWAL_SWEEP_INTERVAL")
	os.Setenv("RENEWAL_SWEEP_INTERVAL", "12h")

	d, err := optionalDuration("RENEWAL_SWEEP_INTERVAL")
	if err != nil {
		t.Fatalf("optionalDuration: %v", err)
	}
	if d.String() != "12h0m0s" {
		t.Fatalf("optionalDuration = %v, want 12h0m0s", d)
	}
}

func TestOptionalDurationRejectsGarbage(t *testing.T) {
	clearEnv(t, "RENEWAL_SWEEP_INTERVAL")
	os.Setenv("RENEWAL_SWEEP_INTERVAL", "not-a-duration")

	if _, err := optionalDuration("RENEWAL_SWEEP_INTERVAL"); err == nil {
		t.Fatal("optionalDuration: expected an error for an unparseable non-empty value, since that's a typo, not \"off\"")
	}
}

func TestApplySecretFilesMissingFileErrors(t *testing.T) {
	clearEnv(t, "APP_ENCRYPTION_KEY", "APP_ENCRYPTION_KEY_FILE")
	os.Setenv("APP_ENCRYPTION_KEY_FILE", "/nonexistent/path/for/test")

	if err := applySecretFiles([]string{"APP_ENCRYPTION_KEY"}); err == nil {
		t.Fatal("applySecretFiles: expected an error for a missing secret file, got nil")
	}
}

func TestOptionalListSepSplitsOnGivenDelimiterNotComma(t *testing.T) {
	clearEnv(t, "LDAP_ROLE_MAP_EDITOR")
	// A real LDAP group DN contains commas as part of its own syntax — this
	// is exactly the bug caught during live verification against a real
	// slapd instance: using the comma-splitting optionalList for a list of
	// DNs silently shredded each DN into its individual RDN components.
	os.Setenv("LDAP_ROLE_MAP_EDITOR", "cn=a,ou=groups,dc=example,dc=com;cn=b,ou=groups,dc=example,dc=com")

	got := optionalListSep("LDAP_ROLE_MAP_EDITOR", ";")
	want := []string{"cn=a,ou=groups,dc=example,dc=com", "cn=b,ou=groups,dc=example,dc=com"}
	if len(got) != len(want) {
		t.Fatalf("optionalListSep = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("optionalListSep[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOptionalListSepEmptyIsNil(t *testing.T) {
	clearEnv(t, "LDAP_ROLE_MAP_EDITOR")
	if got := optionalListSep("LDAP_ROLE_MAP_EDITOR", ";"); got != nil {
		t.Fatalf("optionalListSep = %v, want nil for an unset key", got)
	}
}

// ldapRequiredKeys are the LDAP_* keys Load requires once LDAP_URL is set —
// used by the tests below to build a minimally valid LDAP config, then
// remove one key at a time to prove Load rejects it.
var ldapRequiredKeys = []string{
	"LDAP_URL", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_BASE_DN",
	"LDAP_USER_FILTER", "LDAP_GROUP_FILTER", "LDAP_ROLE_MAP_EDITOR",
}

// setBaseRequiredEnv sets every non-LDAP setting Load requires to a minimal
// valid value, so an LDAP-focused test only has to vary LDAP_* keys.
func setBaseRequiredEnv(t *testing.T) {
	t.Helper()
	values := map[string]string{
		"APP_ENV": "development", "HTTP_ADDR": ":8080",
		"DATABASE_URL": "postgres://u:p@localhost:5432/db", "DB_MAX_CONNS": "10", "DB_CONNECT_TIMEOUT": "10s",
		"ALERT_SWEEP_INTERVAL": "12h", "EXPIRY_WARNING_DAYS": "30", "EXPIRY_CRITICAL_DAYS": "7",
		"EXPIRY_FINAL_DAYS": "1", "EXPIRY_WARNING_PERCENT": "33", "EXPIRY_CRITICAL_PERCENT": "10",
		"SMTP_PORT": "587", "SESSION_IDLE_TIMEOUT": "12h", "SESSION_ABSOLUTE_TIMEOUT": "720h",
		"COOKIE_SECURE": "false", "TICKET_SLA_DAYS": "3",
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	clearEnv(t, keys...)
	for k, v := range values {
		os.Setenv(k, v)
	}
}

func setValidLDAPEnv(t *testing.T) {
	t.Helper()
	clearEnv(t, ldapRequiredKeys...)
	os.Setenv("LDAP_URL", "ldap://ldap.example.com:389")
	os.Setenv("LDAP_BIND_DN", "cn=svc,dc=example,dc=com")
	os.Setenv("LDAP_BIND_PASSWORD", "svcpass")
	os.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	os.Setenv("LDAP_USER_FILTER", "(mail=%s)")
	os.Setenv("LDAP_GROUP_FILTER", "(&(objectClass=groupOfNames)(member=%s))")
	os.Setenv("LDAP_ROLE_MAP_EDITOR", "cn=editors,ou=groups,dc=example,dc=com")
}

func TestLoadAcceptsValidLDAPConfig(t *testing.T) {
	setBaseRequiredEnv(t)
	setValidLDAPEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error with a fully valid LDAP config: %v", err)
	}
	if len(cfg.LDAPRoleMapEditor) != 1 || cfg.LDAPRoleMapEditor[0] != "cn=editors,ou=groups,dc=example,dc=com" {
		t.Fatalf("LDAPRoleMapEditor = %v, want a single parsed DN", cfg.LDAPRoleMapEditor)
	}
}

// Load no longer rejects an incomplete LDAP config (missing required field,
// a filter without its %s placeholder, or no role mapping configured) —
// that cross-field validation moved to service.SettingsService.Update in
// v1.6, the same move v1.5 made for the expiry-day thresholds (see
// TestUpdateRejectsCriticalDaysAboveWarningDays and friends in
// settings_service_test.go). These fields are only a first-boot seed now;
// a bad seed value shouldn't block boot when the portal governs the live
// value from the second boot onward. See CLAUDE.md's v1.6 locked decision.

func TestLoadWithoutLDAPURLIgnoresOtherLDAPSettings(t *testing.T) {
	setBaseRequiredEnv(t)
	clearEnv(t, ldapRequiredKeys...)
	// LDAP_URL left empty — the "empty = off" toggle — even though nothing
	// else LDAP-related is set either.
	if _, err := Load(); err != nil {
		t.Fatalf("Load: expected no error with LDAP_URL unset, got %v", err)
	}
}

var adcsKeys = []string{"ADCS_ENDPOINT", "ADCS_USERNAME", "ADCS_PASSWORD", "ADCS_TEMPLATE"}

func TestLoadWithoutADCSEndpointIgnoresOtherADCSSettings(t *testing.T) {
	setBaseRequiredEnv(t)
	clearEnv(t, adcsKeys...)
	if _, err := Load(); err != nil {
		t.Fatalf("Load: expected no error with ADCS_ENDPOINT unset, got %v", err)
	}
}

// Load no longer rejects an incomplete ADCS config (ADCS_ENDPOINT set but
// username/password/template missing) — that cross-field validation moved
// to service.SettingsService.Update in v1.16, the same move v1.8 made for
// LDAP (see TestLoadWithoutLDAPURLIgnoresOtherLDAPSettings's comment just
// above). These fields are only a first-boot seed now; a bad seed value
// shouldn't block boot when the portal governs the live value from the
// second boot onward. See CLAUDE.md's v1.16 locked decision.

func TestLoadAcceptsValidADCSConfig(t *testing.T) {
	setBaseRequiredEnv(t)
	clearEnv(t, adcsKeys...)
	os.Setenv("ADCS_ENDPOINT", "https://adcs.example.com/ADPolicyProvider_CEP_UsernamePassword/service.svc/CES")
	os.Setenv("ADCS_USERNAME", "svc-adcs")
	os.Setenv("ADCS_PASSWORD", "svcpass")
	os.Setenv("ADCS_TEMPLATE", "WebServer")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error with a fully valid ADCS config: %v", err)
	}
	if cfg.ADCSTemplate != "WebServer" {
		t.Fatalf("ADCSTemplate = %q, want %q", cfg.ADCSTemplate, "WebServer")
	}
}
