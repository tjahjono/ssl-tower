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
