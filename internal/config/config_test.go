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

func TestApplySecretFilesMissingFileErrors(t *testing.T) {
	clearEnv(t, "APP_ENCRYPTION_KEY", "APP_ENCRYPTION_KEY_FILE")
	os.Setenv("APP_ENCRYPTION_KEY_FILE", "/nonexistent/path/for/test")

	if err := applySecretFiles([]string{"APP_ENCRYPTION_KEY"}); err == nil {
		t.Fatal("applySecretFiles: expected an error for a missing secret file, got nil")
	}
}
