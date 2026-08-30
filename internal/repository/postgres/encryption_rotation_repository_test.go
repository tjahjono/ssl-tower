package postgres

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/database"
	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/secret"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testPool connects to a real Postgres instance and applies every migration
// — EncryptionRotationRepository's whole point is a real cross-table
// transaction, which a fake repository can't exercise meaningfully. Set
// TEST_DATABASE_URL to point at a throwaway database; skips if unset, so
// this doesn't fail `go test ./...` in an environment with no Postgres
// available (see CLAUDE.md's environment gotchas).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres-backed test")
	}
	ctx := context.Background()
	pool, err := database.Connect(ctx, dsn, 5, 10*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, discardLogger()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Every test in this file owns the whole certificates/root_cas tables —
	// truncate first so tests don't see each other's rows.
	if _, err := pool.Exec(ctx, `TRUNCATE certificates, root_cas, app_settings, certificate_requests CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func mustSealer(t *testing.T, key string) *secret.Sealer {
	t.Helper()
	s, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer(%q): %v", key, err)
	}
	return s
}

// TestRotateEncryptionKeyReencryptsCertificatesAndRootCAs is the round-trip
// this whole feature exists for: seed a certificate and a Root CA with
// private keys encrypted under one key, rotate to a different key, and
// confirm both decrypt correctly under the new key — and that the new key
// itself lands in app_settings, atomically with the re-encryption.
func TestRotateEncryptionKeyReencryptsCertificatesAndRootCAs(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	oldSealer := mustSealer(t, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") // 32 bytes, base64
	newSealer := mustSealer(t, "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=") // a different 32 bytes

	certRepo := NewCertificateRepository(pool)
	rootCARepo := NewRootCARepository(pool)
	rotationRepo := NewEncryptionRotationRepository(pool)

	certPlaintext := "-----BEGIN PRIVATE KEY-----\ncert-key-plaintext\n-----END PRIVATE KEY-----\n"
	sealedCertKey, err := oldSealer.Seal(certPlaintext)
	if err != nil {
		t.Fatalf("seal cert key: %v", err)
	}
	cert := &domain.Certificate{
		CommonName: "rotate.example.com", KeyAlgorithm: "rsa", Origin: domain.OriginGenerated,
		PrivateKeyPEM: sealedCertKey, PrivateKeyEncrypted: true,
		Status: domain.CertIssued,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	rootPlaintext := "-----BEGIN PRIVATE KEY-----\nroot-key-plaintext\n-----END PRIVATE KEY-----\n"
	sealedRootKey, err := oldSealer.Seal(rootPlaintext)
	if err != nil {
		t.Fatalf("seal root ca key: %v", err)
	}
	ca := &domain.RootCA{
		Name: "Rotation Test CA", CertificatePEM: "cert-pem", PrivateKeyPEM: sealedRootKey, PrivateKeyEncrypted: true,
	}
	if err := rootCARepo.Create(ctx, ca); err != nil {
		t.Fatalf("create root ca: %v", err)
	}

	// A certificate/root CA with no key on file (PrivateKeyPEM == "") must
	// be left alone — reencryptTable's WHERE clause excludes empty strings
	// specifically so there's nothing to decrypt that was never encrypted.
	bareCert := &domain.Certificate{CommonName: "no-key.example.com", KeyAlgorithm: "rsa", Origin: domain.OriginGenerated, Status: domain.CertPending}
	if err := certRepo.Create(ctx, bareCert); err != nil {
		t.Fatalf("create bare certificate: %v", err)
	}

	var progressCalls [][2]int
	result, err := rotationRepo.RotateEncryptionKey(ctx, oldSealer, newSealer, "the-new-key-value", func(done, total int) {
		progressCalls = append(progressCalls, [2]int{done, total})
	})
	if err != nil {
		t.Fatalf("RotateEncryptionKey: %v", err)
	}
	if result.CertificatesReencrypted != 1 {
		t.Fatalf("CertificatesReencrypted = %d, want 1 (the bare certificate must be skipped)", result.CertificatesReencrypted)
	}
	if result.RootCAsReencrypted != 1 {
		t.Fatalf("RootCAsReencrypted = %d, want 1", result.RootCAsReencrypted)
	}

	// Two real key-bearing rows (the bare certificate has none): the very
	// first call must report the total up front (0, 2), and the last call
	// must report completion (2, 2) — with every done value in between
	// non-decreasing, since progress only ever moves forward within one
	// rotation.
	if len(progressCalls) < 3 {
		t.Fatalf("expected at least 3 progress calls (initial total + one per row), got %d: %v", len(progressCalls), progressCalls)
	}
	if progressCalls[0] != [2]int{0, 2} {
		t.Fatalf("first progress call = %v, want [0 2]", progressCalls[0])
	}
	last := progressCalls[len(progressCalls)-1]
	if last != [2]int{2, 2} {
		t.Fatalf("last progress call = %v, want [2 2]", last)
	}
	for i := 1; i < len(progressCalls); i++ {
		if progressCalls[i][0] < progressCalls[i-1][0] {
			t.Fatalf("progress went backwards: %v then %v", progressCalls[i-1], progressCalls[i])
		}
	}

	gotCert, err := certRepo.GetByID(ctx, cert.ID)
	if err != nil {
		t.Fatalf("GetByID certificate: %v", err)
	}
	plaintext, err := newSealer.Open(gotCert.PrivateKeyPEM, gotCert.PrivateKeyEncrypted)
	if err != nil {
		t.Fatalf("open re-encrypted certificate key with the new sealer: %v", err)
	}
	if plaintext != certPlaintext {
		t.Fatalf("certificate key plaintext = %q, want %q", plaintext, certPlaintext)
	}
	if _, err := oldSealer.Open(gotCert.PrivateKeyPEM, gotCert.PrivateKeyEncrypted); err == nil {
		t.Fatal("expected the old sealer to fail against the re-encrypted certificate key")
	}

	gotCA, err := rootCARepo.GetByID(ctx, ca.ID)
	if err != nil {
		t.Fatalf("GetByID root ca: %v", err)
	}
	rootPlain, err := newSealer.Open(gotCA.PrivateKeyPEM, gotCA.PrivateKeyEncrypted)
	if err != nil {
		t.Fatalf("open re-encrypted root ca key with the new sealer: %v", err)
	}
	if rootPlain != rootPlaintext {
		t.Fatalf("root ca key plaintext = %q, want %q", rootPlain, rootPlaintext)
	}

	gotBare, err := certRepo.GetByID(ctx, bareCert.ID)
	if err != nil {
		t.Fatalf("GetByID bare certificate: %v", err)
	}
	if gotBare.PrivateKeyPEM != "" || gotBare.PrivateKeyEncrypted {
		t.Fatalf("bare certificate's key fields changed: pem=%q encrypted=%v, want untouched", gotBare.PrivateKeyPEM, gotBare.PrivateKeyEncrypted)
	}

	settingsRepo := NewSettingsRepository(pool)
	value, found, err := settingsRepo.Get(ctx, domain.SettingEncryptionKey)
	if err != nil {
		t.Fatalf("settings Get: %v", err)
	}
	if !found || value != "the-new-key-value" {
		t.Fatalf("app_settings encryption key = (found=%v, value=%q), want (true, \"the-new-key-value\")", found, value)
	}
}

// TestRotateEncryptionKeyRollsBackOnDecryptFailure confirms the atomicity
// guarantee: if any row can't be decrypted under oldSealer (simulated here
// by seeding a certificate's "encrypted" key with plaintext that isn't
// actually valid ciphertext for oldSealer), nothing commits — not the
// already-processed rows, and not the new key in app_settings.
func TestRotateEncryptionKeyRollsBackOnDecryptFailure(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	oldSealer := mustSealer(t, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	newSealer := mustSealer(t, "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=")

	certRepo := NewCertificateRepository(pool)
	rotationRepo := NewEncryptionRotationRepository(pool)

	goodPlaintext := "good-key-plaintext"
	sealedGood, err := oldSealer.Seal(goodPlaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	goodCert := &domain.Certificate{CommonName: "good.example.com", KeyAlgorithm: "rsa", Origin: domain.OriginGenerated, PrivateKeyPEM: sealedGood, PrivateKeyEncrypted: true, Status: domain.CertIssued}
	if err := certRepo.Create(ctx, goodCert); err != nil {
		t.Fatalf("create good certificate: %v", err)
	}

	// Marked encrypted but holding a value oldSealer never produced —
	// decrypting this must fail and abort the whole transaction.
	badCert := &domain.Certificate{CommonName: "bad.example.com", KeyAlgorithm: "rsa", Origin: domain.OriginGenerated, PrivateKeyPEM: "not-valid-ciphertext", PrivateKeyEncrypted: true, Status: domain.CertIssued}
	if err := certRepo.Create(ctx, badCert); err != nil {
		t.Fatalf("create bad certificate: %v", err)
	}

	if _, err := rotationRepo.RotateEncryptionKey(ctx, oldSealer, newSealer, "should-never-be-persisted", nil); err == nil {
		t.Fatal("expected RotateEncryptionKey to fail when a row can't be decrypted under oldSealer")
	}

	// The good certificate must be exactly as it was — still under oldSealer.
	gotGood, err := certRepo.GetByID(ctx, goodCert.ID)
	if err != nil {
		t.Fatalf("GetByID good certificate: %v", err)
	}
	if plaintext, err := oldSealer.Open(gotGood.PrivateKeyPEM, gotGood.PrivateKeyEncrypted); err != nil || plaintext != goodPlaintext {
		t.Fatalf("good certificate's key changed despite the rollback: plaintext=%q err=%v", plaintext, err)
	}

	settingsRepo := NewSettingsRepository(pool)
	_, found, err := settingsRepo.Get(ctx, domain.SettingEncryptionKey)
	if err != nil {
		t.Fatalf("settings Get: %v", err)
	}
	if found {
		t.Fatal("app_settings encryption key must not be persisted when the rotation transaction rolled back")
	}
}
