package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/secret"
)

// EncryptionRotationRepository performs the one operation dangerous enough
// to deserve its own narrowly-scoped repository rather than living as a
// method on CertificateRepository or SettingsRepository: re-encrypting
// every stored private key — across both the certificates and root_cas
// tables — from one AES key to another, atomically, in the same
// transaction as persisting the new key itself. See
// CertificateService.RotateEncryptionKey, which is the only caller.
type EncryptionRotationRepository struct {
	pool *pgxpool.Pool
}

// NewEncryptionRotationRepository wires the repository to a pool.
func NewEncryptionRotationRepository(pool *pgxpool.Pool) *EncryptionRotationRepository {
	return &EncryptionRotationRepository{pool: pool}
}

var _ domain.EncryptionRotationRepository = (*EncryptionRotationRepository)(nil)

// keyRow is one private-key-bearing row queued for re-encryption, tagged
// with which table it came from so the update loop can write it back to the
// right place after both tables have been read.
type keyRow struct {
	table     string
	id        uuid.UUID
	pem       string
	encrypted bool
}

// RotateEncryptionKey re-encrypts every certificates.private_key_pem and
// root_cas.private_key_pem row that actually holds a key (an empty string
// means "never held one" — see Certificate.HasPrivateKey/RootCA.HasPrivateKey)
// from oldSealer to newSealer, then writes newKeyValue into app_settings —
// all inside one transaction. Any single row failing to decrypt under
// oldSealer (a real, if unlikely, sign that oldSealer doesn't actually match
// what's stored) aborts and rolls back the entire operation: nothing is
// left partially re-encrypted, and the key in app_settings is never updated
// unless every row succeeded.
//
// Both tables are read (and FOR UPDATE locked) up front so the combined
// total is known before any row is rewritten — that's what lets progress
// report a meaningful "N of M" from its very first call rather than
// guessing at a total that grows as it goes.
func (r *EncryptionRotationRepository) RotateEncryptionKey(ctx context.Context, oldSealer, newSealer *secret.Sealer, newKeyValue string, progress func(done, total int)) (domain.RotationResult, error) {
	if progress == nil {
		progress = func(int, int) {}
	}
	var result domain.RotationResult

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("encryption rotation: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	certRows, err := lockKeyRows(ctx, tx, "certificates")
	if err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: certificates: %w", err)
	}
	rootRows, err := lockKeyRows(ctx, tx, "root_cas")
	if err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: root cas: %w", err)
	}

	total := len(certRows) + len(rootRows)
	progress(0, total)

	done := 0
	if err := reencryptRows(ctx, tx, certRows, oldSealer, newSealer, func() {
		done++
		progress(done, total)
	}); err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: certificates: %w", err)
	}
	result.CertificatesReencrypted = len(certRows)

	if err := reencryptRows(ctx, tx, rootRows, oldSealer, newSealer, func() {
		done++
		progress(done, total)
	}); err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: root cas: %w", err)
	}
	result.RootCAsReencrypted = len(rootRows)

	const settingsQ = `INSERT INTO app_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2, 'encryption key rotation', now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`
	if _, err := tx.Exec(ctx, settingsQ, domain.SettingEncryptionKey, newKeyValue); err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: persist new key: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: commit: %w", err)
	}
	return result, nil
}

// lockKeyRows reads and FOR-UPDATE-locks one table's key-bearing rows
// without modifying them yet — table is always one of the two literal names
// above, never user input, so building the query with fmt.Sprintf here
// carries no injection risk.
func lockKeyRows(ctx context.Context, tx pgx.Tx, table string) ([]keyRow, error) {
	rows, err := tx.Query(ctx, fmt.Sprintf(
		`SELECT id, private_key_pem, private_key_encrypted FROM %s WHERE private_key_pem <> '' FOR UPDATE`, table))
	if err != nil {
		return nil, fmt.Errorf("select: %w", err)
	}
	defer rows.Close()
	var out []keyRow
	for rows.Next() {
		row := keyRow{table: table}
		if err := rows.Scan(&row.id, &row.pem, &row.encrypted); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// reencryptRows decrypts each row under oldSealer and rewrites it under
// newSealer, calling onRow after each successful write — the hook progress
// reporting rides on.
func reencryptRows(ctx context.Context, tx pgx.Tx, rows []keyRow, oldSealer, newSealer *secret.Sealer, onRow func()) error {
	for _, row := range rows {
		plaintext, err := oldSealer.Open(row.pem, row.encrypted)
		if err != nil {
			return fmt.Errorf("%s: decrypt with current key: %w", row.id, err)
		}
		sealed, err := newSealer.Seal(plaintext)
		if err != nil {
			return fmt.Errorf("%s: encrypt with new key: %w", row.id, err)
		}
		updateQ := fmt.Sprintf(`UPDATE %s SET private_key_pem = $1, private_key_encrypted = $2, updated_at = now() WHERE id = $3`, row.table)
		if _, err := tx.Exec(ctx, updateQ, sealed, newSealer.Enabled(), row.id); err != nil {
			return fmt.Errorf("%s: write: %w", row.id, err)
		}
		onRow()
	}
	return nil
}
