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

// RotateEncryptionKey re-encrypts every certificates.private_key_pem and
// root_cas.private_key_pem row that actually holds a key (an empty string
// means "never held one" — see Certificate.HasPrivateKey/RootCA.HasPrivateKey)
// from oldSealer to newSealer, then writes newKeyValue into app_settings —
// all inside one transaction. Any single row failing to decrypt under
// oldSealer (a real, if unlikely, sign that oldSealer doesn't actually match
// what's stored) aborts and rolls back the entire operation: nothing is
// left partially re-encrypted, and the key in app_settings is never updated
// unless every row succeeded.
func (r *EncryptionRotationRepository) RotateEncryptionKey(ctx context.Context, oldSealer, newSealer *secret.Sealer, newKeyValue string) (domain.RotationResult, error) {
	var result domain.RotationResult

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("encryption rotation: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	result.CertificatesReencrypted, err = reencryptTable(ctx, tx, "certificates", oldSealer, newSealer)
	if err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: certificates: %w", err)
	}
	result.RootCAsReencrypted, err = reencryptTable(ctx, tx, "root_cas", oldSealer, newSealer)
	if err != nil {
		return domain.RotationResult{}, fmt.Errorf("encryption rotation: root cas: %w", err)
	}

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

// reencryptTable re-encrypts one table's private_key_pem column. table is
// always one of the two literal names above, never user input, so building
// the query with fmt.Sprintf here carries no injection risk.
func reencryptTable(ctx context.Context, tx pgx.Tx, table string, oldSealer, newSealer *secret.Sealer) (int, error) {
	// FOR UPDATE locks every matching row for the rest of this transaction,
	// so a concurrent write to a certificate's private key mid-rotation
	// can't race with this read-decrypt-reencrypt-write cycle.
	rows, err := tx.Query(ctx, fmt.Sprintf(
		`SELECT id, private_key_pem, private_key_encrypted FROM %s WHERE private_key_pem <> '' FOR UPDATE`, table))
	if err != nil {
		return 0, fmt.Errorf("select: %w", err)
	}
	type keyRow struct {
		id        uuid.UUID
		pem       string
		encrypted bool
	}
	var toUpdate []keyRow
	for rows.Next() {
		var row keyRow
		if err := rows.Scan(&row.id, &row.pem, &row.encrypted); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan: %w", err)
		}
		toUpdate = append(toUpdate, row)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()

	updateQ := fmt.Sprintf(`UPDATE %s SET private_key_pem = $1, private_key_encrypted = $2, updated_at = now() WHERE id = $3`, table)
	for _, row := range toUpdate {
		plaintext, err := oldSealer.Open(row.pem, row.encrypted)
		if err != nil {
			return 0, fmt.Errorf("%s: decrypt with current key: %w", row.id, err)
		}
		sealed, err := newSealer.Seal(plaintext)
		if err != nil {
			return 0, fmt.Errorf("%s: encrypt with new key: %w", row.id, err)
		}
		if _, err := tx.Exec(ctx, updateQ, sealed, newSealer.Enabled(), row.id); err != nil {
			return 0, fmt.Errorf("%s: write: %w", row.id, err)
		}
	}
	return len(toUpdate), nil
}
