package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// UserRepository persists accounts, sessions, recovery codes, and the login
// attempt log.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository wires the repository to a pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

var _ domain.UserRepository = (*UserRepository)(nil)

const userColumns = `id, email, password_hash, role, auth_source, totp_secret, mfa_enabled,
	must_change_password, created_at, updated_at, last_login_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	if err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.AuthSource, &u.TOTPSecret, &u.MFAEnabled,
		&u.MustChangePassword, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser inserts a new account.
func (r *UserRepository) CreateUser(ctx context.Context, u *domain.User) error {
	const q = `INSERT INTO users (email, password_hash, role, auth_source, totp_secret, mfa_enabled, must_change_password)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q, u.Email, u.PasswordHash, u.Role, u.AuthSource, u.TOTPSecret, u.MFAEnabled, u.MustChangePassword).
		Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%s: %w", u.Email, domain.ErrConflict)
		}
		return fmt.Errorf("user repo: create: %w", err)
	}
	return nil
}

// UpdateUser persists changes to an existing account.
func (r *UserRepository) UpdateUser(ctx context.Context, u *domain.User) error {
	const q = `UPDATE users SET email = $1, password_hash = $2, role = $3, auth_source = $4, totp_secret = $5,
		mfa_enabled = $6, must_change_password = $7, last_login_at = $8, updated_at = now()
		WHERE id = $9
		RETURNING updated_at`
	err := r.pool.QueryRow(ctx, q, u.Email, u.PasswordHash, u.Role, u.AuthSource, u.TOTPSecret,
		u.MFAEnabled, u.MustChangePassword, u.LastLoginAt, u.ID).Scan(&u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user %s: %w", u.ID, domain.ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%s: %w", u.Email, domain.ErrConflict)
		}
		return fmt.Errorf("user repo: update: %w", err)
	}
	return nil
}

// DeleteUser removes an account (and, via ON DELETE CASCADE, its sessions
// and recovery codes).
func (r *UserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("user repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", id, domain.ErrNotFound)
	}
	return nil
}

// GetUserByID loads one account.
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user %s: %w", id, domain.ErrNotFound)
		}
		return nil, fmt.Errorf("user repo: get by id: %w", err)
	}
	return u, nil
}

// GetUserByEmail loads one account by its (case-insensitive) email.
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user %s: %w", email, domain.ErrNotFound)
		}
		return nil, fmt.Errorf("user repo: get by email: %w", err)
	}
	return u, nil
}

// ListUsers returns every account, most recently created first.
func (r *UserRepository) ListUsers(ctx context.Context) ([]*domain.User, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("user repo: list: %w", err)
	}
	defer rows.Close()

	var out []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("user repo: scan: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountAdmins reports how many admin accounts exist — used to refuse
// demoting or deleting the last one.
func (r *UserRepository) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = $1`, domain.RoleAdmin).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("user repo: count admins: %w", err)
	}
	return n, nil
}

// CountUsers reports how many accounts exist at all — used to decide
// whether first-boot bootstrap is needed.
func (r *UserRepository) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("user repo: count users: %w", err)
	}
	return n, nil
}

// ReplaceRecoveryCodes deletes any existing codes for the user and inserts a
// fresh set — used both at initial MFA enrollment and on a manual reset.
func (r *UserRepository) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("user repo: replace recovery codes: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("user repo: replace recovery codes: clear: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return fmt.Errorf("user repo: replace recovery codes: insert: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// UnusedRecoveryCodes returns every not-yet-consumed code for a user.
func (r *UserRepository) UnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, user_id, code_hash, used_at, created_at
		FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return nil, fmt.Errorf("user repo: unused recovery codes: %w", err)
	}
	defer rows.Close()

	var out []*domain.RecoveryCode
	for rows.Next() {
		var c domain.RecoveryCode
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.UsedAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("user repo: scan recovery code: %w", err)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// MarkRecoveryCodeUsed consumes a code so it can never be replayed.
func (r *UserRepository) MarkRecoveryCodeUsed(ctx context.Context, id uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `UPDATE recovery_codes SET used_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("user repo: mark recovery code used: %w", err)
	}
	return nil
}

// CreateSession persists a new signed-in session.
func (r *UserRepository) CreateSession(ctx context.Context, s *domain.Session) error {
	const q = `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)
		RETURNING created_at, last_seen_at`
	if err := r.pool.QueryRow(ctx, q, s.TokenHash, s.UserID, s.ExpiresAt).Scan(&s.CreatedAt, &s.LastSeenAt); err != nil {
		return fmt.Errorf("user repo: create session: %w", err)
	}
	return nil
}

// GetSession loads a session by its token hash.
func (r *UserRepository) GetSession(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var s domain.Session
	err := r.pool.QueryRow(ctx, `SELECT token_hash, user_id, created_at, last_seen_at, expires_at
		FROM sessions WHERE token_hash = $1`, tokenHash).
		Scan(&s.TokenHash, &s.UserID, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("session: %w", domain.ErrNotFound)
		}
		return nil, fmt.Errorf("user repo: get session: %w", err)
	}
	return &s, nil
}

// TouchSession slides the idle-timeout window forward on activity.
func (r *UserRepository) TouchSession(ctx context.Context, tokenHash string, lastSeen, expiresAt time.Time) error {
	if _, err := r.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $1, expires_at = $2 WHERE token_hash = $3`,
		lastSeen, expiresAt, tokenHash); err != nil {
		return fmt.Errorf("user repo: touch session: %w", err)
	}
	return nil
}

// DeleteSession logs out one session.
func (r *UserRepository) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("user repo: delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForUser logs out every session for an account — used on
// password change and when an account is deleted or demoted.
func (r *UserRepository) DeleteSessionsForUser(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("user repo: delete sessions for user: %w", err)
	}
	return nil
}

// RecordLoginAttempt appends one row to the login audit trail.
func (r *UserRepository) RecordLoginAttempt(ctx context.Context, a *domain.LoginAttempt) error {
	const q = `INSERT INTO login_attempts (email, ip, success, reason) VALUES ($1, $2, $3, $4)`
	if _, err := r.pool.Exec(ctx, q, a.Email, a.IP, a.Success, a.Reason); err != nil {
		return fmt.Errorf("user repo: record login attempt: %w", err)
	}
	return nil
}

// RecentFailedAttempts counts failed logins for an email since a point in
// time — the basis for a simple brute-force guard.
func (r *UserRepository) RecentFailedAttempts(ctx context.Context, email string, since time.Time) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM login_attempts
		WHERE lower(email) = lower($1) AND success = FALSE AND created_at >= $2`, email, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("user repo: recent failed attempts: %w", err)
	}
	return n, nil
}
