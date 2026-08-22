package domain

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Role governs what an authenticated user may do. Deliberately three tiers,
// not two: "who can generate a CSR or edit a monitor" (editor) is a different
// power from "who can create logins and change roles" (admin) — collapsing
// them would force every write-capable user into full account control.
type Role string

// The three roles the app understands. Any other string is invalid.
const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// Valid reports whether r is one of the known roles.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleEditor, RoleViewer:
		return true
	default:
		return false
	}
}

// CanWrite reports whether this role may create, modify, or delete
// monitors and CSRs.
func (r Role) CanWrite() bool {
	return r == RoleAdmin || r == RoleEditor
}

// CanManageUsers reports whether this role may create, edit, or remove
// other accounts.
func (r Role) CanManageUsers() bool {
	return r == RoleAdmin
}

// Label renders the role for humans.
func (r Role) Label() string {
	switch r {
	case RoleAdmin:
		return "Admin"
	case RoleEditor:
		return "Editor"
	case RoleViewer:
		return "Viewer"
	default:
		return "Unknown"
	}
}

// User is an account that can sign in to manage monitors and CSRs. Reading
// the public dashboard never requires one.
type User struct {
	ID                 uuid.UUID
	Email              string
	PasswordHash       string
	Role               Role
	TOTPSecret         string
	MFAEnabled         bool
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastLoginAt        *time.Time
}

// NeedsPasswordChange and NeedsMFAEnrollment each report whether the account
// still has a forced onboarding step to complete before it can use the app
// normally — a fresh bootstrap admin, or anyone who hasn't finished
// enrolling MFA yet.
func (u *User) NeedsPasswordChange() bool { return u != nil && u.MustChangePassword }
func (u *User) NeedsMFAEnrollment() bool  { return u != nil && !u.MFAEnabled }

// Validate normalises and checks user-supplied account fields. Password
// strength and hashing are handled by the auth service, not here.
func (u *User) Validate() error {
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	if u.Email == "" {
		return Invalid("email", "email is required")
	}
	if !strings.Contains(u.Email, "@") {
		return Invalid("email", "must be a valid email address")
	}
	if !u.Role.Valid() {
		return Invalid("role", "role must be admin, editor, or viewer")
	}
	return nil
}

// Session is a signed-in browser session. Only TokenHash is ever persisted —
// the raw token lives solely in the user's cookie.
type Session struct {
	TokenHash  string
	UserID     uuid.UUID
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// Expired reports whether the session has passed its absolute expiry.
func (s *Session) Expired(now time.Time) bool {
	return s == nil || now.After(s.ExpiresAt)
}

// RecoveryCode is a one-time MFA bypass code, stored hashed.
type RecoveryCode struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}

// LoginAttempt records one login try, successful or not — the basis for a
// simple brute-force guard now and the login audit trail in a later phase.
type LoginAttempt struct {
	ID        uuid.UUID
	Email     string
	IP        string
	Success   bool
	Reason    string
	CreatedAt time.Time
}

// UserRepository is the persistence port for accounts, sessions, recovery
// codes, and the login attempt log.
type UserRepository interface {
	CreateUser(ctx context.Context, u *User) error
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	CountAdmins(ctx context.Context) (int, error)
	CountUsers(ctx context.Context) (int, error)

	ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes []string) error
	UnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]*RecoveryCode, error)
	MarkRecoveryCodeUsed(ctx context.Context, id uuid.UUID) error

	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, tokenHash string) (*Session, error)
	TouchSession(ctx context.Context, tokenHash string, lastSeen, expiresAt time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteSessionsForUser(ctx context.Context, userID uuid.UUID) error

	RecordLoginAttempt(ctx context.Context, a *LoginAttempt) error
	RecentFailedAttempts(ctx context.Context, email string, since time.Time) (int, error)
}
