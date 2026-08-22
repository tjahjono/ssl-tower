package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// fakeUserRepo is an in-memory stand-in for domain.UserRepository. It stores
// by value (not by shared pointer) so a test only sees a change the service
// actually persisted via an explicit Update/Create call — the same
// distinction a real database would enforce.
type fakeUserRepo struct {
	users    map[uuid.UUID]domain.User
	byEmail  map[string]uuid.UUID
	sessions map[string]domain.Session
	recovery map[uuid.UUID][]domain.RecoveryCode
	attempts []domain.LoginAttempt
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{
		users:    map[uuid.UUID]domain.User{},
		byEmail:  map[string]uuid.UUID{},
		sessions: map[string]domain.Session{},
		recovery: map[uuid.UUID][]domain.RecoveryCode{},
	}
}

func (f *fakeUserRepo) CreateUser(_ context.Context, u *domain.User) error {
	if _, exists := f.byEmail[strings.ToLower(u.Email)]; exists {
		return domain.ErrConflict
	}
	u.ID = uuid.New()
	u.CreatedAt = time.Now()
	u.UpdatedAt = u.CreatedAt
	f.users[u.ID] = *u
	f.byEmail[strings.ToLower(u.Email)] = u.ID
	return nil
}

func (f *fakeUserRepo) UpdateUser(_ context.Context, u *domain.User) error {
	if _, ok := f.users[u.ID]; !ok {
		return domain.ErrNotFound
	}
	u.UpdatedAt = time.Now()
	f.users[u.ID] = *u
	return nil
}

func (f *fakeUserRepo) DeleteUser(_ context.Context, id uuid.UUID) error {
	u, ok := f.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	delete(f.users, id)
	delete(f.byEmail, strings.ToLower(u.Email))
	return nil
}

func (f *fakeUserRepo) GetUserByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := u
	return &cp, nil
}

func (f *fakeUserRepo) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	id, ok := f.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return f.GetUserByID(ctx, id)
}

func (f *fakeUserRepo) ListUsers(_ context.Context) ([]*domain.User, error) {
	out := make([]*domain.User, 0, len(f.users))
	for _, u := range f.users {
		cp := u
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeUserRepo) CountAdmins(_ context.Context) (int, error) {
	n := 0
	for _, u := range f.users {
		if u.Role == domain.RoleAdmin {
			n++
		}
	}
	return n, nil
}

func (f *fakeUserRepo) CountUsers(_ context.Context) (int, error) { return len(f.users), nil }

func (f *fakeUserRepo) ReplaceRecoveryCodes(_ context.Context, userID uuid.UUID, hashes []string) error {
	codes := make([]domain.RecoveryCode, len(hashes))
	for i, h := range hashes {
		codes[i] = domain.RecoveryCode{ID: uuid.New(), UserID: userID, CodeHash: h, CreatedAt: time.Now()}
	}
	f.recovery[userID] = codes
	return nil
}

func (f *fakeUserRepo) UnusedRecoveryCodes(_ context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error) {
	var out []*domain.RecoveryCode
	for _, c := range f.recovery[userID] {
		if c.UsedAt == nil {
			cp := c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeUserRepo) MarkRecoveryCodeUsed(_ context.Context, id uuid.UUID) error {
	for uid, codes := range f.recovery {
		for i := range codes {
			if codes[i].ID == id {
				now := time.Now()
				codes[i].UsedAt = &now
				f.recovery[uid] = codes
				return nil
			}
		}
	}
	return domain.ErrNotFound
}

func (f *fakeUserRepo) CreateSession(_ context.Context, s *domain.Session) error {
	s.CreatedAt = time.Now()
	s.LastSeenAt = s.CreatedAt
	f.sessions[s.TokenHash] = *s
	return nil
}

func (f *fakeUserRepo) GetSession(_ context.Context, tokenHash string) (*domain.Session, error) {
	s, ok := f.sessions[tokenHash]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := s
	return &cp, nil
}

func (f *fakeUserRepo) TouchSession(_ context.Context, tokenHash string, lastSeen, expiresAt time.Time) error {
	s, ok := f.sessions[tokenHash]
	if !ok {
		return domain.ErrNotFound
	}
	s.LastSeenAt = lastSeen
	s.ExpiresAt = expiresAt
	f.sessions[tokenHash] = s
	return nil
}

func (f *fakeUserRepo) DeleteSession(_ context.Context, tokenHash string) error {
	delete(f.sessions, tokenHash)
	return nil
}

func (f *fakeUserRepo) DeleteSessionsForUser(_ context.Context, userID uuid.UUID) error {
	for k, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, k)
		}
	}
	return nil
}

func (f *fakeUserRepo) RecordLoginAttempt(_ context.Context, a *domain.LoginAttempt) error {
	a.ID = uuid.New()
	a.CreatedAt = time.Now()
	f.attempts = append(f.attempts, *a)
	return nil
}

func (f *fakeUserRepo) RecentFailedAttempts(_ context.Context, email string, since time.Time) (int, error) {
	n := 0
	for _, a := range f.attempts {
		if !a.Success && strings.EqualFold(a.Email, email) && !a.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func newTestAuthService(repo domain.UserRepository) *AuthService {
	return NewAuthService(repo, discardLogger(), AuthOptions{SessionSecret: "test-secret-do-not-use-in-prod"})
}

func TestBootstrapCreatesInitialAdminOnce(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()

	if err := auth.Bootstrap(ctx, "admin@example.com", "hunter22"); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	u, err := repo.GetUserByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("expected bootstrap admin to exist: %v", err)
	}
	if u.Role != domain.RoleAdmin || !u.MustChangePassword {
		t.Fatalf("expected a must-change-password admin, got %+v", u)
	}

	// Second call must be a no-op — a table that already has a user must
	// never get a second bootstrap account, even with different credentials.
	if err := auth.Bootstrap(ctx, "someone-else@example.com", "whatever123"); err != nil {
		t.Fatalf("expected re-bootstrap to be a silent no-op, got error: %v", err)
	}
	if n, _ := repo.CountUsers(ctx); n != 1 {
		t.Fatalf("expected exactly one user after a second Bootstrap call, got %d", n)
	}
}

func TestBootstrapRequiresCredentialsWhenEmpty(t *testing.T) {
	auth := newTestAuthService(newFakeUserRepo())
	if err := auth.Bootstrap(context.Background(), "", ""); err == nil {
		t.Fatal("expected bootstrap with no ADMIN_EMAIL/ADMIN_INITIAL_PASSWORD to fail on an empty user table")
	}
}

func TestLoginWithoutMFAIssuesSessionDirectly(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	mustCreateUser(t, auth, ctx, "editor@example.com", "correct-horse", domain.RoleEditor)

	step, err := auth.Login(ctx, "editor@example.com", "correct-horse", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if step.Session == nil || step.RawToken == "" || step.PendingToken != "" {
		t.Fatalf("expected an immediate session with no MFA enrolled, got %+v", step)
	}

	user, err := auth.ValidateSession(ctx, step.RawToken)
	if err != nil || user.Email != "editor@example.com" {
		t.Fatalf("expected the raw token to validate to the same user, got user=%v err=%v", user, err)
	}
}

func TestLoginWithWrongPasswordFails(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	mustCreateUser(t, auth, ctx, "editor@example.com", "correct-horse", domain.RoleEditor)

	if _, err := auth.Login(ctx, "editor@example.com", "wrong-password", "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for a wrong password, got %v", err)
	}
}

func TestLoginLocksOutAfterTooManyFailures(t *testing.T) {
	repo := newFakeUserRepo()
	auth := NewAuthService(repo, discardLogger(), AuthOptions{
		SessionSecret: "test-secret", MaxFailedAttempts: 3, LockoutWindow: time.Hour,
	})
	ctx := context.Background()
	mustCreateUser(t, auth, ctx, "editor@example.com", "correct-horse", domain.RoleEditor)

	for i := 0; i < 3; i++ {
		if _, err := auth.Login(ctx, "editor@example.com", "wrong", "127.0.0.1"); err != domain.ErrUnauthorized {
			t.Fatalf("attempt %d: expected ErrUnauthorized, got %v", i, err)
		}
	}
	// The 4th attempt uses the CORRECT password but should still be refused —
	// this is what makes it a lockout rather than just normal auth failure.
	if _, err := auth.Login(ctx, "editor@example.com", "correct-horse", "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatalf("expected the account to be locked out after repeated failures, got %v", err)
	}
}

func TestMFAEnrollmentAndLoginFlow(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	user := mustCreateUser(t, auth, ctx, "admin@example.com", "correct-horse", domain.RoleAdmin)

	enrollment, err := auth.BeginMFAEnrollment(ctx, user)
	if err != nil {
		t.Fatalf("begin enrollment failed: %v", err)
	}
	if enrollment.Secret == "" || enrollment.QRPNGBase64 == "" {
		t.Fatalf("expected a populated secret and QR image, got %+v", enrollment)
	}

	// Wrong code must not turn MFA on.
	if _, err := auth.ConfirmMFAEnrollment(ctx, user, "000000"); err != domain.ErrUnauthorized {
		t.Fatalf("expected a wrong confirmation code to fail, got %v", err)
	}
	if refetched, _ := repo.GetUserByID(ctx, user.ID); refetched.MFAEnabled {
		t.Fatal("MFA must not be enabled after a failed confirmation")
	}

	code, err := totp.GenerateCode(user.TOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate a valid TOTP code for the test: %v", err)
	}
	recoveryCodes, err := auth.ConfirmMFAEnrollment(ctx, user, code)
	if err != nil {
		t.Fatalf("expected the correct code to confirm enrollment, got %v", err)
	}
	if len(recoveryCodes) != recoveryCodeCount {
		t.Fatalf("expected %d recovery codes, got %d", recoveryCodeCount, len(recoveryCodes))
	}

	// From here on, a plain password login must yield a pending MFA step,
	// not an immediate session.
	step, err := auth.Login(ctx, "admin@example.com", "correct-horse", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if step.Session != nil || step.PendingToken == "" {
		t.Fatalf("expected a pending MFA step once MFA is enabled, got %+v", step)
	}

	freshUser, _ := repo.GetUserByID(ctx, user.ID)
	totpCode, _ := totp.GenerateCode(freshUser.TOTPSecret, time.Now())
	final, err := auth.VerifyMFA(ctx, step.PendingToken, totpCode, "127.0.0.1")
	if err != nil || final.Session == nil {
		t.Fatalf("expected VerifyMFA with a correct code to issue a session, got final=%+v err=%v", final, err)
	}

	// A recovery code must work exactly once.
	final2, err := auth.Login(ctx, "admin@example.com", "correct-horse", "127.0.0.1")
	if err != nil {
		t.Fatalf("second login failed: %v", err)
	}
	usedRecoveryCode := recoveryCodes[0]
	viaRecovery, err := auth.VerifyMFA(ctx, final2.PendingToken, usedRecoveryCode, "127.0.0.1")
	if err != nil || viaRecovery.Session == nil {
		t.Fatalf("expected a valid recovery code to issue a session, got %v / err=%v", viaRecovery, err)
	}
	final3, _ := auth.Login(ctx, "admin@example.com", "correct-horse", "127.0.0.1")
	if _, err := auth.VerifyMFA(ctx, final3.PendingToken, usedRecoveryCode, "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatal("expected a recovery code to be single-use — reusing it must fail")
	}
}

func TestValidateSessionRejectsExpired(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	user := mustCreateUser(t, auth, ctx, "editor@example.com", "correct-horse", domain.RoleEditor)

	_, raw, err := auth.createSession(ctx, user.ID)
	if err != nil {
		t.Fatalf("createSession failed: %v", err)
	}
	// Reach into the fake store to simulate the idle window having already
	// elapsed — NewAuthService would otherwise silently replace a
	// non-positive IdleTimeout override with its own default, which is
	// exactly the "unset vs. deliberately expired" ambiguity this sidesteps.
	th := hashToken(raw)
	expired := repo.sessions[th]
	expired.ExpiresAt = time.Now().Add(-1 * time.Minute)
	repo.sessions[th] = expired

	if _, err := auth.ValidateSession(ctx, raw); err != domain.ErrUnauthorized {
		t.Fatalf("expected an already-expired session to be rejected, got %v", err)
	}
	if _, err := repo.GetSession(ctx, th); err == nil {
		t.Fatal("expected the expired session to be deleted from storage")
	}
}

func TestValidateSessionRejectsPastAbsoluteCap(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	user := mustCreateUser(t, auth, ctx, "editor@example.com", "correct-horse", domain.RoleEditor)

	_, raw, err := auth.createSession(ctx, user.ID)
	if err != nil {
		t.Fatalf("createSession failed: %v", err)
	}
	// Idle window still fine, but the session is far older than the
	// absolute cap — must be rejected even though it's been "active".
	th := hashToken(raw)
	stale := repo.sessions[th]
	stale.CreatedAt = time.Now().Add(-60 * 24 * time.Hour)
	stale.ExpiresAt = time.Now().Add(time.Hour)
	repo.sessions[th] = stale

	if _, err := auth.ValidateSession(ctx, raw); err != domain.ErrUnauthorized {
		t.Fatalf("expected a session past its absolute cap to be rejected, got %v", err)
	}
}

func TestChangePasswordInvalidatesExistingSessions(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	user := mustCreateUser(t, auth, ctx, "editor@example.com", "old-password", domain.RoleEditor)

	step, err := auth.Login(ctx, "editor@example.com", "old-password", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if err := auth.ChangePassword(ctx, user.ID, "new-password"); err != nil {
		t.Fatalf("change password failed: %v", err)
	}
	if _, err := auth.ValidateSession(ctx, step.RawToken); err != domain.ErrUnauthorized {
		t.Fatal("expected the old session to be invalidated after a password change")
	}
	if _, err := auth.Login(ctx, "editor@example.com", "old-password", "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatal("expected the old password to stop working after a change")
	}
	if _, err := auth.Login(ctx, "editor@example.com", "new-password", "127.0.0.1"); err != nil {
		t.Fatalf("expected the new password to work, got %v", err)
	}
}

func TestCannotDeleteOrDemoteLastAdmin(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	admin := mustCreateUser(t, auth, ctx, "admin@example.com", "correct-horse", domain.RoleAdmin)

	if err := auth.UpdateRole(ctx, admin.ID, domain.RoleViewer); err == nil {
		t.Fatal("expected demoting the last admin to be refused")
	}
	if err := auth.DeleteUser(ctx, admin.ID); err == nil {
		t.Fatal("expected deleting the last admin to be refused")
	}

	// With a second admin present, both operations on the first must succeed.
	mustCreateUser(t, auth, ctx, "admin2@example.com", "correct-horse", domain.RoleAdmin)
	if err := auth.UpdateRole(ctx, admin.ID, domain.RoleViewer); err != nil {
		t.Fatalf("expected demotion to succeed with another admin present, got %v", err)
	}
}

func mustCreateUser(t *testing.T, auth *AuthService, ctx context.Context, email, password string, role domain.Role) *domain.User {
	t.Helper()
	u, err := auth.CreateUser(ctx, email, password, role)
	if err != nil {
		t.Fatalf("failed to create test user %s: %v", email, err)
	}
	return u
}
