package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/ldapauth"
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

func TestResetMFAClearsEnrollmentSessionsAndRecoveryCodes(t *testing.T) {
	repo := newFakeUserRepo()
	auth := newTestAuthService(repo)
	ctx := context.Background()
	user := mustCreateUser(t, auth, ctx, "admin@example.com", "correct-horse", domain.RoleAdmin)

	enrollment, err := auth.BeginMFAEnrollment(ctx, user)
	if err != nil {
		t.Fatalf("begin enrollment failed: %v", err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate a valid TOTP code for the test: %v", err)
	}
	if _, err := auth.ConfirmMFAEnrollment(ctx, user, code); err != nil {
		t.Fatalf("confirm enrollment failed: %v", err)
	}

	// An active session must exist before the reset, so we can prove it gets
	// torn down.
	if _, _, err := auth.createSession(ctx, user.ID); err != nil {
		t.Fatalf("createSession failed: %v", err)
	}
	if got := len(repo.sessions); got == 0 {
		t.Fatal("expected at least one session before ResetMFA")
	}

	if err := auth.ResetMFA(ctx, user.ID); err != nil {
		t.Fatalf("ResetMFA failed: %v", err)
	}

	refetched, err := repo.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID after reset: %v", err)
	}
	if refetched.MFAEnabled {
		t.Fatal("expected MFAEnabled to be false after ResetMFA")
	}
	if refetched.TOTPSecret != "" {
		t.Fatal("expected TOTPSecret to be cleared after ResetMFA")
	}
	if !refetched.NeedsMFAEnrollment() {
		t.Fatal("expected NeedsMFAEnrollment to be true again after ResetMFA, so the holder re-enrolls at next login")
	}
	if len(repo.sessions) != 0 {
		t.Fatalf("expected ResetMFA to sign the account out everywhere, got %d sessions still present", len(repo.sessions))
	}
	remaining, err := repo.UnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("UnusedRecoveryCodes after reset: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected old recovery codes to be cleared after ResetMFA, got %d remaining", len(remaining))
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

// fakeLDAPClient is an in-memory stand-in for ldapauth.Client — no network,
// no real directory. LDAPClient itself is exercised against a real slapd
// instance instead (see internal/pkg/ldapauth's live tests); this fake lets
// AuthService's LDAP branching logic be tested in isolation, exactly like
// fakeUserRepo isolates it from a real database.
type fakeLDAPClient struct {
	// directory maps a lowercased email to the account a real directory
	// would hold for it. A missing entry means "no such user in LDAP."
	directory map[string]fakeLDAPEntry
}

type fakeLDAPEntry struct {
	password string
	dn       string
	groups   []string
}

func newFakeLDAPClient() *fakeLDAPClient {
	return &fakeLDAPClient{directory: map[string]fakeLDAPEntry{}}
}

func (f *fakeLDAPClient) add(email, password string, groups ...string) {
	f.directory[strings.ToLower(email)] = fakeLDAPEntry{
		password: password,
		dn:       "uid=" + email + ",ou=people,dc=example,dc=com",
		groups:   groups,
	}
}

func (f *fakeLDAPClient) Authenticate(_ context.Context, email, password string) (*ldapauth.AuthResult, error) {
	e, ok := f.directory[strings.ToLower(email)]
	if !ok || e.password != password {
		return nil, ldapauth.ErrInvalidCredentials
	}
	return &ldapauth.AuthResult{DN: e.dn, Groups: e.groups}, nil
}

const (
	editorGroupDN    = "cn=sslgen-editors,ou=groups,dc=example,dc=com"
	viewerGroupDN    = "cn=sslgen-viewers,ou=groups,dc=example,dc=com"
	requesterGroupDN = "cn=sslgen-requesters,ou=groups,dc=example,dc=com"
)

// newTestAuthServiceWithLDAP builds an AuthService with LDAP "configured"
// via a settings snapshot (v1.8 moved LDAP config from a static AuthOptions
// field to the portal-editable SettingsService) whose LDAPClientFactory
// ignores the ldapauth.Config it's given and always returns the fake client
// passed in — the fake doesn't care about the config fields, it just needs
// to be the client AuthService actually calls.
func newTestAuthServiceWithLDAP(repo domain.UserRepository, ldap ldapauth.Client) *AuthService {
	settings := newTestSettingsService(domain.AppSettings{
		LDAPURL:              "ldap://fake.example.com:389",
		LDAPRoleMapEditor:    []string{editorGroupDN},
		LDAPRoleMapViewer:    []string{viewerGroupDN},
		LDAPRoleMapRequester: []string{requesterGroupDN},
	})
	return NewAuthService(repo, discardLogger(), AuthOptions{
		SessionSecret:     "test-secret-do-not-use-in-prod",
		Settings:          settings,
		LDAPClientFactory: func(ldapauth.Config) ldapauth.Client { return ldap },
	})
}

func TestLDAPLoginJITProvisionsNewAccount(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("newhire@example.com", "hunter2", editorGroupDN)
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()

	if _, err := repo.GetUserByEmail(ctx, "newhire@example.com"); err == nil {
		t.Fatal("test setup: account must not exist yet")
	}

	step, err := auth.Login(ctx, "newhire@example.com", "hunter2", "127.0.0.1")
	if err != nil {
		t.Fatalf("expected LDAP login to JIT-provision and succeed, got %v", err)
	}
	if step.Session == nil {
		t.Fatalf("expected an immediate session (MFA not yet enrolled), got %+v", step)
	}

	created, err := repo.GetUserByEmail(ctx, "newhire@example.com")
	if err != nil {
		t.Fatalf("expected a local account to have been provisioned: %v", err)
	}
	if created.AuthSource != domain.AuthSourceLDAP {
		t.Fatalf("expected AuthSourceLDAP, got %q", created.AuthSource)
	}
	if created.Role != domain.RoleEditor {
		t.Fatalf("expected role editor from the group mapping, got %q", created.Role)
	}
}

func TestLDAPLoginDeniesUnmappedGroups(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("nogroup@example.com", "hunter2", "cn=some-other-group,ou=groups,dc=example,dc=com")
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()

	if _, err := auth.Login(ctx, "nogroup@example.com", "hunter2", "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatalf("expected fail-closed denial for an unmapped group, got %v", err)
	}
	if _, err := repo.GetUserByEmail(ctx, "nogroup@example.com"); err == nil {
		t.Fatal("expected no account to be provisioned for a denied login")
	}
}

func TestLDAPLoginWrongPasswordFails(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("someone@example.com", "hunter2", editorGroupDN)
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()

	if _, err := auth.Login(ctx, "someone@example.com", "wrong", "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for a bad LDAP password, got %v", err)
	}
}

func TestLDAPLoginResyncsRoleOnGroupChange(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("promoted@example.com", "hunter2", viewerGroupDN)
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()

	if _, err := auth.Login(ctx, "promoted@example.com", "hunter2", "127.0.0.1"); err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	first, _ := repo.GetUserByEmail(ctx, "promoted@example.com")
	if first.Role != domain.RoleViewer {
		t.Fatalf("expected initial role viewer, got %q", first.Role)
	}

	// The directory now reflects a promotion to the editors group — LDAP is
	// the standing source of truth, so the very next login must re-sync the
	// role rather than keeping whatever was JIT-provisioned the first time.
	ldap.add("promoted@example.com", "hunter2", editorGroupDN)
	if _, err := auth.Login(ctx, "promoted@example.com", "hunter2", "127.0.0.1"); err != nil {
		t.Fatalf("second login failed: %v", err)
	}
	second, _ := repo.GetUserByEmail(ctx, "promoted@example.com")
	if second.Role != domain.RoleEditor {
		t.Fatalf("expected role to be re-synced to editor, got %q", second.Role)
	}
	if second.ID != first.ID {
		t.Fatal("expected the same account to be updated, not a second one created")
	}
}

// TestLDAPLoginUsesLiveSettingsWithoutReconstructingAuthService is the
// direct regression test for v1.8's headline claim: a portal edit to LDAP
// settings takes effect on the very next login, with no restart and no
// rebuilding of AuthService itself. It mutates the same SettingsService's
// live snapshot in place between two Login calls on one AuthService
// instance — exactly what a real admin's /settings save does under the
// hood (SettingsService.Update ends with Reload swapping the
// atomic.Pointer) — rather than constructing a second AuthService with
// different settings, which would prove nothing about "live."
func TestLDAPLoginUsesLiveSettingsWithoutReconstructingAuthService(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("carol@example.com", "hunter2", viewerGroupDN)
	settings := newTestSettingsService(domain.AppSettings{
		LDAPURL:           "ldap://fake.example.com:389",
		LDAPRoleMapEditor: []string{editorGroupDN},
		LDAPRoleMapViewer: []string{viewerGroupDN},
	})
	auth := NewAuthService(repo, discardLogger(), AuthOptions{
		SessionSecret:     "test-secret-do-not-use-in-prod",
		Settings:          settings,
		LDAPClientFactory: func(ldapauth.Config) ldapauth.Client { return ldap },
	})
	ctx := context.Background()

	if _, err := auth.Login(ctx, "carol@example.com", "hunter2", "127.0.0.1"); err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	first, _ := repo.GetUserByEmail(ctx, "carol@example.com")
	if first.Role != domain.RoleViewer {
		t.Fatalf("expected initial role viewer from the original settings, got %q", first.Role)
	}

	// Simulate a live admin edit on /settings: move carol's group from the
	// viewer mapping to the editor mapping, and swap the live snapshot the
	// same way SettingsService.Update/Reload does — without touching auth
	// or settings' construction at all.
	settings.current.Store(&domain.AppSettings{
		LDAPURL:           "ldap://fake.example.com:389",
		LDAPRoleMapEditor: []string{viewerGroupDN},
	})

	if _, err := auth.Login(ctx, "carol@example.com", "hunter2", "127.0.0.1"); err != nil {
		t.Fatalf("second login failed: %v", err)
	}
	second, _ := repo.GetUserByEmail(ctx, "carol@example.com")
	if second.Role != domain.RoleEditor {
		t.Fatalf("expected the live settings edit to take effect immediately (role editor), got %q", second.Role)
	}
}

func TestLDAPConfiguredAdminStillUsesLocalPassword(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient() // deliberately has no entry for the admin at all
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()
	mustCreateUser(t, auth, ctx, "admin@example.com", "correct-horse", domain.RoleAdmin)

	step, err := auth.Login(ctx, "admin@example.com", "correct-horse", "127.0.0.1")
	if err != nil {
		t.Fatalf("expected the admin account to still authenticate locally even with LDAP configured, got %v", err)
	}
	if step.Session == nil {
		t.Fatalf("expected an immediate session, got %+v", step)
	}
}

func TestLDAPConfiguredNonAdminLocalPasswordStopsWorking(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient() // no matching LDAP entry either
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()
	// A pre-existing local editor account, created before LDAP was ever
	// configured (mustCreateUser uses AuthSourceLocal via CreateUser).
	mustCreateUser(t, auth, ctx, "editor@example.com", "correct-horse", domain.RoleEditor)

	if _, err := auth.Login(ctx, "editor@example.com", "correct-horse", "127.0.0.1"); err != domain.ErrUnauthorized {
		t.Fatalf("expected local password login to stop working for a non-admin once LDAP is configured, got %v", err)
	}
}

func TestUpdateRoleRefusesPromotingLDAPAccountToAdmin(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("ldapuser@example.com", "hunter2", editorGroupDN)
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()
	if _, err := auth.Login(ctx, "ldapuser@example.com", "hunter2", "127.0.0.1"); err != nil {
		t.Fatalf("provisioning login failed: %v", err)
	}
	u, err := repo.GetUserByEmail(ctx, "ldapuser@example.com")
	if err != nil {
		t.Fatalf("expected provisioned account: %v", err)
	}

	if err := auth.UpdateRole(ctx, u.ID, domain.RoleAdmin); err == nil {
		t.Fatal("expected promoting an LDAP-sourced account to admin to be refused")
	}
}

func TestResetPasswordRefusesForLDAPAccount(t *testing.T) {
	repo := newFakeUserRepo()
	ldap := newFakeLDAPClient()
	ldap.add("ldapuser@example.com", "hunter2", editorGroupDN)
	auth := newTestAuthServiceWithLDAP(repo, ldap)
	ctx := context.Background()
	if _, err := auth.Login(ctx, "ldapuser@example.com", "hunter2", "127.0.0.1"); err != nil {
		t.Fatalf("provisioning login failed: %v", err)
	}
	u, err := repo.GetUserByEmail(ctx, "ldapuser@example.com")
	if err != nil {
		t.Fatalf("expected provisioned account: %v", err)
	}

	if err := auth.ResetPassword(ctx, u.ID, "irrelevant12345"); err == nil {
		t.Fatal("expected resetting an LDAP account's password to be refused")
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
