package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/authcrypto"
	"github.com/ivangiovn/ssl-generator/internal/pkg/ldapauth"
)

const (
	recoveryCodeCount = 10
	pendingMFATTL     = 5 * time.Minute
	sessionTokenBytes = 32
)

// AuthOptions configures session lifetime, brute-force guarding, and TOTP
// enrollment.
type AuthOptions struct {
	// SessionSecret signs the short-lived "password verified, awaiting MFA"
	// token — a full session token is a random opaque value looked up in the
	// sessions table, so it needs no signing of its own.
	SessionSecret string
	// IdleTimeout is the sliding window a session stays valid without
	// activity. Defaults to 12h.
	IdleTimeout time.Duration
	// AbsoluteTimeout is the hard cap on a session's lifetime regardless of
	// activity. Defaults to 30 days.
	AbsoluteTimeout time.Duration
	// MaxFailedAttempts within LockoutWindow locks an email out of further
	// login attempts until the window passes. Defaults to 10 within 15m.
	MaxFailedAttempts int
	LockoutWindow     time.Duration
	// Issuer is the label shown in an authenticator app next to the account.
	Issuer string
	// Settings supplies live LDAP configuration (v1.8: portal-editable, see
	// CLAUDE.md's v1.8 locked decision) — AuthService rebuilds an
	// ldapauth.Client fresh from Settings.Current() on every login attempt
	// rather than caching one at construction time, the same "cheap,
	// stateless, always current" pattern SettingsService.EmailNotifier/
	// TeamsNotifier already use for SMTP/Teams. An empty
	// Settings.Current().LDAPURL means LDAP is off — every login goes
	// through the local password/MFA path exactly as before this feature
	// existed, matching the "empty = off" convention every other optional
	// integration in this app already follows. See CLAUDE.md's LDAP locked
	// decisions for why this is deliberately not a per-role toggle: an
	// admin account always authenticates locally regardless of this
	// setting, and every other role always authenticates via LDAP once
	// it's set, never a mix chosen per account. Nil disables LDAP
	// permanently regardless of settings — used by tests that never touch
	// it.
	Settings *SettingsService
	// LDAPClientFactory builds the LDAP client from a live config —
	// ldapauth.NewLDAPClient does no I/O itself, so rebuilding on every
	// login attempt is cheap, the same property EmailNotifier/TeamsNotifier
	// rely on. Swapped out in tests for one that returns a fake client
	// regardless of the config passed in. Defaults to ldapauth.NewLDAPClient
	// if left nil.
	LDAPClientFactory func(ldapauth.Config) ldapauth.Client
}

// LDAPRoleMapping lists, for each non-admin role, the LDAP group DNs whose
// members should hold that role. Checked in Editor, Viewer, Requester
// order — the most privileged matching group wins when an entry belongs to
// more than one mapped group. Deliberately has no Admin field: admin is
// always locally-granted, see AuthService.UpdateRole. An account whose
// groups match none of these is denied login and logged, not silently
// provisioned at a default role.
type LDAPRoleMapping struct {
	Editor    []string
	Viewer    []string
	Requester []string
}

// AuthService implements accounts, sessions, and TOTP-based MFA.
type AuthService struct {
	repo domain.UserRepository
	log  *slog.Logger
	opts AuthOptions
}

// NewAuthService builds the service, applying sane defaults to any unset option.
func NewAuthService(repo domain.UserRepository, log *slog.Logger, opts AuthOptions) *AuthService {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 12 * time.Hour
	}
	if opts.AbsoluteTimeout <= 0 {
		opts.AbsoluteTimeout = 30 * 24 * time.Hour
	}
	if opts.MaxFailedAttempts <= 0 {
		opts.MaxFailedAttempts = 10
	}
	if opts.LockoutWindow <= 0 {
		opts.LockoutWindow = 15 * time.Minute
	}
	if opts.Issuer == "" {
		opts.Issuer = "SSL Tower"
	}
	if opts.LDAPClientFactory == nil {
		// ldapauth.NewLDAPClient returns a concrete *ldapauth.LDAPClient, not
		// the ldapauth.Client interface, so it needs this thin wrapper to
		// satisfy the factory's signature.
		opts.LDAPClientFactory = func(cfg ldapauth.Config) ldapauth.Client { return ldapauth.NewLDAPClient(cfg) }
	}
	return &AuthService{repo: repo, log: log, opts: opts}
}

// ldapConfigured reads the live LDAP settings and reports whether LDAP is
// currently on (LDAPURL non-empty) — nil/false means every login goes
// through the local password path, exactly as if LDAP had never been
// configured. Building the client here rather than caching one means a
// portal edit to any LDAP field takes effect on the very next login
// attempt, no restart needed, matching every other v1.5/v1.8 portal
// setting.
func (a *AuthService) ldapConfigured() (ldapauth.Client, LDAPRoleMapping, bool) {
	if a.opts.Settings == nil {
		return nil, LDAPRoleMapping{}, false
	}
	cur := a.opts.Settings.Current()
	url := strings.TrimSpace(cur.LDAPURL)
	if url == "" {
		return nil, LDAPRoleMapping{}, false
	}
	cfg := ldapauth.Config{
		URL:          url,
		BindDN:       cur.LDAPBindDN,
		BindPassword: cur.LDAPBindPassword,
		BaseDN:       cur.LDAPBaseDN,
		UserFilter:   cur.LDAPUserFilter,
		GroupFilter:  cur.LDAPGroupFilter,
	}
	roleMap := LDAPRoleMapping{
		Editor:    cur.LDAPRoleMapEditor,
		Viewer:    cur.LDAPRoleMapViewer,
		Requester: cur.LDAPRoleMapRequester,
	}
	return a.opts.LDAPClientFactory(cfg), roleMap, true
}

// Bootstrap ensures at least one account exists, creating an initial admin
// from the given credentials when the user table is empty. Safe to call on
// every boot — a no-op once any account exists.
func (a *AuthService) Bootstrap(ctx context.Context, email, initialPassword string) error {
	n, err := a.repo.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("auth: bootstrap: %w", err)
	}
	if n > 0 {
		return nil
	}
	email = strings.TrimSpace(email)
	if email == "" || initialPassword == "" {
		return fmt.Errorf("auth: no accounts exist yet — set ADMIN_EMAIL and ADMIN_INITIAL_PASSWORD to bootstrap one")
	}
	hash, err := authcrypto.HashPassword(initialPassword)
	if err != nil {
		return err
	}
	u := &domain.User{Email: email, PasswordHash: hash, Role: domain.RoleAdmin, MustChangePassword: true}
	if err := u.Validate(); err != nil {
		return err
	}
	if err := a.repo.CreateUser(ctx, u); err != nil {
		return fmt.Errorf("auth: bootstrap: %w", err)
	}
	a.log.Warn("bootstrapped the initial admin account — sign in and change the password immediately", "email", u.Email)
	return nil
}

// LoginStep is the outcome of a login-flow call: either a full session (MFA
// wasn't required, or already passed), or a pending token that must be
// exchanged for one via VerifyMFA.
type LoginStep struct {
	Session      *domain.Session
	RawToken     string
	PendingToken string
	User         *domain.User
}

// Login verifies email and password — via a local password check, or, once
// LDAP is configured, via an LDAP bind for every account except admin (see
// AuthOptions.Settings's doc comment). When the account has MFA enabled, it
// returns a short-lived pending token instead of a session — the caller
// must then call VerifyMFA with a TOTP or recovery code to finish signing
// in. An account without MFA enabled yet gets a session immediately; the
// onboarding check in the delivery layer forces MFA enrollment before it
// can do anything else — MFA is mandatory regardless of auth source.
func (a *AuthService) Login(ctx context.Context, email, password, ip string) (*LoginStep, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	failed, err := a.repo.RecentFailedAttempts(ctx, email, time.Now().Add(-a.opts.LockoutWindow))
	if err == nil && failed >= a.opts.MaxFailedAttempts {
		a.recordAttempt(ctx, email, ip, false, "locked")
		return nil, domain.ErrUnauthorized
	}

	user, lookupErr := a.repo.GetUserByEmail(ctx, email)

	// An admin account always authenticates locally, LDAP configured or
	// not — admin is never LDAP-derived (see LDAPRoleMapping and
	// UpdateRole), so there is nothing for an LDAP bind to resolve here.
	if lookupErr == nil && user.Role == domain.RoleAdmin {
		return a.passwordLogin(ctx, email, user, password, ip)
	}

	ldapClient, roleMap, ldapOn := a.ldapConfigured()
	if !ldapOn {
		// LDAP isn't configured: unchanged pre-LDAP behavior for every role.
		if lookupErr != nil {
			a.recordAttempt(ctx, email, ip, false, "no_such_user")
			return nil, domain.ErrUnauthorized
		}
		return a.passwordLogin(ctx, email, user, password, ip)
	}

	// LDAP is configured and this isn't an admin account (it may not exist
	// locally yet at all — that's the JIT-provisioning case) — every such
	// account authenticates via LDAP, never a local password, even if it
	// was created locally before LDAP was turned on. See CLAUDE.md's LDAP
	// locked decisions for why this is intentional rather than a fallback.
	var existing *domain.User
	if lookupErr == nil {
		existing = user
	}
	return a.ldapLogin(ctx, email, password, ip, existing, ldapClient, roleMap)
}

// passwordLogin is the pre-LDAP local password + MFA login path, unchanged
// in behavior — factored out so Login can share it between "LDAP not
// configured" and "this is an admin account" without duplicating it.
func (a *AuthService) passwordLogin(ctx context.Context, email string, user *domain.User, password, ip string) (*LoginStep, error) {
	if !authcrypto.VerifyPassword(user.PasswordHash, password) {
		a.recordAttempt(ctx, email, ip, false, "bad_password")
		return nil, domain.ErrUnauthorized
	}

	if user.MFAEnabled {
		token, err := a.signPending(user.ID)
		if err != nil {
			return nil, err
		}
		a.recordAttempt(ctx, email, ip, true, "password_ok_awaiting_mfa")
		return &LoginStep{PendingToken: token, User: user}, nil
	}

	sess, raw, err := a.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	a.recordAttempt(ctx, email, ip, true, "ok_no_mfa_enrolled")
	a.touchLastLogin(ctx, user)
	return &LoginStep{Session: sess, RawToken: raw, User: user}, nil
}

// ldapLogin authenticates against LDAP via search-then-bind, JIT-provisions
// a local account on a brand-new user's first successful login, and
// re-syncs role/AuthSource on every later one — LDAP groups are the
// standing source of truth for a non-admin account's role once LDAP is
// configured, not just a one-time provisioning hint. A user whose groups
// match no configured role mapping is denied and logged (fail-closed), not
// silently provisioned at a default role.
func (a *AuthService) ldapLogin(ctx context.Context, email, password, ip string, existing *domain.User, ldapClient ldapauth.Client, roleMap LDAPRoleMapping) (*LoginStep, error) {
	result, err := ldapClient.Authenticate(ctx, email, password)
	if err != nil {
		if errors.Is(err, ldapauth.ErrInvalidCredentials) {
			a.recordAttempt(ctx, email, ip, false, "ldap_bad_credentials")
		} else {
			a.log.Warn("auth: ldap authenticate failed", "email", email, "error", err)
			a.recordAttempt(ctx, email, ip, false, "ldap_error")
		}
		return nil, domain.ErrUnauthorized
	}

	role, ok := resolveLDAPRole(roleMap, result.Groups)
	if !ok {
		a.log.Warn("auth: ldap user has no mapped role — denying login",
			"email", email, "dn", result.DN, "groups", result.Groups)
		a.recordAttempt(ctx, email, ip, false, "ldap_no_role_mapping")
		return nil, domain.ErrUnauthorized
	}

	user := existing
	switch {
	case user == nil:
		hash, err := lockedPasswordHash()
		if err != nil {
			return nil, err
		}
		user = &domain.User{
			Email:        email,
			PasswordHash: hash,
			Role:         role,
			AuthSource:   domain.AuthSourceLDAP,
		}
		if err := user.Validate(); err != nil {
			return nil, err
		}
		if err := a.repo.CreateUser(ctx, user); err != nil {
			return nil, err
		}
		a.log.Info("auth: JIT-provisioned new LDAP account", "email", email, "role", role)
	case user.AuthSource != domain.AuthSourceLDAP || user.Role != role:
		user.AuthSource = domain.AuthSourceLDAP
		user.Role = role
		if err := a.repo.UpdateUser(ctx, user); err != nil {
			return nil, err
		}
	}

	if user.MFAEnabled {
		token, err := a.signPending(user.ID)
		if err != nil {
			return nil, err
		}
		a.recordAttempt(ctx, email, ip, true, "ldap_ok_awaiting_mfa")
		return &LoginStep{PendingToken: token, User: user}, nil
	}

	sess, raw, err := a.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	a.recordAttempt(ctx, email, ip, true, "ldap_ok_no_mfa_enrolled")
	a.touchLastLogin(ctx, user)
	return &LoginStep{Session: sess, RawToken: raw, User: user}, nil
}

// resolveLDAPRole maps a set of group DNs the user belongs to onto an app
// role, per roleMap, checking Editor before Viewer before Requester so the
// most privileged matching group wins. Comparison is case-insensitive since
// DN component ordering is significant but casing conventionally isn't
// across directory implementations.
func resolveLDAPRole(roleMap LDAPRoleMapping, groups []string) (domain.Role, bool) {
	memberOf := make(map[string]bool, len(groups))
	for _, g := range groups {
		memberOf[strings.ToLower(g)] = true
	}
	for _, candidate := range []struct {
		role domain.Role
		dns  []string
	}{
		{domain.RoleEditor, roleMap.Editor},
		{domain.RoleViewer, roleMap.Viewer},
		{domain.RoleRequester, roleMap.Requester},
	} {
		for _, dn := range candidate.dns {
			if memberOf[strings.ToLower(dn)] {
				return candidate.role, true
			}
		}
	}
	return "", false
}

// lockedPasswordHash returns a bcrypt hash of a random value nobody knows,
// for the NOT NULL password_hash column on an LDAP-provisioned account that
// has no local password at all. It can never verify successfully — that's
// the point — and Login never even attempts to check it for such an
// account, since a non-admin account with LDAP configured always goes
// through ldapLogin instead of passwordLogin.
func lockedPasswordHash() (string, error) {
	token, err := authcrypto.RandomToken(32)
	if err != nil {
		return "", fmt.Errorf("auth: generate locked password placeholder: %w", err)
	}
	return authcrypto.HashPassword(token)
}

// VerifyMFA completes a login started by Login, checking a TOTP code first
// and falling back to a one-time recovery code.
func (a *AuthService) VerifyMFA(ctx context.Context, pendingToken, code, ip string) (*LoginStep, error) {
	userID, err := a.verifyPending(pendingToken)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	user, err := a.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}

	code = strings.TrimSpace(code)
	reason := "bad_totp_or_recovery"
	ok := code != "" && totp.Validate(code, user.TOTPSecret)
	if ok {
		reason = "totp_ok"
	} else if consumed, cerr := a.tryRecoveryCode(ctx, user.ID, code); cerr == nil && consumed {
		ok = true
		reason = "recovery_code"
	}
	if !ok {
		a.recordAttempt(ctx, user.Email, ip, false, reason)
		return nil, domain.ErrUnauthorized
	}

	sess, raw, err := a.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	a.recordAttempt(ctx, user.Email, ip, true, reason)
	a.touchLastLogin(ctx, user)
	return &LoginStep{Session: sess, RawToken: raw, User: user}, nil
}

func (a *AuthService) tryRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	code = authcrypto.NormalizeRecoveryCode(code)
	if code == "" {
		return false, nil
	}
	codes, err := a.repo.UnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, c := range codes {
		if authcrypto.VerifyPassword(c.CodeHash, code) {
			if err := a.repo.MarkRecoveryCodeUsed(ctx, c.ID); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// ValidateSession looks up a session by its raw cookie token, enforcing both
// the sliding idle timeout and the hard absolute cap, and slides the idle
// window forward on success. Returns domain.ErrUnauthorized for any invalid,
// expired, or unknown session.
func (a *AuthService) ValidateSession(ctx context.Context, rawToken string) (*domain.User, error) {
	sess, err := a.repo.GetSession(ctx, hashToken(rawToken))
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	now := time.Now()
	hardCap := sess.CreatedAt.Add(a.opts.AbsoluteTimeout)
	if now.After(sess.ExpiresAt) || now.After(hardCap) {
		_ = a.repo.DeleteSession(ctx, sess.TokenHash)
		return nil, domain.ErrUnauthorized
	}
	user, err := a.repo.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}

	newExpiry := now.Add(a.opts.IdleTimeout)
	if newExpiry.After(hardCap) {
		newExpiry = hardCap
	}
	if err := a.repo.TouchSession(ctx, sess.TokenHash, now, newExpiry); err != nil {
		a.log.Warn("auth: failed to slide session expiry", "error", err)
	}
	return user, nil
}

// Logout deletes one session by its raw cookie token.
func (a *AuthService) Logout(ctx context.Context, rawToken string) error {
	return a.repo.DeleteSession(ctx, hashToken(rawToken))
}

// CheckPassword verifies a plaintext password against an account's stored
// hash — used by the change-password flow to confirm the current password
// before accepting a new one.
func (a *AuthService) CheckPassword(user *domain.User, plaintext string) bool {
	return user != nil && authcrypto.VerifyPassword(user.PasswordHash, plaintext)
}

// ChangePassword sets a new password and clears the forced-change flag, then
// invalidates every session for the account (including the one making this
// request) — the caller is expected to sign the user out and prompt them to
// sign back in with the new password.
func (a *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	user, err := a.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	hash, err := authcrypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	user.MustChangePassword = false
	if err := a.repo.UpdateUser(ctx, user); err != nil {
		return err
	}
	return a.repo.DeleteSessionsForUser(ctx, userID)
}

// MFAEnrollment carries what the enrollment page needs to render — the QR
// code and a manual-entry fallback secret. Nothing sensitive here is a
// long-term secret on its own: TOTPSecret is not yet active until
// ConfirmMFAEnrollment succeeds.
type MFAEnrollment struct {
	Secret      string
	KeyURL      string
	QRPNGBase64 string
}

// BeginMFAEnrollment generates a fresh TOTP secret and QR code and persists
// the secret on the account as "pending" — it only takes effect once
// ConfirmMFAEnrollment (a separate request, against a freshly loaded user)
// verifies the holder actually scanned it, which is why this must write the
// secret through rather than leaving it only on the in-memory user value.
func (a *AuthService) BeginMFAEnrollment(ctx context.Context, user *domain.User) (*MFAEnrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.opts.Issuer,
		AccountName: user.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: generate totp key: %w", err)
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return nil, fmt.Errorf("auth: render qr code: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("auth: encode qr code: %w", err)
	}
	user.TOTPSecret = key.Secret()
	if err := a.repo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("auth: persist pending totp secret: %w", err)
	}
	return &MFAEnrollment{
		Secret:      key.Secret(),
		KeyURL:      key.URL(),
		QRPNGBase64: base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// ConfirmMFAEnrollment verifies the first code against the pending secret
// and, on success, persists it, turns MFA on, and issues one-time recovery
// codes (returned once — the caller must display them immediately).
func (a *AuthService) ConfirmMFAEnrollment(ctx context.Context, user *domain.User, code string) ([]string, error) {
	if strings.TrimSpace(code) == "" || !totp.Validate(strings.TrimSpace(code), user.TOTPSecret) {
		return nil, domain.ErrUnauthorized
	}
	user.MFAEnabled = true
	if err := a.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	codes, err := authcrypto.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		h, err := authcrypto.HashRecoveryCode(c)
		if err != nil {
			return nil, err
		}
		hashes[i] = h
	}
	if err := a.repo.ReplaceRecoveryCodes(ctx, user.ID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// --- account management (admin only, enforced by the delivery layer) -----

// CreateUser provisions a new account with a temporary password the holder
// must change on first login.
func (a *AuthService) CreateUser(ctx context.Context, email, password string, role domain.Role) (*domain.User, error) {
	hash, err := authcrypto.HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &domain.User{Email: email, PasswordHash: hash, Role: role, MustChangePassword: true}
	if err := u.Validate(); err != nil {
		return nil, err
	}
	if err := a.repo.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsers returns every account.
func (a *AuthService) ListUsers(ctx context.Context) ([]*domain.User, error) {
	return a.repo.ListUsers(ctx)
}

// GetUser loads one account by ID.
func (a *AuthService) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return a.repo.GetUserByID(ctx, id)
}

// UpdateRole changes an account's role, refusing to demote the last admin.
// It also refuses to promote an LDAP-sourced account to admin — admin is
// always locally-granted (see AuthOptions.Settings's doc comment and
// CLAUDE.md's LDAP locked decisions): create a separate local admin account
// instead, since an LDAP-provisioned account has no usable local password
// to fall back on once it stopped authenticating via LDAP.
func (a *AuthService) UpdateRole(ctx context.Context, id uuid.UUID, role domain.Role) error {
	u, err := a.repo.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	if role == domain.RoleAdmin && u.AuthSource == domain.AuthSourceLDAP {
		return domain.Invalid("role", "an LDAP account can't be promoted to admin — create a separate local admin account instead")
	}
	if u.Role == domain.RoleAdmin && role != domain.RoleAdmin {
		if err := a.requireAnotherAdmin(ctx); err != nil {
			return err
		}
	}
	u.Role = role
	if err := u.Validate(); err != nil {
		return err
	}
	return a.repo.UpdateUser(ctx, u)
}

// ResetPassword sets a new temporary password and forces every existing
// session for the account to sign out. Refuses an LDAP-sourced account —
// its password_hash column holds an intentionally unusable placeholder (see
// lockedPasswordHash) and Login never checks it, so resetting it would look
// like it worked while changing nothing about how the account actually
// authenticates; the users admin page hides this control for such accounts
// for the same reason, this is the server-side half of that.
func (a *AuthService) ResetPassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	u, err := a.repo.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.AuthSource == domain.AuthSourceLDAP {
		return domain.Invalid("password", "this account authenticates via LDAP — its password can't be reset here")
	}
	hash, err := authcrypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.MustChangePassword = true
	if err := a.repo.UpdateUser(ctx, u); err != nil {
		return err
	}
	return a.repo.DeleteSessionsForUser(ctx, id)
}

// ResetMFA clears an account's TOTP enrollment and unused recovery codes,
// and signs it out everywhere — mirroring ResetPassword's shape. Clearing
// MFAEnabled means NeedsMFAEnrollment is true again, so the forced-onboarding
// middleware (auth_middleware.go) walks the holder straight back through
// /account/mfa/enroll on their next login, exactly like a brand-new account.
// This is for the case a device with the authenticator app is lost, stolen,
// or compromised — the old secret and any recovery codes tied to it must
// stop working, not just get supplemented by a new secret.
func (a *AuthService) ResetMFA(ctx context.Context, id uuid.UUID) error {
	u, err := a.repo.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	u.TOTPSecret = ""
	u.MFAEnabled = false
	if err := a.repo.UpdateUser(ctx, u); err != nil {
		return err
	}
	if err := a.repo.ReplaceRecoveryCodes(ctx, id, nil); err != nil {
		return err
	}
	return a.repo.DeleteSessionsForUser(ctx, id)
}

// DeleteUser removes an account, refusing to delete the last admin.
func (a *AuthService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	u, err := a.repo.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == domain.RoleAdmin {
		if err := a.requireAnotherAdmin(ctx); err != nil {
			return err
		}
	}
	if err := a.repo.DeleteSessionsForUser(ctx, id); err != nil {
		return err
	}
	return a.repo.DeleteUser(ctx, id)
}

func (a *AuthService) requireAnotherAdmin(ctx context.Context) error {
	n, err := a.repo.CountAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return domain.Invalid("role", "cannot remove the last remaining admin")
	}
	return nil
}

// --- internals -------------------------------------------------------------

func (a *AuthService) createSession(ctx context.Context, userID uuid.UUID) (*domain.Session, string, error) {
	raw, err := authcrypto.RandomToken(sessionTokenBytes)
	if err != nil {
		return nil, "", err
	}
	sess := &domain.Session{
		TokenHash: hashToken(raw),
		UserID:    userID,
		ExpiresAt: time.Now().Add(a.opts.IdleTimeout),
	}
	if err := a.repo.CreateSession(ctx, sess); err != nil {
		return nil, "", err
	}
	return sess, raw, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *AuthService) touchLastLogin(ctx context.Context, user *domain.User) {
	now := time.Now()
	user.LastLoginAt = &now
	if err := a.repo.UpdateUser(ctx, user); err != nil {
		a.log.Warn("auth: failed to record last login", "user", user.ID, "error", err)
	}
}

func (a *AuthService) recordAttempt(ctx context.Context, email, ip string, success bool, reason string) {
	if err := a.repo.RecordLoginAttempt(ctx, &domain.LoginAttempt{Email: email, IP: ip, Success: success, Reason: reason}); err != nil {
		a.log.Warn("auth: failed to record login attempt", "error", err)
	}
}

// pendingClaims is the payload of the short-lived "password verified,
// awaiting MFA" token — an HMAC-signed bearer token rather than a database
// row, since it's cheap to verify and deliberately short-lived.
type pendingClaims struct {
	UserID uuid.UUID `json:"uid"`
	Exp    int64     `json:"exp"`
}

func (a *AuthService) signPending(userID uuid.UUID) (string, error) {
	payload, err := json.Marshal(pendingClaims{UserID: userID, Exp: time.Now().Add(pendingMFATTL).Unix()})
	if err != nil {
		return "", fmt.Errorf("auth: sign pending token: %w", err)
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + a.pendingSignature(p), nil
}

func (a *AuthService) verifyPending(token string) (uuid.UUID, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return uuid.Nil, domain.ErrUnauthorized
	}
	if !hmac.Equal([]byte(a.pendingSignature(parts[0])), []byte(parts[1])) {
		return uuid.Nil, domain.ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	var claims pendingClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	if time.Now().Unix() > claims.Exp {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return claims.UserID, nil
}

func (a *AuthService) pendingSignature(payload string) string {
	mac := hmac.New(sha256.New, []byte(a.opts.SessionSecret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
