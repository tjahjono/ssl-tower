package http

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

const mfaPendingCookieName = "mfa_pending"

// handleLoginPage renders the sign-in form. A signed-in visitor is bounced
// straight to their destination instead of seeing it again.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	view := newView(r, "Sign in", "")
	view["Next"] = safeNext(r.URL.Query().Get("next"))
	if r.URL.Query().Get("notice") == "password_changed" {
		view["Notice"] = "Password changed — sign in with your new password."
	}
	s.render.Page(w, http.StatusOK, "login", view)
}

// handleLoginSubmit verifies email and password. Correct credentials on an
// MFA-enabled account get a short-lived pending cookie and a trip to the code
// challenge; everyone else gets a session immediately (the onboarding check
// then takes over if MFA still needs enrolling).
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	email := r.PostFormValue("email")
	step, err := s.auth.Login(r.Context(), email, r.PostFormValue("password"), clientIP(r))
	if err != nil {
		s.audit.Record(r.Context(), nil, email, domain.AuditLoginFailed, "user", "", err.Error(), clientIP(r))
		s.renderLoginError(w, r, next, "Incorrect email or password.")
		return
	}

	if step.PendingToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name: mfaPendingCookieName, Value: step.PendingToken, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure, Expires: time.Now().Add(5 * time.Minute),
		})
		dest := "/login/mfa"
		if next != "/" {
			dest += "?next=" + next
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	setSessionCookie(w, step.RawToken, s.cookieSecure, time.Now().Add(12*time.Hour))
	s.audit.Record(r.Context(), &step.User.ID, step.User.Email, domain.AuditLoginSuccess, "user", step.User.ID.String(), "", clientIP(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, next, message string) {
	view := newView(r, "Sign in", "")
	view["Next"] = next
	view["Error"] = message
	s.render.Page(w, http.StatusUnauthorized, "login", view)
}

// handleMFAChallengePage renders the code-entry form for a login that passed
// the password step and is waiting on TOTP or a recovery code.
func (s *Server) handleMFAChallengePage(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(mfaPendingCookieName); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	view := newView(r, "Verification code", "")
	view["Next"] = safeNext(r.URL.Query().Get("next"))
	s.render.Page(w, http.StatusOK, "mfa_challenge", view)
}

// handleMFAChallengeSubmit completes a pending login with a TOTP or recovery code.
func (s *Server) handleMFAChallengeSubmit(w http.ResponseWriter, r *http.Request) {
	pending, err := r.Cookie(mfaPendingCookieName)
	if err != nil || pending.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))

	step, err := s.auth.VerifyMFA(r.Context(), pending.Value, r.PostFormValue("code"), clientIP(r))
	if err != nil {
		view := newView(r, "Verification code", "")
		view["Next"] = next
		view["Error"] = "That code didn't work. Check your authenticator app, or use a recovery code."
		s.render.Page(w, http.StatusUnauthorized, "mfa_challenge", view)
		return
	}

	clearCookie(w, mfaPendingCookieName, s.cookieSecure)
	setSessionCookie(w, step.RawToken, s.cookieSecure, time.Now().Add(12*time.Hour))
	s.audit.Record(r.Context(), &step.User.ID, step.User.Email, domain.AuditLoginSuccess, "user", step.User.ID.String(), "mfa", clientIP(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// handleLogout ends the current session, wherever the request came from.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		_ = s.auth.Logout(r.Context(), c.Value)
	}
	if u := s.currentUser(r); u != nil {
		s.recordAudit(r, domain.AuditLogout, "user", u.ID.String(), "")
	}
	clearCookie(w, sessionCookieName, s.cookieSecure)
	redirectOrHXRedirect(w, r, "/")
}

// handlePasswordChangePage renders the change-password form — reached either
// voluntarily or because onboarding forced it after a fresh account or an
// admin reset.
func (s *Server) handlePasswordChangePage(w http.ResponseWriter, r *http.Request) {
	view := newView(r, "Change password", "")
	view["Forced"] = s.currentUser(r).NeedsPasswordChange()
	s.render.Page(w, http.StatusOK, "change_password", view)
}

// handlePasswordChangeSubmit verifies the current password, applies the new
// one, and signs the user out everywhere — including this request — so they
// come back in with the password they just set.
func (s *Server) handlePasswordChangeSubmit(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	current := r.PostFormValue("current_password")
	next1 := r.PostFormValue("new_password")
	next2 := r.PostFormValue("confirm_password")

	fail := func(message string) {
		view := newView(r, "Change password", "")
		view["Forced"] = user.NeedsPasswordChange()
		view["Error"] = message
		s.render.Page(w, http.StatusUnprocessableEntity, "change_password", view)
	}

	if !s.auth.CheckPassword(user, current) {
		fail("Current password is incorrect.")
		return
	}
	if len(next1) < 10 {
		fail("New password must be at least 10 characters.")
		return
	}
	if next1 != next2 {
		fail("New password and confirmation don't match.")
		return
	}
	if err := s.auth.ChangePassword(r.Context(), user.ID, next1); err != nil {
		s.serverError(w, err)
		return
	}
	s.recordAudit(r, domain.AuditPasswordChanged, "user", user.ID.String(), "self-service")
	clearCookie(w, sessionCookieName, s.cookieSecure)
	redirectOrHXRedirect(w, r, "/login?notice=password_changed")
}

// handleMFAEnrollPage generates (or regenerates) a pending TOTP secret and
// shows its QR code. Reloading the page issues a fresh secret, invalidating
// any not-yet-confirmed one — expected, since the old QR is presumably still
// unscanned.
func (s *Server) handleMFAEnrollPage(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	if user.MFAEnabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	enrollment, err := s.auth.BeginMFAEnrollment(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Set up two-factor authentication", "")
	view["Enrollment"] = enrollment
	s.render.Page(w, http.StatusOK, "mfa_enroll", view)
}

// handleMFAEnrollSubmit confirms the first code from the authenticator app,
// turns MFA on, and shows the one-time recovery codes exactly once.
func (s *Server) handleMFAEnrollSubmit(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	codes, err := s.auth.ConfirmMFAEnrollment(r.Context(), user, r.PostFormValue("code"))
	if err != nil {
		// Regenerate rather than reuse — a fresh QR the user can scan again
		// beats re-showing one that either they mistyped or already tried.
		enrollment, genErr := s.auth.BeginMFAEnrollment(r.Context(), user)
		if genErr != nil {
			s.serverError(w, genErr)
			return
		}
		view := newView(r, "Set up two-factor authentication", "")
		view["Enrollment"] = enrollment
		view["Error"] = "That code didn't match. Scan the (refreshed) QR code again and try the latest 6-digit code."
		s.render.Page(w, http.StatusUnprocessableEntity, "mfa_enroll", view)
		return
	}
	s.recordAudit(r, domain.AuditMFAEnrolled, "user", user.ID.String(), "")
	view := newView(r, "Recovery codes", "")
	view["RecoveryCodes"] = codes
	s.render.Page(w, http.StatusOK, "mfa_recovery_codes", view)
}

// --- helpers ---------------------------------------------------------------

// safeNext keeps an open-redirect out of the login flow: only a path
// beginning with a single "/" (never "//", which browsers treat as
// protocol-relative to another host) is accepted.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if first, _, ok := strings.Cut(fwd, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(fwd)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
