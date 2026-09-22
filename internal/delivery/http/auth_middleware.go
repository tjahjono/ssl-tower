package http

import (
	"context"
	"crypto/hmac"
	"net/http"
	"net/url"
	"time"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/authcrypto"
)

type contextKey int

const (
	ctxUser contextKey = iota
	ctxCSRF
)

const (
	sessionCookieName = "session"
	csrfCookieName    = "csrf_token"
)

// currentUser reads the authenticated user attached by loadSession, or nil
// for an anonymous request — the dashboard, the only public route, works
// fine with a nil user.
func (s *Server) currentUser(r *http.Request) *domain.User {
	u, _ := r.Context().Value(ctxUser).(*domain.User)
	return u
}

// csrfTokenFor renders the token the current request's forms and htmx
// requests should embed. Always non-empty once csrfProtect has run.
func csrfTokenFor(r *http.Request) string {
	tok, _ := r.Context().Value(ctxCSRF).(string)
	return tok
}

// loadSession attaches the signed-in user (if any) to the request context.
// It never blocks a request on its own — requireAuth/requireWrite/requireAdmin
// do that for the specific routes that need it, which is what keeps the
// dashboard reachable without a session.
func (s *Server) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, err := s.auth.ValidateSession(r.Context(), c.Value)
		if err != nil {
			clearCookie(w, sessionCookieName, s.cookieSecure)
			next.ServeHTTP(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, user))
		next.ServeHTTP(w, r)
	})
}

// csrfProtect implements the double-submit-cookie pattern: every response
// carries a random token cookie, and every mutating request must echo that
// same value back via header or hidden field. It runs before authentication
// so the login form itself is protected too, not just routes behind it.
func csrfProtect(cookieSecure bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, existing := "", false
			if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
				token, existing = c.Value, true
			}
			if !existing {
				tok, err := authcrypto.RandomToken(32)
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				token = tok
				http.SetCookie(w, &http.Cookie{
					Name: csrfCookieName, Value: token, Path: "/", HttpOnly: true,
					SameSite: http.SameSiteLaxMode, Secure: cookieSecure,
					Expires: time.Now().Add(180 * 24 * time.Hour),
				})
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxCSRF, token))

			if !safeMethod(r.Method) {
				submitted := r.Header.Get("X-CSRF-Token")
				if submitted == "" {
					_ = r.ParseForm()
					submitted = r.PostFormValue("csrf_token")
				}
				if submitted == "" || !hmac.Equal([]byte(submitted), []byte(token)) {
					http.Error(w, "invalid or missing CSRF token — reload the page and try again", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// requireAuth redirects an anonymous request to the login page (or, for an
// htmx request, issues an HX-Redirect so the client-side navigation still
// lands there), preserving the original destination as ?next=. It also
// forces any pending onboarding step — a required password change or MFA
// enrollment — ahead of the request the user actually asked for.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := s.currentUser(r)
		if user == nil {
			redirectToLogin(w, r)
			return
		}
		if redirected := s.enforceOnboarding(w, r, user); redirected {
			return
		}
		next(w, r)
	}
}

// requireWrite additionally demands editor or admin — the "read-write"
// half of the role model.
func (s *Server) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !s.currentUser(r).Role.CanWrite() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	})
}

// requireAdmin additionally demands the admin role — user management only.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !s.currentUser(r).Role.CanManageUsers() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	})
}

// requireRequester additionally demands the requester role — the
// self-service "submit a certificate request ticket" pages. Deliberately
// exclusive to that tier: an admin/editor works tickets from the /tickets
// queue instead, which talks to the same CertificateRequestService but
// through the approve/reject/fulfill actions rather than submission.
func (s *Server) requireRequester(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !s.currentUser(r).Role.CanRequestCertificates() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	})
}

// onboardingRedirectPath names the forced onboarding step a user still owes,
// in order (password change before MFA enrollment) — "" once both are done.
// Shared by enforceOnboarding (every subsequent request to a requireAuth
// route) and the login handlers themselves (auth_handler.go), so a freshly
// authenticated user lands on the right page immediately rather than only on
// their next navigation to a protected route.
func onboardingRedirectPath(user *domain.User) string {
	switch {
	case user.NeedsPasswordChange():
		return "/account/password"
	case user.NeedsMFAEnrollment():
		return "/account/mfa/enroll"
	default:
		return ""
	}
}

// enforceOnboarding sends a signed-in user straight to the forced step they
// haven't completed yet, whatever page they actually asked for. Returns true
// when it redirected (the caller must stop handling the request).
func (s *Server) enforceOnboarding(w http.ResponseWriter, r *http.Request, user *domain.User) bool {
	dest := onboardingRedirectPath(user)
	if dest == "" || r.URL.Path == dest {
		return false
	}
	redirectOrHXRedirect(w, r, dest)
	return true
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Path
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	dest := "/login"
	if next != "" && next != "/login" {
		dest += "?next=" + url.QueryEscape(next)
	}
	redirectOrHXRedirect(w, r, dest)
}

func redirectOrHXRedirect(w http.ResponseWriter, r *http.Request, dest string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", dest)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "your role does not permit this action", http.StatusForbidden)
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure,
		MaxAge: -1, Expires: time.Unix(0, 0),
	})
}

func setSessionCookie(w http.ResponseWriter, rawToken string, secure bool, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: rawToken, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure, Expires: expiresAt,
	})
}
