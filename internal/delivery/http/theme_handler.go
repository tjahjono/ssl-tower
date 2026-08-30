package http

import "net/http"

// themeCookieName stores the visitor's light/dark preference. Deliberately
// not tied to a session — anonymous visitors on the public dashboard/Help
// pages can toggle it too.
const themeCookieName = "theme"

// themeFromRequest reads the visitor's stored theme preference, defaulting
// to "dark" — the app's original, unchanged look — whenever the cookie is
// absent or holds anything other than "light". This is plain server-side
// rendering: <html data-theme="..."> is set from this at render time (see
// newView), so there's no client-side toggle script to write and no
// flash-of-wrong-theme on load.
func themeFromRequest(r *http.Request) string {
	c, err := r.Cookie(themeCookieName)
	if err != nil || c.Value != "light" {
		return "dark"
	}
	return "light"
}

// handleThemeToggle flips the visitor's stored preference and sends them
// back to whatever page they toggled it from. It's a plain form POST, not
// htmx — nearly every element on the page is theme-aware, so a full
// re-render is simplest. Public: no session required, same as the pages
// that carry the toggle control for an anonymous visitor.
func (s *Server) handleThemeToggle(w http.ResponseWriter, r *http.Request) {
	next := "light"
	if themeFromRequest(r) == "light" {
		next = "dark"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookieName,
		Value:    next,
		Path:     "/",
		MaxAge:   3600 * 24 * 365,
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// safeNext (auth_handler.go) is the same "same-site relative path only"
	// open-redirect guard the login flow uses — shared rather than
	// duplicated here, so a fix to the check only ever has to happen once.
	http.Redirect(w, r, safeNext(r.PostFormValue("redirect")), http.StatusSeeOther)
}
