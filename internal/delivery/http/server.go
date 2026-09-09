// Package http is the delivery layer: routing, request decoding, and HTML
// rendering. It talks to the service layer and knows nothing about SQL.
package http

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/service"
)

// Server wires the HTTP routes to the service layer.
type Server struct {
	mux          *http.ServeMux
	render       *Renderer
	certs        *service.CertificateService
	sweeper      *service.AlertSweeper
	auth         *service.AuthService
	audit        *service.AuditService
	content      *service.SiteContentService
	requests     *service.CertificateRequestService
	digicert     *service.DigiCertService
	settings     *service.SettingsService
	log          *slog.Logger
	cookieSecure bool
}

// NewServer builds the router.
func NewServer(
	certs *service.CertificateService,
	sweeper *service.AlertSweeper,
	auth *service.AuthService,
	audit *service.AuditService,
	content *service.SiteContentService,
	requests *service.CertificateRequestService,
	digicertSvc *service.DigiCertService,
	settings *service.SettingsService,
	log *slog.Logger,
	cookieSecure bool,
) (*Server, error) {
	renderer, err := NewRenderer()
	if err != nil {
		return nil, err
	}
	s := &Server{
		mux:          http.NewServeMux(),
		render:       renderer,
		certs:        certs,
		sweeper:      sweeper,
		auth:         auth,
		audit:        audit,
		content:      content,
		requests:     requests,
		digicert:     digicertSvc,
		settings:     settings,
		log:          log,
		cookieSecure: cookieSecure,
	}
	s.routes()
	return s, nil
}

// Handler returns the fully decorated http.Handler. Order matters: recovery
// and logging wrap everything, then security headers, then CSRF (which must
// see every mutating request, authenticated or not — the login form
// included), then session loading, then the mux itself.
func (s *Server) Handler() http.Handler {
	return recoverer(s.log)(requestLogger(s.log)(securityHeaders(
		csrfProtect(s.cookieSecure)(s.loadSession(s.mux)),
	)))
}

func (s *Server) routes() {
	static, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", cacheForever(http.FileServer(http.FS(static)))))

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Dashboard and Help are the only pages reachable without a session.
	// The dashboard's own auto-refresh partial (/summary) has to stay public
	// alongside it, or the tiles would stop live-updating for an anonymous
	// visitor. Help is static prose — how to request/renew a certificate —
	// public on purpose so anyone in the org can read it without an account
	// before ever asking for editor access.
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /summary", s.handleSummaryPartial)
	s.mux.HandleFunc("GET /help", s.handleHelpPage)
	s.mux.HandleFunc("GET /help/edit", s.requireAdmin(s.handleHelpEditPage))
	s.mux.HandleFunc("POST /help/edit", s.requireAdmin(s.handleHelpEditSubmit))

	// Certificate vault — every route needs a session, reads included
	// (certificates carry private key material); only editor/admin can
	// create, import, attach, sign, or delete one. Downloads are gated
	// further, per format, inside the handler itself — see
	// handleCertificateDownload.
	s.mux.HandleFunc("GET /certificates", s.requireAuth(s.handleCertificatesPage))
	s.mux.HandleFunc("GET /certificates/list", s.requireAuth(s.handleCertificateList))
	s.mux.HandleFunc("GET /certificates/issuers", s.requireAuth(s.handleCertificateIssuers))
	// Root CA management (v1.1) — admin-only, same tier as chain editing and
	// private-key downloads: a Root CA's key can mint a certificate for any
	// name, which is a materially bigger blast radius than any single
	// certificate's own key.
	s.mux.HandleFunc("POST /certificates/issuers/root-cas", s.requireAdmin(s.handleRootCAUpload))
	s.mux.HandleFunc("POST /certificates/issuers/root-cas/generate", s.requireAdmin(s.handleRootCAGenerate))
	s.mux.HandleFunc("DELETE /certificates/issuers/root-cas/{id}", s.requireAdmin(s.handleRootCADelete))
	s.mux.HandleFunc("POST /certificates/generate", s.requireWrite(s.handleCertificateGenerate))
	s.mux.HandleFunc("POST /certificates/import", s.requireWrite(s.handleCertificateImport))
	s.mux.HandleFunc("POST /certificates/import-csr", s.requireWrite(s.handleCertificateImportCSR))
	s.mux.HandleFunc("POST /certificates/import-pfx", s.requireWrite(s.handleCertificateImportPFX))
	s.mux.HandleFunc("GET /certificates/{id}", s.requireAuth(s.handleCertificateDetail))
	s.mux.HandleFunc("DELETE /certificates/{id}", s.requireWrite(s.handleCertificateDelete))
	s.mux.HandleFunc("POST /certificates/{id}/certificate", s.requireWrite(s.handleCertificateAttach))
	s.mux.HandleFunc("POST /certificates/{id}/chain", s.requireAdmin(s.handleCertificateChainUpdate))
	s.mux.HandleFunc("POST /certificates/{id}/validate", s.requireWrite(s.handleCertificateValidate))
	s.mux.HandleFunc("POST /certificates/{id}/issue", s.requireWrite(s.handleCertificateIssue))
	s.mux.HandleFunc("GET /certificates/{id}/download", s.requireAuth(s.handleCertificateDownload))

	// Authentication
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /login/mfa", s.handleMFAChallengePage)
	s.mux.HandleFunc("POST /login/mfa", s.handleMFAChallengeSubmit)
	s.mux.HandleFunc("POST /logout", s.handleLogout)

	// Forced onboarding + self-service account pages — any signed-in user.
	s.mux.HandleFunc("GET /account/password", s.requireAuth(s.handlePasswordChangePage))
	s.mux.HandleFunc("POST /account/password", s.requireAuth(s.handlePasswordChangeSubmit))
	s.mux.HandleFunc("GET /account/mfa/enroll", s.requireAuth(s.handleMFAEnrollPage))
	s.mux.HandleFunc("POST /account/mfa/enroll", s.requireAuth(s.handleMFAEnrollSubmit))

	// User management — admin only.
	s.mux.HandleFunc("GET /users", s.requireAdmin(s.handleUsersPage))
	s.mux.HandleFunc("POST /users", s.requireAdmin(s.handleUserCreate))
	s.mux.HandleFunc("POST /users/{id}/role", s.requireAdmin(s.handleUserRoleUpdate))
	s.mux.HandleFunc("POST /users/{id}/reset-password", s.requireAdmin(s.handleUserResetPassword))
	s.mux.HandleFunc("POST /users/{id}/reset-mfa", s.requireAdmin(s.handleUserResetMFA))
	s.mux.HandleFunc("DELETE /users/{id}", s.requireAdmin(s.handleUserDelete))

	// Audit log — admin only.
	s.mux.HandleFunc("GET /audit", s.requireAdmin(s.handleAuditPage))
	s.mux.HandleFunc("GET /audit/list", s.requireAdmin(s.handleAuditList))

	// Technical docs — admin only.
	s.mux.HandleFunc("GET /admin/docs", s.requireAdmin(s.handleAdminDocsPage))

	// Settings (v1.5) — admin only, same tier as Root CA management and
	// chain editing: these govern alerting/ticket behavior app-wide, and the
	// encryption-key section on the same page can re-encrypt every stored
	// private key.
	s.mux.HandleFunc("GET /settings", s.requireAdmin(s.handleSettingsPage))
	s.mux.HandleFunc("POST /settings", s.requireAdmin(s.handleSettingsSubmit))
	s.mux.HandleFunc("POST /settings/encryption-key", s.requireAdmin(s.handleSettingsEncryptionKeyRotate))
	s.mux.HandleFunc("GET /settings/encryption-key/status/{id}", s.requireAdmin(s.handleSettingsEncryptionKeyStatus))

	// Theme preference — public, cosmetic, no session needed.
	s.mux.HandleFunc("POST /theme", s.handleThemeToggle)

	// Certificate request tickets (v1.2) — requesters submit and view their
	// own tickets (and everyone else's, per the confirmed "all tickets"
	// visibility); editors/admins work the queue.
	s.mux.HandleFunc("GET /requests", s.requireRequester(s.handleRequestsPage))
	s.mux.HandleFunc("GET /requests/list", s.requireRequester(s.handleRequestsList))
	s.mux.HandleFunc("POST /requests", s.requireRequester(s.handleRequestSubmit))
	s.mux.HandleFunc("POST /requests/{id}/cancel", s.requireAuth(s.handleRequestCancel))

	s.mux.HandleFunc("GET /tickets", s.requireWrite(s.handleTicketsPage))
	s.mux.HandleFunc("GET /tickets/list", s.requireWrite(s.handleTicketsList))
	s.mux.HandleFunc("GET /tickets/{id}", s.requireWrite(s.handleTicketDetail))
	s.mux.HandleFunc("POST /tickets/{id}/approve-internal", s.requireWrite(s.handleTicketApproveInternal))
	s.mux.HandleFunc("POST /tickets/{id}/approve-external", s.requireWrite(s.handleTicketApproveExternal))
	s.mux.HandleFunc("POST /tickets/{id}/fulfill-external", s.requireWrite(s.handleTicketFulfillExternal))
	s.mux.HandleFunc("POST /tickets/{id}/generate-csr", s.requireWrite(s.handleTicketGenerateCSR))
	s.mux.HandleFunc("POST /tickets/{id}/reject", s.requireWrite(s.handleTicketReject))
	s.mux.HandleFunc("POST /tickets/{id}/cancel", s.requireWrite(s.handleRequestCancel))
	s.mux.HandleFunc("POST /tickets/{id}/deliver", s.requireWrite(s.handleTicketDeliver))
	s.mux.HandleFunc("POST /tickets/{id}/send-email", s.requireWrite(s.handleTicketSendEmail))
	s.mux.HandleFunc("POST /tickets/{id}/digicert/submit", s.requireWrite(s.handleTicketDigiCertSubmit))
	s.mux.HandleFunc("POST /tickets/{id}/digicert/check-status", s.requireWrite(s.handleTicketDigiCertCheckStatus))
}

// --- shared view helpers ---------------------------------------------------

func newView(r *http.Request, title, nav string) map[string]any {
	var user *domain.User
	if s, ok := r.Context().Value(ctxUser).(*domain.User); ok {
		user = s
	}
	return map[string]any{
		"Title":       title,
		"Nav":         nav,
		"Now":         time.Now().UTC(),
		"User":        user,
		"CSRFToken":   csrfTokenFor(r),
		"Theme":       themeFromRequest(r),
		"CurrentPath": r.URL.RequestURI(),
	}
}

type flashMessage struct {
	Kind    string // success | error | info
	Message string
}

// recordAudit logs one action to the admin-facing audit trail, attributing it
// to whoever is signed in on r (nil for an anonymous action such as a failed
// login) and the request's client IP. Safe to call unconditionally — a write
// failure only logs a server-side error and never disturbs the response.
func (s *Server) recordAudit(r *http.Request, action, targetType, targetID, detail string) {
	var actorID *uuid.UUID
	actorEmail := ""
	if u := s.currentUser(r); u != nil {
		id := u.ID
		actorID = &id
		actorEmail = u.Email
	}
	s.audit.Record(r.Context(), actorID, actorEmail, action, targetType, targetID, detail, clientIP(r))
}

// flashOOB renders a flash banner as an out-of-band htmx swap.
func (s *Server) flashOOB(w http.ResponseWriter, kind, message string) {
	s.render.Partial(w, http.StatusOK, "flash-oob", &flashMessage{Kind: kind, Message: message})
}

// parseID pulls a UUID path value, writing a 400 when it is malformed.
func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

// errorMessage turns a service error into something worth showing a user.
func errorMessage(err error) (string, int) {
	if ve, ok := domain.AsValidation(err); ok {
		return ve.Message, http.StatusUnprocessableEntity
	}
	if errors.Is(err, domain.ErrConflict) {
		// Show the human half of "<detail>: resource already exists".
		return strings.TrimSuffix(err.Error(), ": "+domain.ErrConflict.Error()), http.StatusConflict
	}
	if errors.Is(err, domain.ErrNotFound) {
		return "not found", http.StatusNotFound
	}
	return err.Error(), http.StatusInternalServerError
}

// isHTMX reports whether the request came from htmx rather than the address bar.
func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// shutdownTimeout bounds graceful shutdown from cmd/server.
const shutdownTimeout = 15 * time.Second

// Serve runs the HTTP server until ctx is cancelled, then drains connections.
func (s *Server) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("http server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		s.log.Info("http server shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}
