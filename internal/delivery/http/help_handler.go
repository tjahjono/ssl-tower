package http

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// handleHelpPage renders the "how to request/renew a certificate" guide.
// Public on purpose, same as the dashboard — the body is either the
// built-in default or whatever an admin has saved through /help/edit; either
// way nothing here depends on a session to read.
func (s *Server) handleHelpPage(w http.ResponseWriter, r *http.Request) {
	content, err := s.content.HelpContent(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Help", "help")
	view["HelpContent"] = template.HTML(content.Content)
	if !content.UpdatedAt.IsZero() {
		view["HelpUpdated"] = content.UpdatedAt
		view["HelpUpdatedBy"] = content.UpdatedBy
	}
	s.render.Page(w, http.StatusOK, "help", view)
}

// handleHelpEditPage renders the admin-only editor for the Help body.
func (s *Server) handleHelpEditPage(w http.ResponseWriter, r *http.Request) {
	content, err := s.content.HelpContent(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Edit Help page", "help")
	view["Content"] = content.Content
	s.render.Page(w, http.StatusOK, "help_edit", view)
}

// handleHelpEditSubmit saves a new Help body. It's raw HTML rendered
// unescaped on a public page, so this is admin-only — the same trust an
// admin already holds over every account and certificate in the vault.
func (s *Server) handleHelpEditSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	body := r.PostFormValue("content")

	fail := func(message string) {
		view := newView(r, "Edit Help page", "help")
		view["Content"] = body
		view["Error"] = message
		s.render.Page(w, http.StatusUnprocessableEntity, "help_edit", view)
	}

	if strings.TrimSpace(body) == "" {
		fail("Content can't be empty.")
		return
	}

	user := s.currentUser(r)
	saved, err := s.content.SetHelpContent(r.Context(), body, user.Email)
	if err != nil {
		fail("Could not save — try again.")
		return
	}
	s.recordAudit(r, domain.AuditHelpContentUpdated, "site_content", domain.SiteContentHelp, "")

	view := newView(r, "Edit Help page", "help")
	view["Content"] = saved.Content
	view["Success"] = "Saved."
	s.render.Page(w, http.StatusOK, "help_edit", view)
}
