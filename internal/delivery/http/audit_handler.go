package http

import (
	"net/http"
	"time"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// handleAuditPage renders the admin-only audit trail with its filter form.
func (s *Server) handleAuditPage(w http.ResponseWriter, r *http.Request) {
	filter := auditFilterFrom(r)
	entries, err := s.audit.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	actions, err := s.audit.Actions(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Audit log", "audit")
	view["Entries"] = entries
	view["Actions"] = actions
	view["Filter"] = filter
	s.render.Page(w, http.StatusOK, "audit", view)
}

// handleAuditList returns just the table, for the filter form's htmx polling.
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	filter := auditFilterFrom(r)
	entries, err := s.audit.List(r.Context(), filter)
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "", "")
	view["Entries"] = entries
	view["Filter"] = filter
	s.render.Partial(w, http.StatusOK, "audit-table", view)
}

// auditFilterFrom reads the filter form's query params. Since/Until accept a
// plain YYYY-MM-DD (an HTML date input's format) — an unparseable or empty
// value just leaves that bound off.
func auditFilterFrom(r *http.Request) domain.AuditFilter {
	q := r.URL.Query()
	f := domain.AuditFilter{
		ActorEmail: q.Get("actor"),
		Action:     q.Get("action"),
	}
	if since, err := time.Parse("2006-01-02", q.Get("since")); err == nil {
		f.Since = since
	}
	if until, err := time.Parse("2006-01-02", q.Get("until")); err == nil {
		// Inclusive of the whole day.
		f.Until = until.Add(24*time.Hour - time.Nanosecond)
	}
	return f
}
