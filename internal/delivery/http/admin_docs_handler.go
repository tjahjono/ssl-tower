package http

import "net/http"

// handleAdminDocsPage renders the admin-only technical reference: how the
// app is layered, and the exact handler → service → repository call chain
// behind each major action. Static content, no database reads — this is
// documentation about the code, not data from it, so unlike Help there's no
// admin-editable version of it (editing it means editing the page itself).
func (s *Server) handleAdminDocsPage(w http.ResponseWriter, r *http.Request) {
	view := newView(r, "Technical docs", "admin-docs")
	s.render.Page(w, http.StatusOK, "admin_docs", view)
}
