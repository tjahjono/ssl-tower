package http

import (
	"net/http"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// handleUsersPage renders the admin-only account management panel.
func (s *Server) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	users, err := s.auth.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "Users", "users")
	view["Users"] = users
	s.render.Page(w, http.StatusOK, "users", view)
}

// handleUserCreate provisions a new account with a temporary password the
// holder must change on first login.
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	role := domain.Role(r.PostFormValue("role"))
	password := r.PostFormValue("password")
	if len(password) < 10 {
		s.usersTableResponse(w, r, &flashMessage{Kind: "error", Message: "Temporary password must be at least 10 characters."})
		return
	}

	flash := &flashMessage{Kind: "success"}
	if created, err := s.auth.CreateUser(r.Context(), r.PostFormValue("email"), password, role); err != nil {
		msg, _ := errorMessage(err)
		flash = &flashMessage{Kind: "error", Message: msg}
	} else {
		flash.Message = "Account created — share the temporary password securely; they'll be forced to change it and enroll MFA on first login."
		s.recordAudit(r, domain.AuditUserCreated, "user", created.ID.String(), string(role))
	}
	s.usersTableResponse(w, r, flash)
}

// handleUserRoleUpdate changes an account's role, refusing to demote the
// last remaining admin.
func (s *Server) handleUserRoleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	role := domain.Role(r.PostFormValue("role"))
	flash := &flashMessage{Kind: "success", Message: "Role updated."}
	if err := s.auth.UpdateRole(r.Context(), id, role); err != nil {
		msg, _ := errorMessage(err)
		flash = &flashMessage{Kind: "error", Message: msg}
	} else {
		s.recordAudit(r, domain.AuditUserRoleChanged, "user", id.String(), string(role))
	}
	s.usersTableResponse(w, r, flash)
}

// handleUserResetPassword issues a new temporary password and forces every
// existing session for the account to sign out.
func (s *Server) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	password := r.PostFormValue("password")
	if len(password) < 10 {
		s.usersTableResponse(w, r, &flashMessage{Kind: "error", Message: "Temporary password must be at least 10 characters."})
		return
	}
	flash := &flashMessage{Kind: "success", Message: "Password reset — the account is signed out everywhere and must set a new one at next login."}
	if err := s.auth.ResetPassword(r.Context(), id, password); err != nil {
		msg, _ := errorMessage(err)
		flash = &flashMessage{Kind: "error", Message: msg}
	} else {
		s.recordAudit(r, domain.AuditUserPasswordReset, "user", id.String(), "")
	}
	s.usersTableResponse(w, r, flash)
}

// handleUserResetMFA clears an account's MFA enrollment, forcing it back
// through setup at next login, and signs it out everywhere in the meantime.
func (s *Server) handleUserResetMFA(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	flash := &flashMessage{Kind: "success", Message: "MFA reset — the account is signed out everywhere and must enroll a new authenticator at next login."}
	if err := s.auth.ResetMFA(r.Context(), id); err != nil {
		msg, _ := errorMessage(err)
		flash = &flashMessage{Kind: "error", Message: msg}
	} else {
		s.recordAudit(r, domain.AuditUserMFAReset, "user", id.String(), "")
	}
	s.usersTableResponse(w, r, flash)
}

// handleUserDelete removes an account, refusing to delete the last admin.
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	flash := &flashMessage{Kind: "info", Message: "Account removed."}
	if err := s.auth.DeleteUser(r.Context(), id); err != nil {
		msg, _ := errorMessage(err)
		flash = &flashMessage{Kind: "error", Message: msg}
	} else {
		s.recordAudit(r, domain.AuditUserDeleted, "user", id.String(), "")
	}
	s.usersTableResponse(w, r, flash)
}

func (s *Server) usersTableResponse(w http.ResponseWriter, r *http.Request, flash *flashMessage) {
	users, err := s.auth.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	view := newView(r, "", "")
	view["Users"] = users
	view["Flash"] = flash
	s.render.Partial(w, http.StatusOK, "user-table-response", view)
}
