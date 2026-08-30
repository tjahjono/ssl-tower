package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// handleSettingsPage renders the admin-only /settings page: the general
// operational settings form (expiry thresholds, SMTP, Teams, ticket SLA)
// plus the separate encryption-key danger zone. Admin-only — same tier as
// Root CA management and chain editing, since these settings govern
// alerting/ticket behavior app-wide, and the encryption key section on the
// same page can re-encrypt every stored private key.
func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	view := s.settingsView(r)
	s.render.Page(w, http.StatusOK, "settings", view)
}

// settingsView builds the shared view data both the page render and a
// failed-submit re-render need.
func (s *Server) settingsView(r *http.Request) map[string]any {
	cur := s.settings.Current()
	view := newView(r, "Settings", "settings")
	view["Settings"] = cur
	view["AlertEmailToText"] = strings.Join(cur.AlertEmailTo, ", ")
	view["EncryptionEnabled"] = s.certs.KeyEncryptionEnabled()
	// One DN per line, not comma- or semicolon-joined — a textarea is the
	// natural shape for a list of DNs, and it sidesteps the comma-inside-a-
	// DN problem entirely (see splitLines's doc comment) rather than asking
	// an admin to remember a delimiter convention.
	view["LDAPRoleMapEditorText"] = strings.Join(cur.LDAPRoleMapEditor, "\n")
	view["LDAPRoleMapViewerText"] = strings.Join(cur.LDAPRoleMapViewer, "\n")
	view["LDAPRoleMapRequesterText"] = strings.Join(cur.LDAPRoleMapRequester, "\n")
	return view
}

// handleSettingsSubmit saves the general settings form. SMTPPassword and
// TeamsWebhookURL are write-only fields in the UI (never pre-filled with
// the real stored value) — a blank submission keeps whatever is already
// stored, and the "clear" checkbox is the only way to explicitly wipe one,
// so an admin can't accidentally erase a working secret just by loading and
// re-saving the page.
func (s *Server) handleSettingsSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	fail := func(message string) {
		view := s.settingsView(r)
		view["Error"] = message
		s.render.Page(w, http.StatusUnprocessableEntity, "settings", view)
	}

	current := s.settings.Current()

	warningDays, err := strconv.Atoi(r.PostFormValue("expiry_warning_days"))
	if err != nil {
		fail("Warning threshold must be a whole number of days.")
		return
	}
	criticalDays, err := strconv.Atoi(r.PostFormValue("expiry_critical_days"))
	if err != nil {
		fail("Critical threshold must be a whole number of days.")
		return
	}
	finalDays, err := strconv.Atoi(r.PostFormValue("expiry_final_days"))
	if err != nil {
		fail("Final-notice threshold must be a whole number of days.")
		return
	}
	smtpPort, err := strconv.Atoi(r.PostFormValue("smtp_port"))
	if err != nil {
		fail("SMTP port must be a whole number.")
		return
	}
	ticketSLADays, err := strconv.Atoi(r.PostFormValue("ticket_sla_days"))
	if err != nil {
		fail("Ticket SLA must be a whole number of days.")
		return
	}

	smtpPassword := current.SMTPPassword
	if r.PostFormValue("smtp_password_clear") == "on" {
		smtpPassword = ""
	} else if v := r.PostFormValue("smtp_password"); v != "" {
		smtpPassword = v
	}
	teamsWebhookURL := current.TeamsWebhookURL
	if r.PostFormValue("teams_webhook_url_clear") == "on" {
		teamsWebhookURL = ""
	} else if v := strings.TrimSpace(r.PostFormValue("teams_webhook_url")); v != "" {
		teamsWebhookURL = v
	}

	// ldap_bind_password is write-only, same pattern as smtp_password above:
	// never pre-filled with the real stored value, a blank submission keeps
	// what's already stored, and the clear checkbox is the only way to wipe
	// it — so a routine settings save can't silently erase a working LDAP
	// service-account credential.
	ldapBindPassword := current.LDAPBindPassword
	if r.PostFormValue("ldap_bind_password_clear") == "on" {
		ldapBindPassword = ""
	} else if v := r.PostFormValue("ldap_bind_password"); v != "" {
		ldapBindPassword = v
	}

	patch := domain.AppSettings{
		ExpiryWarningDays:  warningDays,
		ExpiryCriticalDays: criticalDays,
		ExpiryFinalDays:    finalDays,
		SMTPHost:           strings.TrimSpace(r.PostFormValue("smtp_host")),
		SMTPPort:           smtpPort,
		SMTPUsername:       strings.TrimSpace(r.PostFormValue("smtp_username")),
		SMTPPassword:       smtpPassword,
		AlertEmailFrom:     strings.TrimSpace(r.PostFormValue("alert_email_from")),
		AlertEmailTo:       splitTrimmedList(r.PostFormValue("alert_email_to")),
		TeamsWebhookURL:    teamsWebhookURL,
		TicketSLADays:      ticketSLADays,

		LDAPURL:          strings.TrimSpace(r.PostFormValue("ldap_url")),
		LDAPBindDN:       strings.TrimSpace(r.PostFormValue("ldap_bind_dn")),
		LDAPBindPassword: ldapBindPassword,
		LDAPBaseDN:       strings.TrimSpace(r.PostFormValue("ldap_base_dn")),
		LDAPUserFilter:   strings.TrimSpace(r.PostFormValue("ldap_user_filter")),
		LDAPGroupFilter:  strings.TrimSpace(r.PostFormValue("ldap_group_filter")),

		LDAPRoleMapEditor:    splitLines(r.PostFormValue("ldap_role_map_editor")),
		LDAPRoleMapViewer:    splitLines(r.PostFormValue("ldap_role_map_viewer")),
		LDAPRoleMapRequester: splitLines(r.PostFormValue("ldap_role_map_requester")),
	}

	user := s.currentUser(r)
	if err := s.settings.Update(r.Context(), patch, user.Email); err != nil {
		msg, _ := errorMessage(err)
		fail(msg)
		return
	}
	s.recordAudit(r, domain.AuditSettingsUpdated, "app_settings", "", "")

	view := s.settingsView(r)
	view["Success"] = "Settings saved."
	s.render.Page(w, http.StatusOK, "settings", view)
}

// handleSettingsEncryptionKeyRotate is the danger-zone action: change the
// vault's encryption key and atomically re-encrypt every stored private
// key. Rendered via htmx (hx-confirm on the form) rather than the plain
// full-page POST the general settings form uses, so the confirmation
// prompt and the re-rendered section can happen without a full navigation.
//
// v1.7: this only starts the rotation and immediately returns a progress
// view that polls handleSettingsEncryptionKeyStatus — a rotation over a
// large vault is a real, multi-second database transaction (see
// EncryptionRotationRepository), and the previous fully-synchronous
// request/response left the admin staring at a frozen button with no sign
// anything was happening, which is exactly what prompted this.
func (s *Server) handleSettingsEncryptionKeyRotate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	newKey := strings.TrimSpace(r.PostFormValue("encryption_key"))

	jobID, err := s.certs.StartEncryptionKeyRotation(newKey)
	if err != nil {
		msg, _ := errorMessage(err)
		view := s.settingsView(r)
		view["Flash"] = &flashMessage{Kind: "error", Message: msg}
		s.render.Partial(w, http.StatusOK, "settings-encryption-response", view)
		return
	}

	view := s.settingsView(r)
	view["Rotation"] = rotationView{ID: jobID}
	s.render.Partial(w, http.StatusOK, "settings-encryption-progress", view)
}

// handleSettingsEncryptionKeyStatus is polled by the progress view every
// few hundred milliseconds while a rotation started above is still running,
// and once more after it finishes to record the audit entry and render the
// final flash — see CertificateService.MarkRotationReported for why that
// happens at most once even if a stray extra poll lands late.
func (s *Server) handleSettingsEncryptionKeyStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	status, found := s.certs.EncryptionKeyRotationStatus(id)
	if !found {
		// The job is gone (already reported and superseded, or the process
		// restarted mid-rotation) — fall back to whatever the settings
		// actually show now rather than leaving the admin on a stuck
		// progress bar with nothing to poll.
		s.render.Partial(w, http.StatusOK, "settings-encryption-response", s.settingsView(r))
		return
	}
	if !status.Finished {
		view := s.settingsView(r)
		view["Rotation"] = rotationView{ID: id, Total: status.Total, Done: status.Done, Percent: percentOf(status.Done, status.Total)}
		s.render.Partial(w, http.StatusOK, "settings-encryption-progress", view)
		return
	}

	firstRead := s.certs.MarkRotationReported(id)
	view := s.settingsView(r)
	if status.Err != nil {
		msg, _ := errorMessage(status.Err)
		view["Flash"] = &flashMessage{Kind: "error", Message: msg}
		s.render.Partial(w, http.StatusOK, "settings-encryption-response", view)
		return
	}

	if firstRead {
		detail := fmt.Sprintf("certificates=%d root_cas=%d", status.Result.CertificatesReencrypted, status.Result.RootCAsReencrypted)
		s.recordAudit(r, domain.AuditEncryptionKeyRotated, "app_settings", domain.SettingEncryptionKey, detail)
	}
	message := fmt.Sprintf("Encryption key rotated — %d certificate(s) and %d Root CA key(s) re-encrypted.",
		status.Result.CertificatesReencrypted, status.Result.RootCAsReencrypted)
	if !s.certs.KeyEncryptionEnabled() {
		message = fmt.Sprintf("Encryption disabled — %d certificate(s) and %d Root CA key(s) are now stored as plaintext.",
			status.Result.CertificatesReencrypted, status.Result.RootCAsReencrypted)
	}
	view["Flash"] = &flashMessage{Kind: "success", Message: message}
	s.render.Partial(w, http.StatusOK, "settings-encryption-response", view)
}

// rotationView is the progress-bar template's view of one rotation —
// Percent is computed here rather than in the template, since Go templates
// have no arithmetic operators worth relying on for a percentage.
type rotationView struct {
	ID      uuid.UUID
	Total   int
	Done    int
	Percent int
}

func percentOf(done, total int) int {
	if total <= 0 {
		return 0
	}
	pct := done * 100 / total
	if pct > 100 {
		pct = 100
	}
	return pct
}

// splitTrimmedList splits a comma-separated form field into trimmed,
// non-empty entries — the same convention config.optionalList and
// SettingsService's own splitTrimmed use for ALERT_EMAIL_TO.
func splitTrimmedList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitLines splits an LDAP role-map textarea (one group DN per line) into
// trimmed, non-empty entries. Deliberately newline-, not comma- or
// semicolon-delimited: a DN's own RDN components are comma-separated (e.g.
// "cn=a,ou=b,dc=c" — see CLAUDE.md's v1.4 LDAP section), so splitTrimmedList
// above would shred a single DN, and asking an admin to type ";" between DNs
// in a form field is exactly the kind of delimiter convention a one-per-line
// textarea avoids needing in the first place. Handles both "\n" and "\r\n"
// line endings.
func splitLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			out = append(out, l)
		}
	}
	return out
}
