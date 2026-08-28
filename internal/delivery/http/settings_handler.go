package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
func (s *Server) handleSettingsEncryptionKeyRotate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	newKey := strings.TrimSpace(r.PostFormValue("encryption_key"))

	view := s.settingsView(r)
	result, err := s.certs.RotateEncryptionKey(r.Context(), newKey)
	if err != nil {
		msg, _ := errorMessage(err)
		view["Flash"] = &flashMessage{Kind: "error", Message: msg}
		s.render.Partial(w, http.StatusOK, "settings-encryption-response", view)
		return
	}

	detail := fmt.Sprintf("certificates=%d root_cas=%d", result.CertificatesReencrypted, result.RootCAsReencrypted)
	s.recordAudit(r, domain.AuditEncryptionKeyRotated, "app_settings", domain.SettingEncryptionKey, detail)

	view = s.settingsView(r)
	message := fmt.Sprintf("Encryption key rotated — %d certificate(s) and %d Root CA key(s) re-encrypted.",
		result.CertificatesReencrypted, result.RootCAsReencrypted)
	if newKey == "" {
		message = fmt.Sprintf("Encryption disabled — %d certificate(s) and %d Root CA key(s) are now stored as plaintext.",
			result.CertificatesReencrypted, result.RootCAsReencrypted)
	}
	view["Flash"] = &flashMessage{Kind: "success", Message: message}
	s.render.Partial(w, http.StatusOK, "settings-encryption-response", view)
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
