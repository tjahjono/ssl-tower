package notify

// Mailer is the shape both EmailNotifier (SMTP) and graphmail.Notifier
// (Microsoft Graph API, v1.18) implement. SettingsService.Mailer picks
// which one backs it based on the configured email transport, and every
// caller (AlertService, CertificateRequestService) programs against this
// interface instead of *EmailNotifier directly, so it never needs to know
// which transport is actually active. graphmail.Notifier can't declare
// this assertion itself without an import cycle (it already imports notify
// for Attachment/RenderHTMLBody) — its own file asserts it against this
// interface instead.
type Mailer interface {
	// Enabled reports whether this notifier has enough configuration to
	// send an alert to its fixed distribution list.
	Enabled() bool
	// TransportReady reports whether this notifier has enough
	// configuration to send an arbitrary message to an arbitrary
	// recipient, independent of the fixed distribution list.
	TransportReady() bool
	// Send delivers subject/body to the fixed distribution list. A no-op
	// (nil error) when !Enabled().
	Send(subject, body string) error
	// SendWithAttachment delivers subject/body plus attachments to to. Unlike
	// Send, this never silently no-ops on missing configuration.
	SendWithAttachment(to []string, subject, body string, attachments ...Attachment) error
}

var _ Mailer = (*EmailNotifier)(nil)
