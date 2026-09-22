package graphmail

import (
	"context"
	"fmt"

	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
)

// Notifier adapts a Client to the Enabled/TransportReady/Send/
// SendWithAttachment shape notify.EmailNotifier already exposes — see
// notify.Mailer — so AlertService and CertificateRequestService can use
// whichever transport SettingsService.Mailer hands them without knowing or
// caring which one is actually active. It is always safe to construct and
// call, even with an empty Config — Send becomes a no-op and
// SendWithAttachment returns a clear error, exactly like EmailNotifier.
type Notifier struct {
	cfg    Config
	client Client
}

// NewNotifier builds a Notifier against the real Microsoft identity
// platform / Graph API.
func NewNotifier(cfg Config) *Notifier {
	return &Notifier{cfg: cfg, client: NewHTTPClient(cfg)}
}

// NewNotifierWithClient builds a Notifier against an injected Client —
// tests use a fake; production always uses NewNotifier.
func NewNotifierWithClient(cfg Config, client Client) *Notifier {
	return &Notifier{cfg: cfg, client: client}
}

// Enabled reports whether this notifier has enough configuration to send an
// alert to the fixed distribution list — mirrors
// notify.EmailNotifier.Enabled.
func (n *Notifier) Enabled() bool {
	return n != nil && n.cfg.configured() && len(n.cfg.AlertTo) > 0
}

// TransportReady reports whether this notifier has enough configuration to
// send an arbitrary message to an arbitrary recipient — unlike Enabled, it
// doesn't require the alert distribution list, since SendWithAttachment
// takes its own recipient. Mirrors notify.EmailNotifier.TransportReady.
func (n *Notifier) TransportReady() bool {
	return n != nil && n.cfg.configured()
}

// Send delivers an email to every configured alert recipient, rendered
// through the same branded HTML template every other transport uses (see
// notify.RenderHTMLBody) so a Graph-delivered alert looks identical to an
// SMTP-delivered one.
func (n *Notifier) Send(subject, body string) error {
	if !n.Enabled() {
		return nil
	}
	return n.client.SendMail(context.Background(), Message{
		To:       n.cfg.AlertTo,
		Subject:  subject,
		HTMLBody: notify.RenderHTMLBody(subject, body),
	})
}

// SendWithAttachment delivers a message plus one or more attachments to the
// given recipient — mirrors notify.EmailNotifier.SendWithAttachment,
// including never silently no-opping on missing configuration (the caller,
// a ticket's "send by email" action, needs to know the send didn't
// happen).
func (n *Notifier) SendWithAttachment(to []string, subject, body string, attachments ...notify.Attachment) error {
	if !n.TransportReady() {
		return fmt.Errorf("graphmail: email isn't configured — set the Graph tenant ID, client ID, client secret, and sender from /settings")
	}
	if len(to) == 0 {
		return fmt.Errorf("graphmail: no recipient given")
	}
	if len(attachments) == 0 {
		return fmt.Errorf("graphmail: no attachment given")
	}

	msg := Message{To: to, Subject: subject, HTMLBody: notify.RenderHTMLBody(subject, body)}
	for _, a := range attachments {
		msg.Attachments = append(msg.Attachments, Attachment{Filename: a.Filename, ContentType: a.ContentType, Data: a.Data})
	}
	return n.client.SendMail(context.Background(), msg)
}

var _ notify.Mailer = (*Notifier)(nil)
