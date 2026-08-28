// Package notify sends alert notifications over email (SMTP) and Microsoft
// Teams (incoming webhook). Both notifiers are no-ops when unconfigured, so
// the alerting service can call them unconditionally without special-casing
// a deployment that hasn't set up one channel or the other.
package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/smtp"
	"net/textproto"
	"strings"
)

// EmailConfig configures outbound SMTP delivery.
type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

// Enabled reports whether enough configuration is present to attempt sending
// an alert — the fixed alert distribution list (To) included. This is what
// gates the alerting channel itself (see AlertService.Enabled).
func (c EmailConfig) Enabled() bool {
	return strings.TrimSpace(c.Host) != "" && strings.TrimSpace(c.From) != "" && len(c.To) > 0
}

// EmailNotifier sends plain-text alert emails over SMTP, with or without
// authentication, over STARTTLS (the common port-587 case, handled by
// smtp.SendMail automatically) or implicit TLS (port 465).
type EmailNotifier struct {
	cfg EmailConfig
}

// NewEmailNotifier builds a notifier from the given configuration. It is
// always safe to construct and call even when cfg is empty — Send becomes a
// no-op.
func NewEmailNotifier(cfg EmailConfig) *EmailNotifier {
	return &EmailNotifier{cfg: cfg}
}

// Enabled reports whether this notifier has enough configuration to send an
// alert to the fixed distribution list.
func (n *EmailNotifier) Enabled() bool {
	return n != nil && n.cfg.Enabled()
}

// TransportReady reports whether this notifier has enough SMTP connection
// configuration (host, from address) to send an arbitrary message to an
// arbitrary recipient — unlike Enabled, it doesn't require the alert
// distribution list (cfg.To), since SendWithAttachment takes its own
// recipient rather than using the fixed alert list. A deployment can have
// SMTP configured for ticket delivery without ever setting up the (optional)
// alerting channel, and vice versa.
func (n *EmailNotifier) TransportReady() bool {
	return n != nil && strings.TrimSpace(n.cfg.Host) != "" && strings.TrimSpace(n.cfg.From) != ""
}

// Send delivers a plain-text email to every configured alert recipient.
func (n *EmailNotifier) Send(subject, body string) error {
	if !n.Enabled() {
		return nil
	}
	return n.deliver(n.cfg.To, buildMIME(n.cfg.From, n.cfg.To, subject, body))
}

// Attachment is one file attached to an email sent via SendWithAttachment.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// SendWithAttachment delivers a multipart email (a text body plus one or
// more attachments — e.g. the certificate itself, and optionally a separate
// private-key file) to the given recipient. Used to hand a specific
// certificate to whoever asked for it, as opposed to Send's fixed alert
// distribution list. Unlike Send, this never silently no-ops on missing
// configuration: the caller (a ticket's "send by email" action) needs to
// know the send didn't happen, not just have it vanish.
func (n *EmailNotifier) SendWithAttachment(to []string, subject, body string, attachments ...Attachment) error {
	if !n.TransportReady() {
		return fmt.Errorf("notify: email isn't configured — set SMTP_HOST and ALERT_EMAIL_FROM")
	}
	if len(to) == 0 {
		return fmt.Errorf("notify: no recipient given")
	}
	if len(attachments) == 0 {
		return fmt.Errorf("notify: no attachment given")
	}
	msg, err := buildMultipartMIME(n.cfg.From, to, subject, body, attachments)
	if err != nil {
		return fmt.Errorf("notify: build message: %w", err)
	}
	return n.deliver(to, msg)
}

// deliver sends a fully-built MIME message to the given recipients, over
// STARTTLS (smtp.SendMail's default, the common port-587 case) or implicit
// TLS (port 465).
func (n *EmailNotifier) deliver(to []string, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", n.cfg.Host, n.cfg.Port)

	if n.cfg.Port == 465 {
		return n.sendImplicitTLS(addr, to, msg)
	}

	var auth smtp.Auth
	if n.cfg.Username != "" {
		auth = smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)
	}
	if err := smtp.SendMail(addr, auth, n.cfg.From, to, msg); err != nil {
		return fmt.Errorf("notify: send email: %w", err)
	}
	return nil
}

// sendImplicitTLS handles port 465, where the server expects TLS from the
// first byte rather than a plaintext connection upgraded via STARTTLS.
func (n *EmailNotifier) sendImplicitTLS(addr string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: n.cfg.Host})
	if err != nil {
		return fmt.Errorf("notify: smtp tls dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, n.cfg.Host)
	if err != nil {
		return fmt.Errorf("notify: smtp client: %w", err)
	}
	defer client.Close()

	if n.cfg.Username != "" {
		auth := smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("notify: smtp auth: %w", err)
		}
	}
	if err := client.Mail(n.cfg.From); err != nil {
		return fmt.Errorf("notify: smtp mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("notify: smtp rcpt to %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("notify: smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("notify: smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: smtp close: %w", err)
	}
	return client.Quit()
}

func buildMIME(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return []byte(b.String())
}

// buildMultipartMIME builds a multipart/mixed message: a text/plain part
// (the body) followed by one part per attachment, each base64-encoded per
// RFC 2045 (mime/multipart.Writer writes part bodies verbatim, so the
// base64 encoding — and its required 76-column line wrapping — is done by
// hand here).
func buildMultipartMIME(from string, to []string, subject, body string, attachments []Attachment) ([]byte, error) {
	var parts bytes.Buffer
	mw := multipart.NewWriter(&parts)

	textPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {`text/plain; charset="utf-8"`},
	})
	if err != nil {
		return nil, fmt.Errorf("create text part: %w", err)
	}
	if _, err := textPart.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("write text part: %w", err)
	}

	for _, attachment := range attachments {
		contentType := attachment.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		attachPart, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {contentType},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", attachment.Filename)},
		})
		if err != nil {
			return nil, fmt.Errorf("create attachment part: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(attachment.Data)
		const lineLen = 76
		for i := 0; i < len(encoded); i += lineLen {
			end := i + lineLen
			if end > len(encoded) {
				end = len(encoded)
			}
			if _, err := attachPart.Write([]byte(encoded[i:end])); err != nil {
				return nil, fmt.Errorf("write attachment part: %w", err)
			}
			if _, err := attachPart.Write([]byte("\r\n")); err != nil {
				return nil, fmt.Errorf("write attachment part: %w", err)
			}
		}
	}

	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/mixed; boundary=%q\r\n", mw.Boundary())
	msg.WriteString("\r\n")
	msg.Write(parts.Bytes())
	return msg.Bytes(), nil
}
