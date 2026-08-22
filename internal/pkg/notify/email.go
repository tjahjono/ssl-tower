// Package notify sends alert notifications over email (SMTP) and Microsoft
// Teams (incoming webhook). Both notifiers are no-ops when unconfigured, so
// the alerting service can call them unconditionally without special-casing
// a deployment that hasn't set up one channel or the other.
package notify

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
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

// Enabled reports whether enough configuration is present to attempt sending.
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

// Enabled reports whether this notifier has enough configuration to send.
func (n *EmailNotifier) Enabled() bool {
	return n != nil && n.cfg.Enabled()
}

// Send delivers a plain-text email to every configured recipient.
func (n *EmailNotifier) Send(subject, body string) error {
	if !n.Enabled() {
		return nil
	}
	addr := fmt.Sprintf("%s:%d", n.cfg.Host, n.cfg.Port)
	msg := buildMIME(n.cfg.From, n.cfg.To, subject, body)

	if n.cfg.Port == 465 {
		return n.sendImplicitTLS(addr, msg)
	}

	var auth smtp.Auth
	if n.cfg.Username != "" {
		auth = smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)
	}
	if err := smtp.SendMail(addr, auth, n.cfg.From, n.cfg.To, msg); err != nil {
		return fmt.Errorf("notify: send email: %w", err)
	}
	return nil
}

// sendImplicitTLS handles port 465, where the server expects TLS from the
// first byte rather than a plaintext connection upgraded via STARTTLS.
func (n *EmailNotifier) sendImplicitTLS(addr string, msg []byte) error {
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
	for _, rcpt := range n.cfg.To {
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
