package notify

import (
	"html"
	"strings"
)

// renderHTMLBody wraps a plain-text email body in a simple, self-contained
// HTML layout — every outgoing email (alerts and ticket certificate
// delivery alike) is sent as multipart/alternative so a plain-text client
// still sees exactly what it always saw. No external CSS/images/fonts:
// everything is inlined, both because email clients routinely block
// external resources and to keep the same "nothing from third-party
// origins" posture this app's own CSP already holds for the web UI. Every
// dynamic value is HTML-escaped — the body/subject can carry a certificate
// common name or a ticket ID that ultimately traces back to a requester's
// own input, and this is rendered by the *recipient's* mail client, not
// this app, so there is no CSP of its own to fall back on.
func renderHTMLBody(subject, textBody string) string {
	var paragraphs strings.Builder
	for _, para := range strings.Split(strings.TrimSpace(textBody), "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		escaped := strings.ReplaceAll(html.EscapeString(para), "\n", "<br>")
		paragraphs.WriteString(`<p style="margin:0 0 14px;">` + escaped + `</p>`)
	}
	return htmlEmailTemplate(html.EscapeString(subject), paragraphs.String())
}

// htmlEmailTemplate is the one layout every outgoing email shares: a single
// card (table-based, not flexbox/grid — the only layout model consistently
// honoured across real-world email clients) with a header, the message
// body, and a footer disclaimer. subjectHTML/bodyHTML must already be
// HTML-escaped by the caller.
func htmlEmailTemplate(subjectHTML, bodyHTML string) string {
	const fontStack = "system-ui,-apple-system,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif"
	return `<!doctype html>
<html>
  <body style="margin:0;padding:0;background-color:#0f172a;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f172a;">
      <tr>
        <td align="center" style="padding:32px 16px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background-color:#1e293b;border-radius:12px;">
            <tr>
              <td style="padding:20px 24px;border-bottom:1px solid rgba(255,255,255,0.08);font-family:` + fontStack + `;">
                <span style="font-size:14px;font-weight:600;color:#e2e8f0;letter-spacing:0.02em;">SSL Tower</span>
              </td>
            </tr>
            <tr>
              <td style="padding:24px;font-family:` + fontStack + `;color:#cbd5e1;font-size:14px;line-height:1.6;">
                <h1 style="margin:0 0 16px;font-size:16px;font-weight:600;color:#f1f5f9;">` + subjectHTML + `</h1>
                ` + bodyHTML + `
              </td>
            </tr>
            <tr>
              <td style="padding:16px 24px;border-top:1px solid rgba(255,255,255,0.08);font-family:` + fontStack + `;color:#64748b;font-size:12px;">
                Sent automatically by SSL Tower.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`
}
