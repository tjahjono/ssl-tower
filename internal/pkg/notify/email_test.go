package notify

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func TestBuildMultipartMIME(t *testing.T) {
	attachment := Attachment{
		Filename:    "example.com.pem",
		ContentType: "application/x-pem-file",
		Data:        []byte("-----BEGIN CERTIFICATE-----\nfake-certificate-bytes-not-real-pem-data\n-----END CERTIFICATE-----\n"),
	}

	raw, err := buildMultipartMIME("alerts@example.com", []string{"requester@example.com", "second@example.com"}, "Your certificate: example.com", "Attached is the certificate you requested.", []Attachment{attachment})
	if err != nil {
		t.Fatalf("buildMultipartMIME: %v", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}

	if got := msg.Header.Get("From"); got != "alerts@example.com" {
		t.Fatalf("From = %q, want %q", got, "alerts@example.com")
	}
	if got := msg.Header.Get("To"); got != "requester@example.com, second@example.com" {
		t.Fatalf("To = %q, want both recipients", got)
	}
	if got := msg.Header.Get("Subject"); got != "Your certificate: example.com" {
		t.Fatalf("Subject = %q, want %q", got, "Your certificate: example.com")
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q, want multipart/mixed", mediaType)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])

	// The first part of the outer multipart/mixed is itself a
	// multipart/alternative (text + simple HTML renderings of the same
	// body) — see buildAlternativeBody — not a bare text/plain part.
	altPart, err := mr.NextPart()
	if err != nil {
		t.Fatalf("read alternative part: %v", err)
	}
	altMediaType, altParams, err := mime.ParseMediaType(altPart.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse alternative part Content-Type: %v", err)
	}
	if altMediaType != "multipart/alternative" {
		t.Fatalf("first part Content-Type = %q, want multipart/alternative", altMediaType)
	}
	altReader := multipart.NewReader(altPart, altParams["boundary"])

	textPart, err := altReader.NextPart()
	if err != nil {
		t.Fatalf("read text part: %v", err)
	}
	textBody, err := io.ReadAll(textPart)
	if err != nil {
		t.Fatalf("read text part body: %v", err)
	}
	if got := string(textBody); got != "Attached is the certificate you requested." {
		t.Fatalf("text part body = %q, want the message body verbatim", got)
	}
	if ct := textPart.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("text part Content-Type = %q, want text/plain", ct)
	}

	htmlPart, err := altReader.NextPart()
	if err != nil {
		t.Fatalf("read html part: %v", err)
	}
	htmlBody, err := io.ReadAll(htmlPart)
	if err != nil {
		t.Fatalf("read html part body: %v", err)
	}
	if ct := htmlPart.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("html part Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(string(htmlBody), "Attached is the certificate you requested.") {
		t.Fatalf("html part does not contain the body text: %s", htmlBody)
	}
	if !strings.Contains(string(htmlBody), "Your certificate: example.com") {
		t.Fatalf("html part does not contain the subject heading: %s", htmlBody)
	}
	if _, err := altReader.NextPart(); err != io.EOF {
		t.Fatalf("expected exactly two alternative parts (text, html), got a third (err=%v)", err)
	}

	attachPart, err := mr.NextPart()
	if err != nil {
		t.Fatalf("read attachment part: %v", err)
	}
	if ct := attachPart.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Fatalf("attachment Content-Type = %q, want %q", ct, "application/x-pem-file")
	}
	if enc := attachPart.Header.Get("Content-Transfer-Encoding"); enc != "base64" {
		t.Fatalf("attachment Content-Transfer-Encoding = %q, want base64", enc)
	}
	_, dispParams, err := mime.ParseMediaType(attachPart.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("parse Content-Disposition: %v", err)
	}
	if dispParams["filename"] != "example.com.pem" {
		t.Fatalf("attachment filename = %q, want %q", dispParams["filename"], "example.com.pem")
	}

	encodedBody, err := io.ReadAll(attachPart)
	if err != nil {
		t.Fatalf("read attachment part body: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(encodedBody), "\r\n", ""))
	if err != nil {
		t.Fatalf("decode attachment base64: %v", err)
	}
	if !bytes.Equal(decoded, attachment.Data) {
		t.Fatalf("decoded attachment = %q, want %q", decoded, attachment.Data)
	}

	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatalf("expected exactly two parts, got a third (err=%v)", err)
	}
}

// TestBuildMIMERejectsHeaderInjection covers a go/email-injection (CWE-640)
// finding: From/To/Subject used to be spliced into raw header lines with no
// CR/LF stripping, so a "\r\n" in an attacker-reachable value (an
// admin-typed "send by email" recipient, or a certificate request's
// requester-supplied common name feeding the subject) could inject an
// extra header or smuggle content past the intended message. mail.ReadMessage
// parsing back to exactly the expected three headers, with the injected
// text neutralized rather than interpreted, confirms the fix.
func TestBuildMIMERejectsHeaderInjection(t *testing.T) {
	raw, err := buildMIME(
		"alerts@example.com",
		[]string{"victim@example.com\r\nBcc: attacker@evil.com"},
		"Your certificate\r\nX-Injected: yes",
		"body",
	)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	if got := msg.Header.Get("Bcc"); got != "" {
		t.Fatalf("Bcc must not be injectable, got %q", got)
	}
	if got := msg.Header.Get("X-Injected"); got != "" {
		t.Fatalf("X-Injected must not be injectable, got %q", got)
	}
	if got := msg.Header.Get("To"); got != "victim@example.comBcc: attacker@evil.com" {
		t.Fatalf("To = %q, want the CRLF stripped but the rest of the value intact", got)
	}
	if got := msg.Header.Get("Subject"); got != "Your certificateX-Injected: yes" {
		t.Fatalf("Subject = %q, want the CRLF stripped but the rest of the value intact", got)
	}
}

func TestBuildMultipartMIMERejectsHeaderInjection(t *testing.T) {
	raw, err := buildMultipartMIME(
		"alerts@example.com\r\nBcc: attacker@evil.com",
		[]string{"victim@example.com"},
		"subject\r\n\r\nInjected body via header smuggling",
		"body",
		nil,
	)
	if err != nil {
		t.Fatalf("buildMultipartMIME: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	if got := msg.Header.Get("Bcc"); got != "" {
		t.Fatalf("Bcc must not be injectable via From, got %q", got)
	}
	if strings.Contains(msg.Header.Get("Subject"), "\n") {
		t.Fatalf("Subject must not carry a raw newline, got %q", msg.Header.Get("Subject"))
	}
}

// TestRenderHTMLBodySplitsParagraphsAndEscapes covers the simple HTML email
// template (template.go): blank-line-separated paragraphs each become their
// own <p>, and anything that traces back to untrusted input (a certificate
// common name, say) is HTML-escaped rather than interpreted — the body is
// rendered by the recipient's own mail client, which has no CSP of its own
// to fall back on if this app doesn't escape it first.
func TestRenderHTMLBodySplitsParagraphsAndEscapes(t *testing.T) {
	got := renderHTMLBody("Your certificate: <script>evil</script>", "First paragraph.\n\nSecond paragraph with a <b>tag</b> and an & ampersand.")
	if strings.Contains(got, "<script>evil</script>") {
		t.Fatalf("subject must be HTML-escaped, got: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;evil&lt;/script&gt;") {
		t.Fatalf("expected the escaped subject to appear, got: %s", got)
	}
	if !strings.Contains(got, "<p style=\"margin:0 0 14px;\">First paragraph.</p>") {
		t.Fatalf("expected the first paragraph wrapped in its own <p>, got: %s", got)
	}
	if !strings.Contains(got, "Second paragraph with a &lt;b&gt;tag&lt;/b&gt; and an &amp; ampersand.") {
		t.Fatalf("expected the second paragraph HTML-escaped, got: %s", got)
	}
	if !strings.HasPrefix(strings.TrimSpace(got), "<!doctype html>") {
		t.Fatalf("expected a full HTML document, got: %s", got)
	}
}

func TestEmailNotifierTransportReady(t *testing.T) {
	cases := []struct {
		name string
		cfg  EmailConfig
		want bool
	}{
		{"fully configured", EmailConfig{Host: "smtp.example.com", From: "alerts@example.com", To: []string{"ops@example.com"}}, true},
		{"transport ready, no alert distribution list", EmailConfig{Host: "smtp.example.com", From: "alerts@example.com"}, true},
		{"no host", EmailConfig{From: "alerts@example.com"}, false},
		{"no from", EmailConfig{Host: "smtp.example.com"}, false},
		{"empty", EmailConfig{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := NewEmailNotifier(tc.cfg)
			if got := n.TransportReady(); got != tc.want {
				t.Fatalf("TransportReady() = %v, want %v", got, tc.want)
			}
		})
	}

	// A nil *EmailNotifier (the zero value a misconfigured caller might hold)
	// must never panic — it's simply never ready.
	var nilNotifier *EmailNotifier
	if nilNotifier.TransportReady() {
		t.Fatal("nil notifier should never report TransportReady")
	}
}

func TestSendWithAttachmentRejectsMissingConfig(t *testing.T) {
	n := NewEmailNotifier(EmailConfig{}) // no host/from at all
	err := n.SendWithAttachment([]string{"requester@example.com"}, "subject", "body", Attachment{Filename: "x.pem", Data: []byte("x")})
	if err == nil {
		t.Fatal("expected an error when SMTP transport isn't configured, got nil")
	}
}

func TestSendWithAttachmentRejectsNoRecipient(t *testing.T) {
	n := NewEmailNotifier(EmailConfig{Host: "smtp.example.com", From: "alerts@example.com"})
	err := n.SendWithAttachment(nil, "subject", "body", Attachment{Filename: "x.pem", Data: []byte("x")})
	if err == nil {
		t.Fatal("expected an error when no recipient is given, got nil")
	}
}

func TestSendWithAttachmentRejectsNoAttachment(t *testing.T) {
	n := NewEmailNotifier(EmailConfig{Host: "smtp.example.com", From: "alerts@example.com"})
	err := n.SendWithAttachment([]string{"requester@example.com"}, "subject", "body")
	if err == nil {
		t.Fatal("expected an error when no attachment is given, got nil")
	}
}

// TestBuildMultipartMIMEMultipleAttachments covers the "certificate plus a
// separately-attached private key" case the ticket send-by-email feature
// needs: two attachment parts in one message, each independently readable.
func TestBuildMultipartMIMEMultipleAttachments(t *testing.T) {
	cert := Attachment{Filename: "example.com.crt", ContentType: "application/x-pem-file", Data: []byte("cert-bytes")}
	key := Attachment{Filename: "example.com.key", ContentType: "application/x-pem-file", Data: []byte("key-bytes")}

	raw, err := buildMultipartMIME("alerts@example.com", []string{"requester@example.com"}, "subject", "body", []Attachment{cert, key})
	if err != nil {
		t.Fatalf("buildMultipartMIME: %v", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])

	var filenames []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		if fn := part.FileName(); fn != "" {
			filenames = append(filenames, fn)
		}
	}
	if len(filenames) != 2 || filenames[0] != "example.com.crt" || filenames[1] != "example.com.key" {
		t.Fatalf("attachment filenames = %v, want [example.com.crt example.com.key]", filenames)
	}
}
