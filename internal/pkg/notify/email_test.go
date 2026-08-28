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
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("Content-Type = %q, want multipart/*", mediaType)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])

	textPart, err := mr.NextPart()
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
