package graphmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mustTestServers spins up two httptest.Servers standing in for Entra ID's
// token endpoint and Graph's own API — kept separate (rather than one
// server routing on path) so each test can shape token and sendMail
// behavior independently, the same way a real client's two distinct hosts
// (login.microsoftonline.com vs graph.microsoft.com) are never the same
// server either.
func mustTestServers(t *testing.T, tokenHandler, graphHandler http.HandlerFunc) (tokenURL, graphURL string, cleanup func()) {
	t.Helper()
	tokenSrv := httptest.NewServer(tokenHandler)
	graphSrv := httptest.NewServer(graphHandler)
	return tokenSrv.URL, graphSrv.URL, func() {
		tokenSrv.Close()
		graphSrv.Close()
	}
}

func tokenOKHandler(t *testing.T, wantClientID, wantClientSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("token request: parse form: %v", err)
		}
		if got := r.PostFormValue("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", got)
		}
		if got := r.PostFormValue("scope"); got != "https://graph.microsoft.com/.default" {
			t.Errorf("scope = %q, want the Graph .default scope", got)
		}
		if wantClientID != "" {
			if got := r.PostFormValue("client_id"); got != wantClientID {
				t.Errorf("client_id = %q, want %q", got, wantClientID)
			}
		}
		if wantClientSecret != "" {
			if got := r.PostFormValue("client_secret"); got != wantClientSecret {
				t.Errorf("client_secret = %q, want %q", got, wantClientSecret)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-access-token", ExpiresIn: 3600})
	}
}

// TestHTTPClientSendMailRoundTrip exercises the full SendMail call against
// real httptest.Servers standing in for Entra ID's token endpoint and the
// Graph API's own sendMail endpoint: token acquisition (client-credentials
// form body, correct scope/grant_type), the Authorization bearer header on
// the sendMail request, the JSON request shape (subject/body/recipients),
// and attachment base64 encoding — everything but hitting a real tenant.
func TestHTTPClientSendMailRoundTrip(t *testing.T) {
	var sawAuth string
	var sawBody graphSendMailRequest
	var sendMailCalls int32

	tokenURL, graphURL, cleanup := mustTestServers(t,
		tokenOKHandler(t, "client-123", "s3cr3t"),
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&sendMailCalls, 1)
			if r.URL.Path != "/users/alerts@example.com/sendMail" {
				t.Errorf("request path = %q, want the sender's sendMail path (net/http decodes the escaped @ before routing)", r.URL.Path)
			}
			sawAuth = r.Header.Get("Authorization")
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read sendMail body: %v", err)
			}
			if err := json.Unmarshal(raw, &sawBody); err != nil {
				t.Fatalf("sendMail body is not valid JSON: %v\n%s", err, raw)
			}
			w.WriteHeader(http.StatusAccepted)
		},
	)
	defer cleanup()

	client := NewHTTPClient(Config{
		TenantID:     "tenant-abc",
		ClientID:     "client-123",
		ClientSecret: "s3cr3t",
		Sender:       "alerts@example.com",
		TokenURL:     tokenURL,
		GraphBaseURL: graphURL,
	})

	err := client.SendMail(context.Background(), Message{
		To:       []string{"a@example.com", "b@example.com"},
		Subject:  "cert expiring",
		HTMLBody: "<p>renew it</p>",
		Attachments: []Attachment{
			{Filename: "cert.pem", ContentType: "application/x-pem-file", Data: []byte("PEM-DATA")},
		},
	})
	if err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	if sawAuth != "Bearer test-access-token" {
		t.Errorf("Authorization header = %q, want the bearer token from the token endpoint", sawAuth)
	}
	if sawBody.Message.Subject != "cert expiring" {
		t.Errorf("Subject = %q, want %q", sawBody.Message.Subject, "cert expiring")
	}
	if sawBody.Message.Body.ContentType != "HTML" || sawBody.Message.Body.Content != "<p>renew it</p>" {
		t.Errorf("Body = %+v, want HTML content %q", sawBody.Message.Body, "<p>renew it</p>")
	}
	if len(sawBody.Message.ToRecipients) != 2 ||
		sawBody.Message.ToRecipients[0].EmailAddress.Address != "a@example.com" ||
		sawBody.Message.ToRecipients[1].EmailAddress.Address != "b@example.com" {
		t.Errorf("ToRecipients = %+v, want both recipients in order", sawBody.Message.ToRecipients)
	}
	if len(sawBody.Message.Attachments) != 1 {
		t.Fatalf("Attachments = %d entries, want 1", len(sawBody.Message.Attachments))
	}
	att := sawBody.Message.Attachments[0]
	if att.ODataType != "#microsoft.graph.fileAttachment" {
		t.Errorf("attachment @odata.type = %q, want the fileAttachment type", att.ODataType)
	}
	if att.Name != "cert.pem" || att.ContentType != "application/x-pem-file" {
		t.Errorf("attachment name/type = %q/%q, want %q/%q", att.Name, att.ContentType, "cert.pem", "application/x-pem-file")
	}
	gotData, err := base64.StdEncoding.DecodeString(att.ContentBytes)
	if err != nil {
		t.Fatalf("attachment ContentBytes is not valid base64: %v", err)
	}
	if string(gotData) != "PEM-DATA" {
		t.Errorf("attachment data = %q, want %q", gotData, "PEM-DATA")
	}
	if sendMailCalls != 1 {
		t.Errorf("sendMail was called %d times, want exactly 1", sendMailCalls)
	}
}

// TestHTTPClientCachesAccessTokenAcrossCalls confirms a second SendMail
// within the token's lifetime reuses the cached token rather than hitting
// the token endpoint again — the whole point of accessToken's expiry
// tracking, and worth locking down since a per-send token fetch would
// double every alert's latency and load Entra ID unnecessarily.
func TestHTTPClientCachesAccessTokenAcrossCalls(t *testing.T) {
	var tokenCalls int32
	tokenURL, graphURL, cleanup := mustTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&tokenCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResponse{AccessToken: "cached-token", ExpiresIn: 3600})
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		},
	)
	defer cleanup()

	client := NewHTTPClient(Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s", Sender: "a@example.com",
		TokenURL: tokenURL, GraphBaseURL: graphURL,
	})
	for i := 0; i < 3; i++ {
		if err := client.SendMail(context.Background(), Message{To: []string{"x@example.com"}, Subject: "s", HTMLBody: "b"}); err != nil {
			t.Fatalf("SendMail #%d: %v", i, err)
		}
	}
	if tokenCalls != 1 {
		t.Errorf("token endpoint was called %d times across 3 sends, want exactly 1 (token should be cached)", tokenCalls)
	}
}

// TestHTTPClientSendMailSurfacesTokenEndpointError confirms a non-2xx
// response from the token endpoint fails SendMail with the response body
// in the error, rather than proceeding to call Graph with an empty/invalid
// bearer token.
func TestHTTPClientSendMailSurfacesTokenEndpointError(t *testing.T) {
	tokenURL, graphURL, cleanup := mustTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_client","error_description":"bad client secret"}`)
		},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("sendMail should never be called when the token request failed")
		},
	)
	defer cleanup()

	client := NewHTTPClient(Config{
		TenantID: "t", ClientID: "c", ClientSecret: "wrong", Sender: "a@example.com",
		TokenURL: tokenURL, GraphBaseURL: graphURL,
	})
	err := client.SendMail(context.Background(), Message{To: []string{"x@example.com"}, Subject: "s", HTMLBody: "b"})
	if err == nil {
		t.Fatal("expected an error when the token endpoint rejects the credentials")
	}
	if !strings.Contains(err.Error(), "bad client secret") {
		t.Errorf("error = %q, want it to surface the token endpoint's response body", err.Error())
	}
}

// TestHTTPClientSendMailSurfacesGraphError confirms a non-2xx response from
// the sendMail call itself (a valid token, but Graph rejects the message —
// e.g. the app registration isn't allowed to send as this mailbox) is
// surfaced with the response body, not swallowed as a generic failure.
func TestHTTPClientSendMailSurfacesGraphError(t *testing.T) {
	tokenURL, graphURL, cleanup := mustTestServers(t,
		tokenOKHandler(t, "", ""),
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied. Check credentials and try again."}}`)
		},
	)
	defer cleanup()

	client := NewHTTPClient(Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s", Sender: "a@example.com",
		TokenURL: tokenURL, GraphBaseURL: graphURL,
	})
	err := client.SendMail(context.Background(), Message{To: []string{"x@example.com"}, Subject: "s", HTMLBody: "b"})
	if err == nil {
		t.Fatal("expected an error when Graph rejects the sendMail request")
	}
	if !strings.Contains(err.Error(), "Access is denied") {
		t.Errorf("error = %q, want it to surface Graph's response body", err.Error())
	}
}

// TestConfigDefaultTokenAndGraphURLs confirms the default (non-test-
// override) TokenURL/GraphBaseURL are built from TenantID the way Entra
// ID/Graph's real, documented endpoints expect — the override fields exist
// purely for these tests, so it's worth locking down what a real
// deployment (no override set) actually calls.
func TestConfigDefaultTokenAndGraphURLs(t *testing.T) {
	cfg := Config{TenantID: "contoso.onmicrosoft.com"}
	if got, want := cfg.tokenURL(), "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"; got != want {
		t.Errorf("tokenURL() = %q, want %q", got, want)
	}
	if got, want := cfg.graphBaseURL(), "https://graph.microsoft.com/v1.0"; got != want {
		t.Errorf("graphBaseURL() = %q, want %q", got, want)
	}
}

func TestConfigConfigured(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"fully set", Config{TenantID: "t", ClientID: "c", ClientSecret: "s", Sender: "a@example.com"}, true},
		{"zero value", Config{}, false},
		{"missing sender", Config{TenantID: "t", ClientID: "c", ClientSecret: "s"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.configured(); got != tc.want {
				t.Errorf("configured() = %v, want %v", got, tc.want)
			}
		})
	}
}
