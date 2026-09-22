// Package graphmail sends email through the Microsoft Graph API's
// /users/{sender}/sendMail endpoint, authenticated via the OAuth 2.0
// client-credentials grant against Microsoft Entra ID — an app
// registration with the Mail.Send *application* permission, admin-
// consented. This is the Microsoft-recommended replacement for SMTP AUTH
// with a plain username and password, which Microsoft is retiring for
// Exchange Online / Microsoft 365: Basic Authentication for SMTP AUTH is
// disabled by default for existing tenants by the end of December 2026,
// and mandatory (OAuth-only) for every tenant created after that date. See
// CLAUDE.md's v1.18 locked decision for the full context.
//
// This mirrors internal/pkg/digicert and internal/pkg/adcs: a small Client
// interface seam over the real network calls, so SettingsService and every
// caller above it depend only on that interface, never on HTTPClient
// directly. Unlike those two integrations there is no "unverified wire
// format" caveat here — the OAuth2 client-credentials token request and
// the Graph sendMail request/response shapes are both stable, versioned,
// widely-used public APIs (see
// https://learn.microsoft.com/graph/api/user-sendmail and
// https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
// — but it has still only been exercised against a fake Client/a local
// httptest.Server in this codebase, never a real Entra ID tenant. Before
// pointing this at production: register an app in Entra ID, grant it the
// Mail.Send application permission with admin consent, set
// GRAPH_TENANT_ID/GRAPH_CLIENT_ID/GRAPH_CLIENT_SECRET/GRAPH_SENDER_ADDRESS
// (or the /settings equivalents), and send a real test alert.
package graphmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures a Client's connection to one Microsoft Entra ID app
// registration and the mailbox it sends as.
type Config struct {
	// TenantID is the Entra ID (Azure AD) tenant's GUID or verified domain
	// name.
	TenantID string
	// ClientID is the app registration's application (client) ID.
	ClientID string
	// ClientSecret is a client secret created for that app registration.
	// Docker-secrets-eligible, same as SMTP_PASSWORD/ADCS_PASSWORD/
	// LDAP_BIND_PASSWORD (see config.secretFileKeys).
	ClientSecret string
	// Sender is the mailbox (user principal name or object ID) Graph sends
	// as — POSTed to /v1.0/users/{Sender}/sendMail. The app registration's
	// Mail.Send permission must be granted (and admin-consented); if the
	// tenant restricts it via an application access policy, that policy
	// must cover this mailbox too.
	Sender string
	// AlertTo is the fixed alert distribution list Send delivers to —
	// mirrors notify.EmailConfig.To.
	AlertTo []string

	// TokenURL and GraphBaseURL override the real Microsoft identity
	// platform / Graph API endpoints. Tests point both at one
	// httptest.Server; production leaves both empty.
	TokenURL     string
	GraphBaseURL string
	// HTTPClient overrides the default *http.Client — tests point this at
	// an httptest.Server; production leaves it nil.
	HTTPClient *http.Client
}

func (c Config) configured() bool {
	return strings.TrimSpace(c.TenantID) != "" && strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" && strings.TrimSpace(c.Sender) != ""
}

func (c Config) tokenURL() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(c.TenantID))
}

func (c Config) graphBaseURL() string {
	if c.GraphBaseURL != "" {
		return strings.TrimRight(c.GraphBaseURL, "/")
	}
	return "https://graph.microsoft.com/v1.0"
}

// Attachment is one file attached to a Message.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Message is one email to send via Client.SendMail.
type Message struct {
	To          []string
	Subject     string
	HTMLBody    string
	Attachments []Attachment
}

// Client sends one message through the Graph API. HTTPClient is the real
// implementation; tests use a fake, the same shape internal/pkg/digicert's
// and internal/pkg/adcs's Client interfaces already established.
type Client interface {
	SendMail(ctx context.Context, msg Message) error
}

// HTTPClient is the real Graph API client: OAuth2 client-credentials token
// acquisition (cached until shortly before it expires) plus the sendMail
// call itself.
type HTTPClient struct {
	cfg Config

	mu    sync.Mutex
	token string
	exp   time.Time
}

// NewHTTPClient builds a Client from cfg.
func NewHTTPClient(cfg Config) *HTTPClient {
	return &HTTPClient{cfg: cfg}
}

var _ Client = (*HTTPClient)(nil)

func (c *HTTPClient) httpClient() *http.Client {
	if c.cfg.HTTPClient != nil {
		return c.cfg.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// tokenResponse is the OAuth2 client-credentials grant's response body —
// https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow#successful-response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// accessToken returns a cached token when one is still valid, otherwise
// requests a fresh one via the client-credentials grant. Guarded by a mutex
// since AlertService and CertificateRequestService can both reach a shared
// *HTTPClient concurrently in principle (they don't today — SettingsService.
// Mailer builds a fresh Notifier/HTTPClient per call — but this is cheap
// insurance either way).
func (c *HTTPClient) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.exp) {
		return c.token, nil
	}

	form := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("graphmail: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("graphmail: token request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("graphmail: reading token response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("graphmail: token request: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var out tokenResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("graphmail: decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("graphmail: token response carried no access_token")
	}

	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= time.Minute {
		ttl = 5 * time.Minute
	}
	c.token = out.AccessToken
	// Refresh a little early rather than right at the reported expiry.
	c.exp = time.Now().Add(ttl - time.Minute)
	return c.token, nil
}

// graphSendMailRequest is the Graph API's sendMail request body —
// https://learn.microsoft.com/graph/api/user-sendmail.
type graphSendMailRequest struct {
	Message         graphMessage `json:"message"`
	SaveToSentItems bool         `json:"saveToSentItems"`
}
type graphMessage struct {
	Subject      string            `json:"subject"`
	Body         graphItemBody     `json:"body"`
	ToRecipients []graphRecipient  `json:"toRecipients"`
	Attachments  []graphAttachment `json:"attachments,omitempty"`
}
type graphItemBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}
type graphRecipient struct {
	EmailAddress graphEmailAddress `json:"emailAddress"`
}
type graphEmailAddress struct {
	Address string `json:"address"`
}
type graphAttachment struct {
	ODataType    string `json:"@odata.type"`
	Name         string `json:"name"`
	ContentType  string `json:"contentType"`
	ContentBytes string `json:"contentBytes"`
}

// SendMail sends msg as the mailbox named by cfg.Sender.
func (c *HTTPClient) SendMail(ctx context.Context, msg Message) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}

	body := graphSendMailRequest{
		Message: graphMessage{
			Subject: msg.Subject,
			Body:    graphItemBody{ContentType: "HTML", Content: msg.HTMLBody},
		},
	}
	for _, to := range msg.To {
		body.Message.ToRecipients = append(body.Message.ToRecipients, graphRecipient{EmailAddress: graphEmailAddress{Address: to}})
	}
	for _, a := range msg.Attachments {
		contentType := a.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		body.Message.Attachments = append(body.Message.Attachments, graphAttachment{
			ODataType:    "#microsoft.graph.fileAttachment",
			Name:         a.Filename,
			ContentType:  contentType,
			ContentBytes: base64.StdEncoding.EncodeToString(a.Data),
		})
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("graphmail: encoding sendMail request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/users/%s/sendMail", c.cfg.graphBaseURL(), url.PathEscape(c.cfg.Sender))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("graphmail: building sendMail request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("graphmail: sendMail request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graphmail: sendMail: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	return nil
}
