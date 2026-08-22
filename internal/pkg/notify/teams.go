package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TeamsNotifier posts alert cards to a Microsoft Teams incoming webhook.
type TeamsNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewTeamsNotifier builds a notifier from a webhook URL. It is always safe to
// construct and call even with an empty URL — Send becomes a no-op.
func NewTeamsNotifier(webhookURL string) *TeamsNotifier {
	return &TeamsNotifier{
		webhookURL: strings.TrimSpace(webhookURL),
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether a webhook URL has been configured.
func (n *TeamsNotifier) Enabled() bool {
	return n != nil && n.webhookURL != ""
}

// teamsCard is the legacy "MessageCard" format Teams incoming webhooks accept
// — simpler than an Adaptive Card and sufficient for a one-line alert.
type teamsCard struct {
	Type       string `json:"@type"`
	Context    string `json:"@context"`
	ThemeColor string `json:"themeColor"`
	Summary    string `json:"summary"`
	Title      string `json:"title"`
	Text       string `json:"text"`
}

// Send posts one alert card. themeColor is a bare hex string (no leading #),
// used as a left-edge accent bar so severity is visible at a glance in Teams.
func (n *TeamsNotifier) Send(ctx context.Context, title, text, themeColor string) error {
	if !n.Enabled() {
		return nil
	}
	payload := teamsCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: themeColor,
		Summary:    title,
		Title:      title,
		Text:       text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: encode teams payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build teams request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: teams webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: teams webhook returned %s", resp.Status)
	}
	return nil
}
