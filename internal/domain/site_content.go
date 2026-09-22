package domain

import (
	"context"
	"time"
)

// SiteContentHelp is the key for the editable "how to request/renew" guide
// shown at GET /help.
const SiteContentHelp = "help"

// SiteContent is one admin-editable block of rich text (raw HTML), rendered
// unescaped into a public page. Only an admin can write one — see
// requireAdmin on the /help/edit routes — since the content is trusted and
// injected as-is, the same trust level an admin already has over every
// other account and certificate in the vault.
type SiteContent struct {
	Key       string
	Content   string
	UpdatedAt time.Time
	UpdatedBy string
}

// SiteContentRepository is the persistence port for admin-editable page
// content. GetSiteContent returns (nil, nil) — not an error — when no row
// exists yet for key, so callers can fall back to a built-in default.
type SiteContentRepository interface {
	GetSiteContent(ctx context.Context, key string) (*SiteContent, error)
	SetSiteContent(ctx context.Context, key, content, updatedBy string) (*SiteContent, error)
}
