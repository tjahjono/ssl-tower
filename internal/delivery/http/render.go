// Package http is the delivery layer: routing, request decoding, and HTML
// rendering. It talks to the service layer and knows nothing about SQL.
package http

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/certutil"
)

//go:embed templates/*.html templates/pages/*.html templates/partials/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Renderer holds the parsed template sets: one per page (page + layout +
// partials) plus a partial-only set used for htmx fragment responses.
type Renderer struct {
	pages    map[string]*template.Template
	partials *template.Template
}

// NewRenderer parses every template at boot so a syntax error fails fast.
func NewRenderer() (*Renderer, error) {
	funcs := templateFuncs()

	pageFiles, err := fs.Glob(templateFS, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}

	r := &Renderer{pages: make(map[string]*template.Template, len(pageFiles))}
	for _, page := range pageFiles {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(
			templateFS,
			"templates/layout.html",
			"templates/partials/*.html",
			page,
		)
		if err != nil {
			return nil, fmt.Errorf("render: parse %s: %w", page, err)
		}
		name := strings.TrimSuffix(pathBase(page), ".html")
		r.pages[name] = t
	}

	partials, err := template.New("partials").Funcs(funcs).ParseFS(templateFS, "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("render: parse partials: %w", err)
	}
	r.partials = partials
	return r, nil
}

// Page renders a full page through the layout.
func (r *Renderer) Page(w http.ResponseWriter, status int, name string, data any) {
	t, ok := r.pages[name]
	if !ok {
		http.Error(w, "template "+name+" not found", http.StatusInternalServerError)
		return
	}
	r.write(w, status, t, "layout.html", data)
}

// Partial renders one named fragment, for htmx swaps.
func (r *Renderer) Partial(w http.ResponseWriter, status int, name string, data any) {
	r.write(w, status, r.partials, name, data)
}

// write buffers first so a template error never produces a half-written page.
func (r *Renderer) write(w http.ResponseWriter, status int, t *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "render "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatTime": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2 Jan 2006 15:04 MST")
		},
		"formatDate": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2 Jan 2006")
		},
		"formatStamp": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return t.UTC().Format("2 Jan 15:04 MST")
		},
		"since": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			default:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			}
		},
		"sinceOrNever": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "never"
			}
			d := time.Since(*t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			default:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			}
		},
		"join": func(sep string, items []string) string {
			if len(items) == 0 {
				return "—"
			}
			return strings.Join(items, sep)
		},
		"badgeClass":  badgeClass,
		"dotClass":    dotClass,
		"flashClass":  flashClass,
		"statusLabel": func(s domain.CheckStatus) string { return statusLabel(s) },
		"lifetimeBar": lifetimeBar,
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"hasValue": func(s string) bool { return strings.TrimSpace(s) != "" },
		"yesNo": func(b bool) string {
			if b {
				return "Yes"
			}
			return "No"
		},
		"truncate": func(n int, s string) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
		"upper":           strings.ToUpper,
		"auditBadgeClass": auditBadgeClass,
		"hasWarningFinding": func(findings []domain.HealthFinding) bool {
			for _, f := range findings {
				if f.Severity == domain.HealthWarning {
					return true
				}
			}
			return false
		},
		"ekuLabel": certutil.ExtKeyUsageLabel,
		"ekuSummary": func(keys []string) string {
			if len(keys) == 0 {
				return "—"
			}
			labels := make([]string, 0, len(keys))
			for _, k := range keys {
				labels = append(labels, certutil.ExtKeyUsageLabel(k))
			}
			return strings.Join(labels, ", ")
		},
		"issuerSummary": issuerSummary,
		"dict": func(values ...any) map[string]any {
			out := map[string]any{}
			for i := 0; i+1 < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					continue
				}
				out[key] = values[i+1]
			}
			return out
		},
	}
}

// IssuerSummaryStats is a small per-CA rollup for the dashboard's "Certificate
// authorities" section: how concentrated the fleet's dependency on that CA
// is, and the soonest thing that'll need attention from it.
type IssuerSummaryStats struct {
	Issued     int
	Pending    int
	NextExpiry *time.Time
}

// issuerSummary reduces one IssuerGroup's certificates into IssuerSummaryStats.
func issuerSummary(certs []*domain.Certificate) IssuerSummaryStats {
	var stats IssuerSummaryStats
	for _, c := range certs {
		if c.Status != domain.CertIssued {
			stats.Pending++
			continue
		}
		stats.Issued++
		if c.NotAfter == nil {
			continue
		}
		if stats.NextExpiry == nil || c.NotAfter.Before(*stats.NextExpiry) {
			stats.NextExpiry = c.NotAfter
		}
	}
	return stats
}

func statusLabel(s domain.CheckStatus) string {
	if s == "" {
		return "Awaiting certificate"
	}
	return s.Label()
}

// badgeClass maps a status onto Tailwind utility classes for a pill badge.
func badgeClass(s domain.CheckStatus) string {
	switch s {
	case domain.StatusOK:
		return "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
	case domain.StatusExpiring:
		return "bg-amber-500/10 text-amber-300 ring-amber-500/30"
	case domain.StatusCritical:
		return "bg-orange-500/10 text-orange-300 ring-orange-500/30"
	case domain.StatusExpired:
		return "bg-rose-500/10 text-rose-300 ring-rose-500/30"
	default:
		return "bg-slate-500/10 text-slate-300 ring-slate-500/30"
	}
}

// flashClass maps a banner kind onto Tailwind utility classes.
func flashClass(kind string) string {
	switch kind {
	case "success":
		return "bg-emerald-500/10 text-emerald-200 ring-emerald-500/25"
	case "error":
		return "bg-rose-500/10 text-rose-200 ring-rose-500/25"
	case "warning":
		return "bg-amber-500/10 text-amber-200 ring-amber-500/25"
	default:
		return "bg-sky-500/10 text-sky-200 ring-sky-500/25"
	}
}

// auditBadgeClass color-codes an audit action for quick scanning: red for a
// failure or destructive action, amber for a sensitive read (a private-key
// download), sky for routine account/security events, slate for ordinary writes.
func auditBadgeClass(action string) string {
	switch action {
	case "login_failed", "user_deleted", "certificate_deleted":
		return "bg-rose-500/10 text-rose-300 ring-rose-500/30"
	case "private_key_downloaded":
		return "bg-amber-500/10 text-amber-300 ring-amber-500/30"
	case "login_success", "logout", "password_changed", "mfa_enrolled":
		return "bg-sky-500/10 text-sky-300 ring-sky-500/30"
	default:
		return "bg-slate-500/10 text-slate-300 ring-slate-500/30"
	}
}

func dotClass(s domain.CheckStatus) string {
	switch s {
	case domain.StatusOK:
		return "bg-emerald-400"
	case domain.StatusExpiring:
		return "bg-amber-400"
	case domain.StatusCritical:
		return "bg-orange-400"
	case domain.StatusExpired:
		return "bg-rose-400"
	default:
		return "bg-slate-500"
	}
}

// lifetimeBar returns a 0-100 width for the "time remaining" meter, assuming a
// nominal 90 day certificate lifetime when the issue date is unknown.
func lifetimeBar(days *int) int {
	if days == nil {
		return 0
	}
	d := *days
	switch {
	case d <= 0:
		return 0
	case d >= 90:
		return 100
	default:
		return d * 100 / 90
	}
}
