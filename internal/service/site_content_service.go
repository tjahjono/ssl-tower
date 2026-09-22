package service

import (
	"context"
	"strings"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

// SiteContentService reads and writes admin-editable rich-text page content.
type SiteContentService struct {
	repo domain.SiteContentRepository
}

// NewSiteContentService wires the service to its repository.
func NewSiteContentService(repo domain.SiteContentRepository) *SiteContentService {
	return &SiteContentService{repo: repo}
}

// HelpContent returns the current /help body — the admin's saved copy if
// one exists, otherwise the built-in default so the page is never blank.
func (s *SiteContentService) HelpContent(ctx context.Context) (*domain.SiteContent, error) {
	c, err := s.repo.GetSiteContent(ctx, domain.SiteContentHelp)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return &domain.SiteContent{Key: domain.SiteContentHelp, Content: DefaultHelpContent}, nil
	}
	return c, nil
}

// SetHelpContent saves a new /help body. updatedBy is the editing admin's
// email, recorded for the "last updated by" line on the page.
func (s *SiteContentService) SetHelpContent(ctx context.Context, content, updatedBy string) (*domain.SiteContent, error) {
	content = strings.TrimSpace(content)
	return s.repo.SetSiteContent(ctx, domain.SiteContentHelp, content, updatedBy)
}

// DefaultHelpContent is what /help renders until an admin saves their own
// copy — the original static guide, preserved verbatim as the fallback so
// upgrading to an editable Help page never blanks it out. It's raw HTML,
// injected unescaped by the help template — see the trust note on
// domain.SiteContent.
const DefaultHelpContent = `
  <section class="rounded-xl border border-line/5 bg-card/40 p-5">
    <h2 class="mb-1 text-sm font-semibold text-ink">Request a brand-new certificate</h2>
    <p class="mb-4 text-xs text-ink-5">Five steps from nothing to an installed certificate.</p>
    <ol class="space-y-4">
      <li class="flex gap-3">
        <span class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sky-500/10 text-[11px] font-semibold text-hue-sky ring-1 ring-inset ring-sky-500/25">1</span>
        <p class="text-sm text-ink-3">
          <a href="/login" class="text-hue-sky hover:text-hue-sky-strong">Sign in</a> with an editor or
          admin account, then open <span class="font-medium text-ink-2">Certificates</span> →
          <span class="font-medium text-ink-2">Generate a CSR</span>.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sky-500/10 text-[11px] font-semibold text-hue-sky ring-1 ring-inset ring-sky-500/25">2</span>
        <p class="text-sm text-ink-3">
          Fill in the common name and any subject alternative names the certificate needs to cover,
          pick a key algorithm and size, and choose the extended key usage that matches how it'll be
          used — <span class="font-medium text-ink-2">Server Authentication</span> for a website
          or API, <span class="font-medium text-ink-2">Client Authentication</span> for mTLS,
          and so on. Submit — this mints a private key and a signing request, held pending in the
          vault.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sky-500/10 text-[11px] font-semibold text-hue-sky ring-1 ring-inset ring-sky-500/25">3</span>
        <p class="text-sm text-ink-3">
          Open the new certificate's detail page and download the signing request
          (<span class="font-mono">.csr</span>). Send that to whichever CA is issuing the
          certificate — an internal PKI, DigiCert, Sectigo, Let's Encrypt, or similar.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sky-500/10 text-[11px] font-semibold text-hue-sky ring-1 ring-inset ring-sky-500/25">4</span>
        <p class="text-sm text-ink-3">
          When the CA sends back the signed certificate, return to the same detail page and paste it
          into <span class="font-medium text-ink-2">Attach the issued certificate</span>. A full
          chain is fine — the leaf and any intermediates are split apart automatically. It's rejected
          if it doesn't match the private key generated in step 2.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sky-500/10 text-[11px] font-semibold text-hue-sky ring-1 ring-inset ring-sky-500/25">5</span>
        <p class="text-sm text-ink-3">
          Download whichever format the target platform needs — see the table below — and hand it
          to IT for installation, or install it yourself if that's you.
        </p>
      </li>
    </ol>

    <div class="mt-5 rounded-lg bg-line/[0.02] p-4 ring-1 ring-inset ring-line/10">
      <p class="text-sm font-medium text-ink-2">Already generated a CSR and key elsewhere?</p>
      <p class="mt-1 text-xs text-ink-5">
        If it was made on your own laptop with <span class="font-mono">openssl</span> or similar,
        rather than through this page, use the <span class="font-medium text-ink-3">Import CSR
        + key</span> tab instead of Generate — paste both in, and the common name, SANs, and any
        extended key usage the CSR itself requests are read straight off it. Continue from step 3
        above.
      </p>
    </div>
  </section>

  <section class="rounded-xl border border-line/5 bg-card/40 p-5">
    <h2 class="mb-1 text-sm font-semibold text-ink">Renew an existing certificate</h2>
    <p class="mb-4 text-xs text-ink-5">
      Renewing is the same request flow again, started early — there's no separate "renew" button.
    </p>
    <ol class="space-y-3">
      <li class="flex gap-3">
        <span class="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-500"></span>
        <p class="text-sm text-ink-3">
          Open the expiring certificate's detail page for reference — its common name, SANs, and key
          settings — then start a fresh <span class="font-medium text-ink-2">Generate a CSR</span>
          with the same details. A new private key is best practice for a renewal rather than reusing
          the old one.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-500"></span>
        <p class="text-sm text-ink-3">
          Follow the request steps above to get the new CSR signed and attached, then install it
          wherever the old one was.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-500"></span>
        <p class="text-sm text-ink-3">
          Once the replacement is confirmed live, delete the old vault record if you don't need it
          for history — or leave it; nothing forces cleanup, and an old, no-longer-installed
          certificate sitting in the vault does no harm besides a stale entry.
        </p>
      </li>
      <li class="flex gap-3">
        <span class="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-500"></span>
        <p class="text-sm text-ink-3">
          You don't have to track expiry dates by hand: the
          <a href="/" class="text-hue-sky hover:text-hue-sky-strong">dashboard</a> surfaces anything
          expiring or critical, and email/Teams alerts fire on the same thresholds if they're
          configured.
        </p>
      </li>
    </ol>
  </section>

  <div class="grid gap-6 lg:grid-cols-2">
    <section class="rounded-xl border border-line/5 bg-card/40 p-5">
      <h2 class="mb-3 text-sm font-semibold text-ink">Who can do what</h2>
      <dl class="space-y-3 text-sm">
        <div>
          <dt class="font-medium text-ink-2">Viewer</dt>
          <dd class="mt-0.5 text-xs text-ink-5">Read-only — sees the vault and issuer breakdown, can't create, attach, or download anything.</dd>
        </div>
        <div>
          <dt class="font-medium text-ink-2">Editor</dt>
          <dd class="mt-0.5 text-xs text-ink-5">Generates, imports, attaches, and self-signs certificates, and can export a bare signing request to send to a CA.</dd>
        </div>
        <div>
          <dt class="font-medium text-ink-2">Admin</dt>
          <dd class="mt-0.5 text-xs text-ink-5">Everything an editor can do, plus downloading full certificates and any key material, and managing user accounts.</dd>
        </div>
      </dl>
    </section>

    <section class="rounded-xl border border-line/5 bg-card/40 p-5">
      <h2 class="mb-3 text-sm font-semibold text-ink">Download formats</h2>
      <div class="overflow-x-auto">
        <table class="min-w-full text-xs">
          <tbody class="divide-y divide-line/5">
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.pem</td><td class="py-1.5 text-ink-5">Full chain — nginx, Apache, HAProxy</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.crt</td><td class="py-1.5 text-ink-5">Leaf only, PEM</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.der / .cer</td><td class="py-1.5 text-ink-5">Leaf only, binary — Java, Windows</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.p7b</td><td class="py-1.5 text-ink-5">Certificate chain, DER — Windows / IIS</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.pfx / .p12</td><td class="py-1.5 text-ink-5">Key + chain, password protected — IIS, Azure, Java, load balancers</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.key</td><td class="py-1.5 text-ink-5">Private key, PKCS#8 PEM</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.csr</td><td class="py-1.5 text-ink-5">Signing request, to send to a CA</td></tr>
            <tr><td class="py-1.5 pr-3 font-mono text-ink-4">.zip</td><td class="py-1.5 text-ink-5">Everything on file, every format</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <section class="rounded-xl border border-amber-500/15 bg-amber-500/[0.03] p-5">
    <h2 class="mb-1 text-sm font-semibold text-hue-amber-strong">About self-signing</h2>
    <p class="text-sm text-ink-4">
      A pending certificate can be self-signed from the same key while you wait on a CA — useful to
      unblock staging or an internal service. Browsers and most clients won't trust a self-signed
      certificate automatically, so it's for internal/staging use only, never a public-facing
      service.
    </p>
  </section>
`
