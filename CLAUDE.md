# CLAUDE.md

Guidance for Claude Code (or any coding agent) working in this repository.

## What this is

**SSL Tower** (repo name `ssl-generator`) — a certificate vault and CSR
toolkit. Generate CSRs with their key pairs, or upload certificates you
already have (PEM or PKCS#12), export in whatever encoding a target platform
wants, get alerted before anything expires, all behind role-gated logins
with MFA and a full audit trail. There is no live endpoint monitoring —
Phase 10 retired it in favor of reading expiry straight from each
certificate's own `notAfter` (see the Phase 10 decision below).

Go · PostgreSQL · htmx · Tailwind CSS. No SPA, no build step at runtime —
templates and static assets are `go:embed`-ed into a single binary.

## Architecture

Strict layering, dependencies point inward:

```
delivery/http → service → domain ← repository/postgres
```

- `internal/domain` — entities, validation, repository *interfaces* (ports).
  Imports neither `pgx` nor `net/http`, so services can be tested against
  fakes and the storage engine is swappable in principle. `certificate.go`
  is the vault's one entity — it replaced both `csr.go` and `monitor.go`
  in Phase 10.
- `internal/repository/postgres` — the only place SQL lives. Implements the
  domain's repository interfaces with pgx/v5.
- `internal/service` — business rules: the certificate vault
  (`certificate_service.go` — generate, import, import-PFX, bulk-import,
  export), alerting (`alert_service.go`), the periodic alert sweeper
  (`alert_sweeper.go`), auth, audit, admin-editable page content
  (`site_content_service.go`).
- `internal/delivery/http` — router, handlers, templates, static assets.
  - `templates/pages/` — one full page each, rendered through `layout.html`.
  - `templates/partials/` — htmx fragments, reused by both full pages and
    swaps.
- `internal/pkg/certutil` — keys, CSRs, PKCS#12 encode (`export.go`) and
  decode (`DecodePKCS12`), export encoders (PEM/DER/PKCS#7/PKCS#12/ZIP).
  Phase 10 deleted `inspect.go` (`InspectEndpoint`, a live TLS handshake) —
  there is no endpoint left to inspect once monitoring becomes upload/generate.
- `internal/pkg/secret` — AES-256-GCM envelope encryption for stored key
  material.
- `internal/pkg/authcrypto` — password hashing (bcrypt), session tokens,
  recovery codes.
- `internal/pkg/notify` — email (SMTP) and Microsoft Teams alert senders.
- `web/input.css` — Tailwind source; prebuilt into
  `internal/delivery/http/static/app.css` and embedded (no Node needed at
  runtime).

When adding a feature, respect the direction of the arrows above: handlers
call services, services call repository interfaces declared in `domain`,
never the other way around, and SQL never leaks out of
`repository/postgres`.

## Locked decisions (do not re-litigate these)

These were decided early and later phases were built on top of them. Undoing
one is a cross-cutting change, not a tweak — flag it to the user first.

- **Second factor: TOTP authenticator app**, not SMTP/SMS-based — no extra
  infra dependency, works offline, matches Authenticator/Authy/1Password.
  MFA is mandatory for every account and is enforced **server-side**, before
  any other authenticated route — not just hidden in the UI.
- **Four roles**: `admin` (also manages accounts, `CanManageUsers()`),
  `editor` (full read-write on monitors/CSRs, `CanWrite()`), `viewer`
  (read-only, including CSR downloads), and — added in v1.2 —
  `requester` (`CanRequestCertificates()`), a self-service tier that can
  only submit and view certificate request tickets; it has no vault
  read/write access of its own and is deliberately exclusive with the other
  three capabilities (a requester is never also `CanWrite`). Every write
  route re-checks the caller's role server-side.
- **Only the dashboard and Help are public.** The certificate dashboard
  (`GET /{$}` and its `/summary` auto-refresh partial) and the request/renew
  guide (`GET /help`, Phase 14) are the only routes reachable without a
  session — Help is intentionally public so anyone in the org can read how
  to request a certificate before they have an account. Everything else —
  the vault, issuer pages, account/admin/audit pages, and `/help/edit` —
  requires `requireAuth` at minimum, reads included; mutations additionally
  require `requireWrite` or `requireAdmin`. (This tightened an earlier
  "public read, gated write" design for monitoring — see `PLAN.md`'s Phase 7
  note. CSR routes had already required a session for any read from Phase 3
  onward, since they hold private key material — that has not changed.)
  As of Phase 15, the dashboard's public surface is deliberately wide: it
  shows every certificate (common name, key/status/origin, SAN summary) and
  a CA breakdown, unconditionally, not just what's unhealthy. What stays
  gated: the cards render as plain, non-clickable `<div>`s for an anonymous
  visitor (only a signed-in session gets `<a>` links into a detail page),
  so there is still no way to reach CSR text or key material without
  signing in. Help's body is admin-editable (see the Phase 15 decision
  below) but the page itself carries no session-derived data, which is why
  both routes remain safe to leave public.
- **Certificate model: unified vault, no endpoint monitoring** (Phase 10,
  supersedes the earlier "cert-first, one endpoint per monitor" design).
  `internal/domain/certificate.go`'s `Certificate` replaced both `CSR` and
  `Monitor`/`Check`: every certificate has an `Origin` (`generated` via CSR,
  or `uploaded` directly) and an `Owner`/team tag. Intake is one of three
  paths: generate-a-CSR (unchanged from before), import a CSR + private key
  generated elsewhere — e.g. on an operator's own laptop with openssl —
  which reads subject/SANs/requested-EKU straight off the pasted CSR
  (Phase 13), or upload — a PEM triplet (certificate, optional chain,
  optional key, pasted as text) or a PKCS#12 bundle, including
  bulk-importing several `.pfx` files at once with a shared password. Both
  CSR-based paths land with `Origin = generated`, since what distinguishes
  the two origins is "does this record have a pending-CSR stage," not which
  machine ran the keygen. There is no live TLS handshake against anything —
  expiry comes from the certificate's own `notAfter`, checked by a periodic
  `AlertSweeper` (`internal/service/alert_sweeper.go`) rather than the old
  per-endpoint scheduler. Duplicate-fingerprint detection is preserved,
  ported from monitors to certificates (`FindSharingFingerprint`).
- **Extended key usage is requested at CSR time, but the issued leaf is
  ground truth** (Phase 12). `Certificate.ExtKeyUsage` holds what was
  requested while pending and is overwritten by `applyIssuedCert` with
  whatever the actual issued/uploaded certificate carries the moment it
  becomes issued — a CA is free to honour, ignore, or override the request.
  The EKU vocabulary (keys, labels, OIDs, `x509.ExtKeyUsage` mapping) lives
  entirely in `certutil`, not domain, so domain stays free of crypto/x509
  imports.
- **Certificate/key downloads are admin-only** (Phase 10, supersedes the
  earlier "viewer can download CSRs" decision). The one carve-out: an
  editor can still export the bare CSR text (`FormatCSR`, no private key)
  to send to a CA themselves — checked explicitly in
  `handleCertificateDownload`, not via a route-level role gate, since the
  permitted role depends on which `format` is requested.
- **Weak-certificate health findings are computed once, at intake** (Phase
  11), not on a recurring schedule — `Certificate.HealthFindings()` ported
  `Check.HealthFindings()`'s logic (weak signature MD5/SHA1, undersized key
  RSA<2048/ECDSA<256, self-signed, no-intermediates) verbatim. "Issuer
  changed" was dropped — it only made sense when a periodic re-check could
  notice a change; here a replaced certificate is just a new record.
- **The Help page's body is admin-editable, stored as raw HTML** (Phase 15).
  `domain.SiteContent` / `SiteContentRepository` back a small `site_content`
  key/value table; `GET /help` renders whatever an admin has saved via
  `GET/POST /help/edit` (`requireAdmin`), falling back to
  `service.DefaultHelpContent` — the original static guide, preserved
  verbatim — when no row exists yet. The saved value is injected unescaped
  (`template.HTML`) into a page anyone can view without a session. This is
  an accepted, admin-only trust boundary, not an oversight: an admin
  already controls every account and can download any private key, so
  authoring the Help page's markup is the same tier of trust. It does add a
  new failure mode worth naming — a compromised or careless admin account
  can now inject arbitrary HTML/script into a *public* page, not just an
  authenticated one — so treat that route with the same care as user/role
  management if this decision is ever revisited. Edits are audited
  (`AuditHelpContentUpdated`).
- **Certificate chain validation checks signature linkage, not trust**
  (Phase 16). `certutil.ValidateChain(leaf, chain)` confirms each
  certificate in a chain actually signed the one before it, that
  intermediates carry `IsCA` with valid basic constraints, and that
  nothing in the chain is outside its validity window — but it does **not**
  check the chain against any trusted root store. This is deliberate: an
  internal PKI's root is commonly self-signed and was never meant to land
  in a public trust store, so "does this chain validate against a CA
  bundle" isn't the right question here. `CertificateService.UpdateChain`
  (admin-only, `POST /certificates/{id}/chain`) follows the same
  save-always-succeeds/validation-is-informational shape as Phase 15's
  Help content: a chain that fails to *parse* blocks the save, but a chain
  that parses fine and merely fails logical validation still saves, with
  every issue surfaced in the response so the admin can see exactly what's
  wrong instead of being locked out. Edits are audited
  (`AuditCertificateChainEdited`).
- **A top-right "Validate" button on the certificate detail page re-checks
  everything on file, on demand, without saving anything.**
  `CertificateService.ValidateIntegrity` (`POST /certificates/{id}/validate`,
  `requireWrite` — it decrypts the private key internally, same sensitivity
  tier as self-sign) composes existing `certutil` primitives rather than
  adding new crypto logic: `ParsePrivateKeyPEM`, `MatchesCSRKey`/`MatchesKey`
  for key-vs-CSR and key-vs-certificate agreement, and the existing
  `ValidateChain` for intermediate signature linkage. It also checks whether
  the chain's last entry is a self-signed CA (the "root") — informational
  only, never a failure, consistent with `ValidateChain` already treating
  trust-root validation as out of scope. Returns an `IntegrityReport{Valid,
  Checks, Issues}`; the handler joins `Checks` into a success flash or
  `Issues` into an error flash, same OOB-swap pattern as every other
  certificate action. The button itself is rendered unconditionally (no
  `.User.Role.CanWrite` gate in the template) — matching the pre-existing
  convention for the attach-certificate/self-sign forms just below it on the
  same page, which also rely on the backend 403 rather than hiding the
  control from a viewer.
  - **Gotcha hit while testing this**: two pre-existing certificate records
    in this dev database fail with "private key unavailable: cipher: message
    authentication failed" — their `PrivateKeyPEM` ciphertext doesn't decrypt
    under the current `APP_ENCRYPTION_KEY` in `.env`. This is stale seed/test
    data from earlier in this project's life (encrypted under a since-changed
    key), not a bug in the sealer or in `ValidateIntegrity` — the feature is
    correctly surfacing a real, pre-existing inconsistency it was asked to
    catch. Don't "fix" this by weakening the AEAD check; if it matters, those
    two records need their certificate re-attached or re-issued.
- **Docker Swarm deploy reads credentials from Docker secrets, via a
  `*_FILE` env-var convention, not the plain `docker-compose.yml` path**
  (v1.1). `internal/config/config.go`'s `applySecretFiles` runs before
  `loadDotEnv`: for each of `DATABASE_URL`, `APP_ENCRYPTION_KEY`,
  `SESSION_SECRET`, `ADMIN_INITIAL_PASSWORD`, `SMTP_PASSWORD`, and
  `TEAMS_WEBHOOK_URL`, if `<KEY>_FILE` is set and `<KEY>` itself isn't, it
  reads that file's trimmed contents into `<KEY>` — this is exactly the
  Docker/Kubernetes secrets-as-mounted-files pattern
  (`/run/secrets/<name>`). Precedence, highest to lowest: a real env var set
  directly, then `*_FILE`, then `.env`, matching `loadDotEnv`'s own
  env-wins-over-.env rule (both rely on the same "skip if already set"
  check, which is why running `applySecretFiles` first is enough to make it
  win over `.env` without any special-casing). `docker-compose.yml` (local
  dev) is untouched — plain environment variables, `docker compose up
  --build` still builds the image itself. `docker-stack.yml` is a new,
  separate manifest for `docker stack deploy`, since Swarm mode can't build
  images at deploy time and needs a pre-built, tagged image plus every
  secret created ahead of time via `docker secret create` (or `make
  docker-secrets`, which generates and creates all of them idempotently).
  `DATABASE_URL` has no separate password field to peel off — it's one
  connection string — so its Docker secret has to be built from the *same*
  generated DB password used for Postgres's own secret, not a second
  independently-generated one; `make docker-secrets` does this correctly
  from a single generated password, and `docker-stack.yml`'s header comment
  spells out the manual equivalent for anyone not using that target.
  **`make docker-secrets` sources real values from `.env` where they
  exist** (v1.3 follow-up; supersedes the original always-random
  behavior). For `APP_ENCRYPTION_KEY`, `SESSION_SECRET`, and
  `ADMIN_INITIAL_PASSWORD`, the target now reads `.env` first and only
  falls back to `openssl rand` when that key is absent or empty there —
  so a redeploy reuses the same values already configured for local dev
  instead of minting new ones the running app doesn't actually have. Same
  idea for the DB password: if `.env`'s `DATABASE_URL` has a password
  segment, that's reused (with the host rewritten to `postgres:5432`,
  since a `.env` pointed at `localhost` isn't reachable inside the Swarm
  network); otherwise a fresh one is generated exactly as before.
  `SMTP_PASSWORD` and `TEAMS_WEBHOOK_URL` have no random fallback — if
  `.env` has a non-empty value, the secret is created; if empty or
  missing, the target skips creating it and prints a note, matching the
  existing "empty = channel off" convention (`config.go`, alert channels).
  A secret this target has already created is always left untouched
  (Docker secrets are immutable), regardless of source. `docker-stack.yml`
  now references `ssl_tower_smtp_password`/`ssl_tower_teams_webhook`
  uncommented by default, on the assumption both are set in `.env` — see
  that file's own comments for what to re-comment if one isn't.
- **Root CA upload/sign-with-CA templates live in `templates/partials/`, not
  `templates/pages/`** (v1.1, bug fix). `Renderer.Partial` (used for every
  htmx OOB response) only parses `templates/partials/*.html` — a `{{define}}`
  block placed in a `templates/pages/*.html` file is invisible to it, even
  though a full-page render works fine (that template set also parses
  `templates/pages/*.html`, masking the bug until an htmx swap hit it). The
  Root CA upload/delete responses were first written as
  `root-ca-section-response`/`root-ca-section` inside
  `certificate_issuers.html` and failed with `html/template: "..." is
  undefined` on the very first live upload attempt. Fixed by moving both
  `{{define}}` blocks into their own `templates/partials/root_ca_section.html`
  — `certificate_issuers.html`'s full-page render still finds them there
  (that template set parses `templates/partials/*.html` too), and the htmx
  response now does as well. If you add another admin action that
  re-renders a page-level section via htmx (matching the existing
  `certificate-detail-response` pattern), define it under
  `templates/partials/`, never inside the `templates/pages/*.html` file it's
  logically "part of."
- **Theme: CSS-variable-backed semantic colors, not Tailwind's `dark:`
  variant** (Phase 16). Doubling every utility class with a `dark:` prefix
  across ~19 templates would have meant editing (and maintaining) every
  template twice. Instead, `web/input.css` defines the palette as CSS
  custom properties (`--color-surface`, `--color-card`, `--color-line`,
  `--color-ink-*`, `--color-hue-*`) — dark values on bare `:root`, light
  overrides on `:root[data-theme="light"]` — and `tailwind.config.js` maps
  semantic color names (`surface`, `card`, `line`, `ink`/`ink-1..6`,
  `hue-emerald`/`hue-amber`/`hue-orange`/`hue-rose`/`hue-sky`, each with a
  `-strong` variant) to `rgb(var(--color-x) / <alpha-value>)`, so opacity
  modifiers like `bg-card/40` keep working. Templates reference the
  semantic names once; the palette swap happens entirely in CSS. The
  toggle is a plain `theme` cookie (`light`/`dark`, default `dark`), read
  server-side via `themeFromRequest(r)` in `internal/delivery/http/theme_handler.go`
  and stamped onto `<html data-theme="...">` at render time via `newView`'s
  `"Theme"` key — no client-side JavaScript at all, which also means no
  flash-of-wrong-theme on load. `POST /theme` is intentionally public
  (cosmetic, no session needed) and validates its `redirect` target isn't
  protocol-relative (`//host/path`) before redirecting, so it can't be used
  as an open redirect. A few classes stayed literal on purpose — e.g. the
  QR code's solid white background in `mfa_enroll.html`, which needs to
  stay white regardless of theme for scannability — don't "fix" these into
  semantic tokens.
  **Gotcha, already hit once:** the retokenization pass only touched
  `.html` files under `templates/`. `service.DefaultHelpContent`
  (`internal/service/site_content_service.go`) is raw HTML too, injected
  unescaped into `/help`, but it lives in a `.go` string constant and was
  missed on the first pass — it stayed hard-coded to the dark palette
  (`bg-slate-900/40`, `text-white`, `text-slate-300`, etc.) until a light-mode
  visual bug was reported and it was retokenized separately. If Help's body
  is ever edited by an admin through `/help/edit`, that saved copy in the
  `site_content` table would need the same check — the DB content isn't
  covered by this file at all.
- **Sidebar nav is a collapsible drawer below `lg`, not a squeezed row**
  (Phase 16 follow-up). The original mobile layout kept `<aside>` as a plain
  `flex` row: logo, nav, and (once Phase 16 added it) the theme toggle and
  account footer all sat side by side and got squeezed into unreadable
  wrapped text on a phone-width screen — reported and fixed the same day
  Phase 16 shipped. The fix: nav links, the theme toggle, and the account
  footer are now wrapped in one `#sidebar-panel` div that's `hidden` by
  default and toggled by a `lg:hidden` "Menu" button next to the logo,
  using the same `data-toggle-target` mechanism as the Certificates page's
  "Add a certificate" button. At `lg` and up, `lg:flex` on that div wins
  over `hidden` in the cascade (the same "hidden lg:table-cell" pattern
  already used for responsive table columns), so the panel is always shown
  and the button is always hidden — no JS-driven breakpoint logic, just
  CSS doing what CSS is for.
- **Fixed while touching it: `data-toggle-target`'s hidden/label state was
  inverted.** `panel.classList.toggle("hidden")` returns `true` when the
  class ends up present (i.e., the panel is now hidden) — the original code
  negated that (`!panel.classList.toggle(...)`) into a variable it then
  called `nowHidden`, which actually meant "now visible." That silently
  swapped the open/closed label text and skipped `scrollIntoView` on open
  instead of on close, on every toggle button in the app (the Certificates
  page's "Add a certificate" included) — just not blatant enough to notice
  until the new mobile menu button made it obvious. Fixed in
  `static/app.js` by dropping the negation; don't reintroduce it.
- **`<select>` elements get their own `.field-select`/`.field-select-bare`
  component classes, not plain `.field-input`** (Phase 16 follow-up). A
  native select's closed box picks up `.field-input`'s background/border/
  text color fine, but its dropdown arrow is drawn by the browser itself
  and ignores every one of our classes — left as `.field-input`, every
  select in the app looked like a bare, unstyled OS control dropped into an
  otherwise custom-designed page. `.field-select` adds `appearance-none`
  plus a small inline SVG chevron as a `background-image`, colored a flat
  literal `#64748b` (slate-500 — the same literal already used for the
  scrollbar thumb above) rather than a theme token, since a background-image
  can't reference a CSS custom property or `currentColor`, and this neutral
  a gray reads fine unchanged on either palette. `.field-select-bare` layers
  `bg-card/60` on top for a toolbar/filter-bar context, same relationship as
  `.field-input`/`.field-input-bare`. **The gotcha that actually mattered:**
  the chevron needs reserved right-padding (`pr-9`) to avoid sitting under
  long option text, but Tailwind's utilities layer always overrides the
  components layer at equal specificity — a call site's own `px-3` (setting
  `padding-right` again) silently wins over anything the component tries to
  bake in, chevron included, no matter how it's written on the component
  side. So every `<select>`'s call-site class list splits `px-*` into
  `pl-*` + `pr-9` explicitly (e.g. `pl-3 pr-9` instead of `px-3`) rather than
  relying on the component for it — grep for `field-select` before adding a
  new one and match that pattern, not `.field-input`'s plain `px-*`.
- **Alert channels: Email + Microsoft Teams**, not Slack — matches how the
  team is actually notified. Each channel is independently opt-in via its own
  env vars; leaving both unset is a supported, fully-functional
  configuration (boot-time warning only).
- **Form styling runs last** (Phase 5, after everything else) precisely so it
  covers every page built in earlier phases in one pass instead of styling
  things twice. If you add a new form/page, apply the existing
  `.field-label` / `.field-input` / `.field-input-bare` / `.btn-primary` /
  `.btn-secondary` / `.btn-ghost` component classes from `web/input.css`
  rather than hand-rolling new utility strings.
- **CSRF**: double-submit cookie on every mutating request, including the
  login form itself (`X-CSRF-Token` header or `csrf_token` form field; htmx
  pages get the header for free via `hx-headers` on `<body>`).
- **Sessions**: opaque random tokens (32 bytes, base64url), SHA-256-hashed
  before storage — a DB leak never exposes a usable session. Idle timeout and
  absolute timeout are both configurable via env.
- **Audit log records successes only**, not every attempt (with the explicit
  exception of failed logins, which are logged specifically because they're
  a security signal). It is non-blocking — `AuditService.Record()` never
  returns an error to the caller, it only logs failures internally.
  Private-key-bearing downloads (`.key`, `.pfx`, `.zip`) are audited
  specifically as `AuditKeyDownloaded`; plain cert-only downloads are not.
- **No built-in config defaults.** `internal/config/config.go` has no
  fallback values baked into the Go code. Every setting is either required
  (must resolve to a real value or `Load()` fails fast, listing exactly
  what's missing) or explicitly optional by design (a feature toggle whose
  empty value is itself meaningful — e.g. empty `SMTP_HOST` means "email
  alerts off", not "use some default host"). `.env.example` is the single
  source of truth for what a required variable's value should be. If you
  add a new config field, decide which category it belongs to and add it to
  `.env.example` either way — don't reach for a Go-level fallback.
- **`config.Load()` reads `.env` itself.** `loadDotEnv(".env")` runs first,
  parsing `.env` from the process's current working directory and calling
  `os.Setenv` for any key that isn't already set — a real environment
  variable (shell, `docker compose`'s `environment:` block, systemd, a
  scheduler) always wins over `.env`, which only fills in what's missing.
  This is why `go run ./cmd/server`, `./bin/server`, and `make run` all
  behave identically without any of them needing to source `.env` into the
  shell first. Inside the Docker image there's deliberately no `.env` file
  (`.dockerignore` excludes it), so `loadDotEnv` is a no-op there and every
  value comes from `docker-compose.yml`'s `environment:` block instead —
  don't "fix" `loadDotEnv` to require the file to exist.
- **v1.2 certificate request tickets** (`internal/domain/certificate_request.go`,
  `CertificateRequestService`, `/requests` + `/tickets`). A `requester`
  submits a ticket naming a trust class (`internal`/`external`, binding —
  an approver can never switch it), a new-vs-renewal type, and — for
  external only — a procurement PO number. Internal and external tickets
  then diverge on purpose: an internal ticket is **approved and signed in
  one combined action** (`ApproveInternal` — the ticket detail page embeds
  the same CSR-generation + Root-CA-signing forms `certificate_detail.html`
  uses, scoped to the ticket, so approving *is* creating the certificate),
  landing straight on `RequestFulfilled`; an external ticket instead moves
  to `RequestInProgress` on approval (procurement with a public CA happens
  manually, outside the app) and only reaches `RequestFulfilled` once
  `FulfillExternal` attaches the certificate the CA returned (via
  `CertificateService.Import` — a fresh uploaded record, not
  `AttachCertificate`, since there is no pending placeholder certificate to
  attach to). **No certificate is ever downloadable by a requester** —
  `Deliver` only records that an editor/admin handed it over by hand, it
  never changes ticket status. SLA age is tracked from `ApprovedAt`, not
  `CreatedAt` (`CertificateRequest.OverdueSLA`), because that's when an
  editor/admin actually took ownership of the work; the window itself is
  `TICKET_SLA_DAYS`, a required env var (3 days for both trust classes, per
  the confirmed decision), not a Go-level default. Ticket lifecycle events
  reuse the existing `EmailNotifier`/`TeamsNotifier` channels rather than a
  new notification path. See the CA/Browser Forum's Ballot SC-081v3 (passed
  April 2025) for why this shipped when it did: publicly-trusted TLS
  certificate max validity drops 398→200 days (Mar 2026), then 100 (Mar
  2027), then 47 (Mar 2029) — external (publicly-trusted) certificates in
  this app will need renewing far more often, which is what makes a
  self-service request/approve flow worth having instead of ad hoc emails.
- **v1.3: sending a fulfilled ticket's certificate by email is an
  intentional, admin/editor-gated exception to "no certificate is ever
  downloadable by a requester" above** — that decision is about the
  requester never having self-service access, not about every hand-off
  requiring a literal in-person handover. `POST /tickets/{id}/send-email`
  (`requireWrite`, same tier as the rest of the ticket queue) exports the
  ticket's `ResultCertificateID` via the existing `CertificateService.Export`
  (`certutil`) and sends it as a real attachment through
  `EmailNotifier.SendWithAttachment` — a new method alongside the existing
  alert-only `Send`, since alerts go to a fixed distribution list
  (`EmailConfig.To`) while a ticket email goes to an arbitrary recipient the
  admin/editor types in (pre-filled with `RequesterEmail`, editable).
  `EmailNotifier.TransportReady()` (host + from address only) gates this
  separately from `Enabled()` (which additionally requires the alert
  distribution list) — a deployment can have ticket email working without
  ever configuring the optional alerting channel, and vice versa. The
  format dropdown is deliberately narrower than the Download panel's
  (`certificateSendFormats`, `internal/delivery/http/certificate_handler.go`):
  it excludes every key-bearing format (`.key`, `.pfx`, `.zip`), because key
  inclusion here is its own separate, explicit "include private key"
  checkbox — honored only when the caller is `CanManageUsers()`, exactly
  mirroring `handleCertificateDownload`'s own admin-vs-editor gate, and
  resolved server-side (`handleTicketSendEmail` zeroes an editor's submitted
  `include_key=on` rather than trusting it) so a tampered request can't get
  a key out through an editor session. A successful send fires
  `AuditRequestEmailed`, plus `AuditKeyDownloaded` alongside it when the key
  was actually attached — same pairing convention the Download panel
  already uses. Sending also auto-sets `DeliveredBy`/`DeliveredAt` (unless
  already set) — emailing the certificate to the requester *is* handing it
  over, so this closes the delivery loop the same way a manual
  "Mark delivered" click does; that button stays for the out-of-band case
  (handed over in person, etc.). `EmailNotifier.SendWithAttachment` takes a
  variadic list of attachments (not just one) specifically to support the
  certificate-plus-separately-attached-key case in one email.
- **v1.3: bulk renewal is scoped to internal certificates only, and always
  creates fresh records** (`CertificateService.BulkRenewInternal`,
  `POST /certificates/bulk-renew`, `requireWrite`). From the certificate
  vault list, checking several internal + issued rows, picking one Root CA
  and a validity period, and submitting loops over the selection calling the
  same `CreateCSR` + `SignWithRootCA` pair `ApproveInternal` already uses for
  a single ticket — one new certificate record per selected row, the
  original left untouched as history, exactly how a renewal ticket already
  behaves. One bad row (already deleted, wrong trust class, sign failure)
  is reported as a per-row failure rather than aborting the batch —
  `BulkRenewOutcome` carries an `Err` per `CertificateID`. External is
  deliberately out of scope here: there's no CA to call from this app yet
  (see the DigiCert integration below), and even once there is one, that
  stays a single explicit admin click per ticket, not a bulk action — an
  unattended process should never be the thing that submits a batch of paid
  orders to an outside CA. The vault list template only shows a row's
  checkbox when `TrustClass=="internal" AND Status=="issued"`, and the
  "Bulk renew internal" bar only renders when `.RootCAs` is non-empty
  (nothing uploaded yet ⇒ nothing to renew against) — both are
  template-level conveniences, not the actual authorization boundary, which
  is `BulkRenewInternal` itself re-checking `TrustClass()` server-side.
- **v1.3: auto-drafted renewal tickets track a certificate's origin ticket
  by querying `result_certificate_id` in reverse, not via a new column on
  `certificates`** (`CertificateRequestService.AutoDraftRenewals`, sibling
  `RenewalSweeper`, `RENEWAL_SWEEP_INTERVAL`). `certificate_requests.
  result_certificate_id` already links a ticket forward to the certificate
  it produced (since v1.2); `LatestByResultCertificateID` just queries it
  the other way to answer "who originally requested this certificate" —
  adding a symmetric `origin_ticket_id` column on `certificates` was
  considered and rejected as a redundant, independently-maintained copy of
  the same fact. The consequence worth knowing: a certificate that reaches
  this app any other way — generated directly in the vault, or produced by
  `BulkRenewInternal` above — has no ticket with a matching
  `result_certificate_id`, so it has no resolvable requester and the
  sweeper silently skips it. This is an accepted gap, not a bug: an
  auto-drafted ticket exists specifically to notify *someone* that a
  renewal is due, and a vault-only or bulk-renewed certificate has nobody
  in particular to notify. A ticket-driven renewal chain (ticket → cert →
  auto-drafted renewal ticket → cert → …) stays traceable indefinitely,
  since each new ticket in the chain sets its own `result_certificate_id`.
  Auto-drafting is scoped to internal certificates only, for the same
  unattended-action reason bulk renewal is. `AutoGenerated` (new boolean
  column, migration `0011_ticket_auto_generated.sql`) is a pure display
  flag — a violet "Auto"/"Auto-drafted" badge on the ticket queue, ticket
  detail, and the requester's own ticket list — an auto-drafted ticket is
  approved, rejected, fulfilled, or cancelled through exactly the same
  paths as any other. Duplicate prevention is a separate check
  (`HasOpenRenewalFor`: does a pending/in-progress ticket already name this
  certificate as `existing_certificate_id`) run before every draft, so a
  12-hour sweep interval never piles up repeat tickets for a certificate
  that's been sitting in the warning window for days. `RENEWAL_SWEEP_INTERVAL`
  is optional (empty = feature off, same convention as `SMTP_HOST`/
  `TEAMS_WEBHOOK_URL`) — an operator can keep the app purely reactive if
  they'd rather editors/admins notice expiring certificates themselves.
- **v1.3: the DigiCert renewal integration's wire format is unverified —
  there were no live CertCentral API credentials available while building
  it** (`internal/pkg/digicert`, `DigiCertService`, `DIGICERT_API_KEY`/
  `DIGICERT_BASE_URL`). Every JSON request/response shape and endpoint path
  in `internal/pkg/digicert/client.go` is a best-effort reading of DigiCert's
  public docs, not something exercised against a real account — that
  uncertainty is deliberately isolated to that one file behind the `Client`
  interface (`SubmitOrder`/`SubmitReissue`/`OrderStatus`/
  `DownloadCertificate`), so a wrong payload shape only requires fixing that
  file once real credentials are available; `DigiCertService`'s own tests
  run against a fake `Client`, never `HTTPClient`. **Before pointing this at
  production**, get a CertCentral sandbox (or production) account and run
  through this checklist by hand: (1) set `DIGICERT_API_KEY`/
  `DIGICERT_BASE_URL` and confirm the server logs "DigiCert integration
  enabled" at boot; (2) create an external renewal ticket against a real
  certificate in the vault, approve it, click "Submit to DigiCert" on the
  ticket detail page, and confirm the order actually appears in the DigiCert
  dashboard — if it 500s or errors here, the request shape in
  `orderRequestBody`/`SubmitOrder`'s endpoint path is what to fix; (3) click
  "Check status" and confirm it reflects the dashboard's real status string;
  (4) once DigiCert issues it, click "Check status" again and confirm the
  ticket reaches Fulfilled with a real, valid certificate attached (`openssl
  x509 -in ... -noout -dates` to confirm it's genuine, same check used
  throughout this project); (5) renew that same certificate a second time
  and confirm `SubmitReissue` (not `SubmitOrder`) fires, since it now
  carries a `DigiCertOrderID`. Scoping decisions made without live
  verification, worth knowing before extending this: submission is
  restricted to an **in-progress external renewal ticket naming an existing
  certificate** — a brand-new external certificate has no prior
  subject/SANs to seed the CSR from and still goes through
  `FulfillExternal`'s manual paste flow; submission is a single explicit
  admin click per ticket, never automatic on approval or from the
  auto-draft sweeper, since an unattended process should never submit a
  paid order to an outside CA on its own. Fulfillment reuses
  `CertificateService.AttachCertificate`, not `Import` — a deliberate
  divergence from how `FulfillExternal`'s manual-paste path works: a
  manually-pasted external certificate brings its own key from outside (or
  none at all), while a DigiCert submission generates the key pair *inside*
  this app to build the CSR DigiCert signs, so that key is already stored
  against a pending vault record (`Submit`'s `PendingCertificateID`) and the
  eventual certificate must be matched to it, not imported as a fresh
  record. `DigiCertOrderID` on `domain.Certificate` and
  `ExternalProvider`/`ExternalOrderRef`/`ExternalOrderStatus`/
  `PendingCertificateID` on `domain.CertificateRequest` (migration
  `0012_digicert_integration.sql`) exist solely for this integration and are
  empty/nil for every certificate and ticket that never touches it.
- **v1.4: LDAP authentication — admin always signs in locally, every other
  role always signs in via LDAP once it's configured, never a per-account
  choice** (`internal/pkg/ldapauth`, `AuthService.Login`/`ldapLogin`/
  `resolveLDAPRole`, `domain.AuthSource`, `LDAP_*` config). `LDAP_URL` is the
  "empty = off" toggle, same convention as `SMTP_HOST`/`TEAMS_WEBHOOK_URL`/
  `DIGICERT_API_KEY`: unset, every account authenticates with a local
  password exactly as before this feature existed. Once set,
  `AuthService.Login` branches on the account's **role**, not its
  `AuthSource` or whether it exists locally yet: a `role == admin` account
  (found by email) always takes the local password + MFA path, full stop —
  admin is never LDAP-derived, confirmed explicitly rather than assumed, so
  there is deliberately no `LDAP_ROLE_MAP_ADMIN`. Every other case — the
  email doesn't exist locally at all, or it does but its role isn't admin —
  goes through `ldapLogin`: search-then-bind against the directory (service
  account binds and searches by `LDAP_USER_FILTER`, then a **second**
  connection binds as the found DN with the submitted password — never
  re-binding the first connection, since a directory's ACLs may not let an
  ordinary user read group membership, so the group search has to happen
  while still bound as the service account), then `resolveLDAPRole` maps the
  entry's group DNs onto a role via `LDAP_ROLE_MAP_EDITOR`/`_VIEWER`/
  `_REQUESTER` (checked in that order — most-privileged matching group
  wins). No match on any configured mapping is a **hard fail-closed
  denial**, logged at `slog.Warn` with the email, DN, and full group list for
  an admin to diagnose, not a silent low-privilege provision. A first-ever
  successful LDAP login JIT-provisions the local account row (`AuthSource:
  ldap`, `PasswordHash`: `lockedPasswordHash()` — a bcrypt hash of a random
  value nobody knows, since the column is `NOT NULL` but nothing must ever
  verify against it); every later LDAP login **re-syncs** `Role`/
  `AuthSource` rather than trusting what was provisioned once — LDAP is the
  standing source of truth for a non-admin account's role for as long as
  `LDAP_URL` stays set, not just a provisioning hint, so a group change in
  the directory takes effect at the very next login, promotion or demotion.
  MFA stays mandatory regardless of source (confirmed explicitly, per the
  locked decision above) — a fresh LDAP account still walks through
  `/account/mfa/enroll` before it can do anything else, exactly like a fresh
  local one. **Consequence worth knowing, and confirmed rather than
  inferred**: a **pre-existing local non-admin account** (created before
  `LDAP_URL` was ever set) loses its local password the moment LDAP is
  turned on — the branch is on role, not on how the account was created —
  and must authenticate via LDAP under the same email from then on, or not
  at all if that email has no LDAP entry or resolves to no mapped group.
  Live-verified end to end against a real slapd 2.6.10 instance seeded with
  `uid=alice`/`bob`/`carol` and `groupOfNames` groups (see
  `internal/pkg/ldapauth/client_live_test.go`'s doc comment for the exact
  seed data): JIT provisioning, MFA enforcement on the new account, role
  re-sync on a group change, fail-closed denial (with the login-attempts row
  recorded) for a user in no mapped group, the pre-existing local
  editor/admin split above, and both server-side guards below — via the
  actual running HTTP server, not just service-level unit tests.
  `UpdateRole` **refuses to promote an LDAP-sourced account to admin** —
  such an account has no usable local password to fall back on once it
  stopped authenticating via LDAP (which is exactly what promoting it to
  admin would immediately require), so the users admin page hides the
  "Admin" option from an LDAP account's role `<select>` and the server
  rejects it too if posted directly. `ResetPassword` similarly **refuses an
  LDAP-sourced account** for the same underlying reason — resetting a
  password nothing ever checks would look like it worked while changing
  nothing — and the users admin page hides the "Reset password" control for
  the same accounts (both confirmed live via a raw POST bypassing the
  hidden UI control, not just via the hidden markup). Unlike
  `internal/pkg/digicert` — a proprietary, credential-gated REST API with no
  test account available — LDAP is a standardized protocol with a mature
  open-source server, so `LDAPClient` earns the stronger verification bar: a
  real `slapd`/`ldap-utils` test instance, not only a fake `Client` (used in
  `AuthService`'s own tests, `fakeLDAPClient` in `auth_service_test.go`).
  `LDAP_ROLE_MAP_*` values are **semicolon-, not comma-separated** — caught
  during live verification: a bare comma-split silently shredded a group DN
  like `cn=sslgen-editors,ou=groups,dc=example,dc=com` into four bogus
  single-RDN entries, since a DN's own syntax is comma-delimited (see
  `optionalListSep` in `internal/config/config.go` and
  `TestOptionalListSepSplitsOnGivenDelimiterNotComma`). `LDAP_BIND_PASSWORD`
  is Docker-secrets-eligible, same as `SMTP_PASSWORD`/`TEAMS_WEBHOOK_URL`.
- **v1.5: eleven operational settings moved from `.env`-only to portal-
  editable, admin-only, via a new `app_settings` key/value table** —
  `EXPIRY_WARNING_DAYS`/`EXPIRY_CRITICAL_DAYS`/`EXPIRY_FINAL_DAYS`,
  `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`,
  `ALERT_EMAIL_FROM`/`ALERT_EMAIL_TO`, `TEAMS_WEBHOOK_URL`, and
  `TICKET_SLA_DAYS` (`internal/domain/settings.go`,
  `internal/service/settings_service.go`, `GET/POST /settings`). The user
  explicitly asked for these to be admin-editable from the portal rather
  than requiring a restart — `EXPIRY_WARNING_PERCENT`/
  `EXPIRY_CRITICAL_PERCENT` were deliberately excluded from this list and
  stay env-only/static, per the same request.
  **Seed-once-then-portal-authoritative model**: `SettingsService.Bootstrap`
  runs on every boot (mirroring `AuthService.Bootstrap`'s "safe to call
  every time" shape) but only writes a key that has no row yet, checked
  per-key rather than table-wide — a fresh database seeds every key from
  whatever's in `.env` at that moment (these eleven env vars are now
  optional, read only as that seed), and every later boot leaves
  already-seeded keys alone, portal/database authoritative from then on. A
  future new setting key still gets seeded from its env fallback on the
  first boot after it's added, without disturbing any key an admin already
  edited. The generic day-threshold cross-field validation (critical &le;
  warning, final &le; critical) moved from `config.Load` to
  `SettingsService.Update` for the same reason: it's no longer meaningful
  to fail boot over a seed value once the portal governs the live setting.
  **Live effect, no restart**: every consumer reads
  `SettingsService.Current()` at the point of use rather than being handed
  a frozen struct at construction — `CertificateService.Thresholds`,
  `AlertService.levelFor`, `CertificateRequestService.SLADays` all do this.
  `EmailNotifier`/`TeamsNotifier` are rebuilt fresh from `Current()` on
  every send (`SettingsService.EmailNotifier`/`TeamsNotifier`) rather than
  held as fixed fields on the services that use them — both notifiers are
  cheap, stateless config holders (no persistent SMTP connection or open
  socket), so "always current" costs nothing and needed no update-hook
  plumbing across `AlertService` and `CertificateRequestService`.
  **`APP_ENCRYPTION_KEY` is handled completely differently** from the other
  ten — the user was asked explicitly how the portal should treat it, since
  it's the AES key encrypting every private key already stored in the
  vault, and chose the highest-risk, most-capable option: **fully
  portal-editable, with atomic re-encryption of every stored key on every
  change** (`CertificateService.RotateEncryptionKey`,
  `POST /settings/encryption-key`). This is NOT part of
  `SettingsService`'s generic get-all/update surface —
  `domain.SettingEncryptionKey` is excluded from `settingKeys`/`AppSettings`
  entirely and read through its own `SettingsService.EncryptionKeyValue`,
  which deliberately bypasses the cached snapshot so the key value never
  sits in a struct that gets copied, logged, or rendered as casually as
  every other setting. Rotation is one atomic cross-table Postgres
  transaction (`internal/repository/postgres/
  encryption_rotation_repository.go`, behind its own narrowly-scoped
  `domain.EncryptionRotationRepository` interface — deliberately not folded
  into `CertificateRepository` or `SettingsRepository`, since it's the one
  operation in this app that can corrupt every stored private key if it
  goes wrong): `FOR UPDATE`-locks every `certificates`/`root_cas` row with
  a non-empty `private_key_pem`, decrypts each under the old sealer and
  re-encrypts under the new one, then upserts the new key into
  `app_settings` — all in the same transaction, so a single row failing to
  decrypt (a real signal the old sealer doesn't actually match what's
  stored) rolls back everything, including the new key, rather than
  leaving anything partially re-encrypted. `CertificateService`'s own live
  sealer (`atomic.Pointer[secret.Sealer]`, swapped via `CertificateService.
  currentSealer`) is only updated after that transaction commits
  successfully — confirmed live (see below) that a freshly-rotated key
  decrypts a certificate's private key and signs with a Root CA's private
  key immediately, no restart, and again correctly after a full process
  restart (reading the rotated value from `app_settings`, not the stale
  `.env` seed). An empty new-key value is honored the same way `.env`'s
  original empty `APP_ENCRYPTION_KEY` always was — encryption disabled,
  every affected key re-"encrypted" as plaintext — so the rotation endpoint
  doubles as the only way to turn encryption on or off after first boot,
  not just change the key.
  **Security tradeoff, worth stating plainly since it's a real posture
  change**: this moves the vault's encryption key from a process
  environment variable into the same Postgres database it protects. A
  database-only compromise (a leaked backup, a misconfigured replica) that
  previously exposed only ciphertext now exposes the key alongside it. The
  user chose this tradeoff explicitly, in exchange for not needing shell
  access to the host to rotate the key — accepted, not unnoticed.
  **`SMTP_PASSWORD` and `TEAMS_WEBHOOK_URL` are stored as plain text in
  `app_settings`, not `Sealer`-encrypted** — a deliberate scope-limiting
  choice to keep the encryption-key-rotation transaction narrowly scoped to
  the two tables that actually need it (`certificates`, `root_cas`) rather
  than also entangling the generic settings table; both were already
  un-encrypted in `.env` (a plain environment variable, no encryption at
  rest either) and remain Docker-secrets-eligible via `SMTP_PASSWORD_FILE`/
  `TEAMS_WEBHOOK_URL_FILE` for the first-boot seed. Both are write-only
  fields in the `/settings` UI: the real stored value is never pre-filled
  into the form (confirmed live — grepping a fetched `/settings` page for
  the actual stored secret values finds neither), a blank submission keeps
  whatever's already stored, and an explicit "clear" checkbox is the only
  way to wipe one — this is what stops a routine settings save from
  accidentally erasing a working credential just by loading and re-saving
  the page.
  `AuditSettingsUpdated` and `AuditEncryptionKeyRotated` are separate audit
  actions on purpose: the former is a routine, low-stakes edit, the latter
  re-encrypts every stored private key and carries the
  `domain.RotationResult` counts in its detail field so the audit trail
  shows the blast radius, not just "it happened." Both the general
  `/settings` form and the encryption-key danger zone are admin-only
  (`requireAdmin`), the same tier as Root CA management and chain editing,
  not `requireWrite` — these settings govern alerting/ticket behavior
  app-wide, and the encryption-key section lives on the same page.
  Live-verified end to end against a real running server and Postgres
  instance: first-boot seeding from `.env` (confirmed via the boot log's
  "settings: seeded initial values from .env" line), a live `/settings`
  edit taking effect immediately with no restart (confirmed the updated
  values render on the very next page load and the SLA/threshold change is
  visible), a full encryption-key rotation against a real generated
  certificate and a real uploaded Root CA (confirmed both the certificate's
  downloaded private key and a fresh Root-CA-signed certificate work
  correctly immediately after rotation, and again after a full process
  restart), the audit log entries for both actions, and that the write-only
  SMTP password/Teams webhook fields never appear in rendered HTML.
- **v1.6: the Issuers page can also generate a brand-new Root CA in-app,
  alongside the existing upload flow** (`certutil.GenerateRootCA`,
  `CertificateService.GenerateRootCA`, `POST
  /certificates/issuers/root-cas/generate`, `requireAdmin`) — the follow-up
  `domain.RootCA`'s own doc comment had flagged since v1.1 ("deliberately
  upload-only... a natural follow-up, not built here"). `certutil.
  GenerateRootCA(subject, spec, validDays)` builds the self-signed
  certificate directly from an `x509.Certificate` template — `IsCA: true`,
  `KeyUsageCertSign`/`KeyUsageCRLSign`, no CSR intermediate step — rather
  than routing through `CreateCSR` + `SelfSign` the way the existing test
  fixture (`buildTestRootCAPEMs`) does; the two-step route works but a CSR
  whose only purpose is to be immediately self-signed by its own key is
  pure overhead once nothing else needs to inspect that intermediate CSR.
  Deliberately carries no `ExtKeyUsage` at all, unlike a leaf: a root's job
  is signing other certificates, not authenticating as a TLS endpoint
  itself. Defaults to a 10-year validity (`validDays <= 0`) — much longer
  than `SelfSign`/`SignWithCA`'s 365-day leaf default, matching how long a
  root is actually expected to live. `CertificateService.GenerateRootCA`
  is UploadRootCA's sibling, not a variant of it: same persistence tail end
  (seal the key via `currentSealer().Seal`, capture the same display
  fields, `s.rootCAs.Create`), but skips every check that only makes sense
  for material arriving from outside (parse, IsCA check, key-match check) —
  freshly generated material is correct by construction. The HTML form
  (`templates/partials/root_ca_section.html`, never
  `templates/pages/certificate_issuers.html` — see the v1.1 template-
  placement decision above) is a second `<details>` block, a sibling of
  "Upload a Root CA" inside the same admin-gated section, reusing the
  identical key-algorithm/bits/curve select markup (and `data-key-rsa`/
  `data-key-ecdsa` toggle via `static/app.js`, keyed on the `name` attribute
  rather than element `id`, so both forms can coexist on one page) already
  established by the certificate-generation form on `/certificates`.
  `AuditRootCAGenerated` is a separate audit action from
  `AuditRootCAUploaded` — same tier (routine, not a rotation-level event),
  but worth distinguishing in the trail since the two paths mean different
  things happened (a new keypair was born here vs. brought in from
  outside). Live-verified end to end against a real running server: a
  generated RSA-4096 CA (self-signed, `Subject == Issuer`, `CA:TRUE`,
  `Certificate Sign` key usage, confirmed with `openssl x509 -text`), a
  generated ECDSA P-384 CA, immediately signing a real pending CSR with the
  generated CA (the issued leaf verifies against the generated CA's
  certificate via `openssl verify -CAfile`), the missing-common-name
  validation path returning a flash error rather than a 500, and the audit
  log recording both generations correctly.
- **v1.7: encryption-key rotation runs as an async, polled job with a real
  progress bar, not a synchronous request that leaves the admin staring at
  a frozen button** (`CertificateService.StartEncryptionKeyRotation`/
  `EncryptionKeyRotationStatus`/`MarkRotationReported`, `POST
  /settings/encryption-key` + `GET /settings/encryption-key/status/{id}`).
  The user explicitly doubted the v1.5 rotation feature actually worked,
  which is what prompted this — on a vault with more than a handful of
  private keys, the original fully-synchronous handler really did just
  block the request for however long the transaction took, with nothing on
  screen to distinguish "working" from "hung." `StartEncryptionKeyRotation`
  validates the new key up front (so a malformed key fails immediately,
  before any job exists), refuses to start a second rotation while one is
  already in flight, then launches the actual work in a goroutine against
  `context.Background()` — deliberately not the request context, so a
  client navigating away or closing the tab never cancels a rotation
  that's already touching private key material — and returns a job ID
  immediately. A `rotationJob` (mutex-guarded, tracked via
  `atomic.Pointer[rotationJob]` on `CertificateService`) is what the
  status endpoint polls; `EncryptionRotationRepository.RotateEncryptionKey`
  gained a `progress func(done, total int)` parameter that fires
  synchronously from *inside* the still-open transaction — once with
  `(0, total)` as soon as the row count across both tables is known, then
  once per row re-encrypted. This is why a caller sees a real "30 of 47,"
  not a fake animation — but it is only ever a report of work done inside
  a pending transaction, not a durability guarantee: a failure after that
  point still rolls everything back, exactly as before this existed. The
  htmx side is the same self-re-triggering `hx-trigger="load
  delay:400ms"` pattern already used by the dashboard's `every 60s`
  auto-refresh — no new client-side mechanism, just the existing idiom
  applied to a progress view instead of a summary panel. `reported`
  (mutex-guarded on `rotationJob`, exposed via `MarkRotationReported`) is
  what guarantees the audit entry — with its `RotationResult` counts —
  gets recorded exactly once no matter how many times the status endpoint
  is polled after the job finishes, including a poll that lands after a
  process restart wiped the in-memory job (the handler falls back to
  rendering the plain settings section rather than a stuck progress bar in
  that case). Live-verified end to end against a real running server: a
  rotation that atomically rolled back on a row that failed to decrypt
  under the current key (two pre-existing corrupted dev-database records —
  see the v1.6 Root CA section's own gotcha note — correctly aborted the
  whole transaction with the encryption key left unchanged, confirming
  atomicity held under a real failure, not just the unit tests' simulated
  one), then a clean rotation of 15 real generated certificates reporting
  `(0,15)` through `(15,15)`, the re-encrypted key immediately decrypting
  and validating correctly afterward (`POST /certificates/{id}/validate`),
  exactly one `AuditEncryptionKeyRotated` entry despite multiple polls
  after completion, and the general settings section rendering again
  cleanly once the job was done.
  - **Gotcha hit — and initially missed — while building this**: the
    button did not actually work in a real browser at first, despite every
    curl-driven check above passing. `templates/pages/settings.html`
    rendered the danger-zone section by calling
    `{{template "settings-encryption-section" .}}` directly on a full page
    load, but that define block (`settings_encryption.html`) is a bare
    `<section>` with no `id` on it — only the htmx-response wrapper
    (`settings-encryption-response`/`-progress`) carries
    `id="settings-encryption-section"`. The form's own
    `hx-target="#settings-encryption-section" hx-swap="outerHTML"` needs
    that id to already exist in the DOM to find something to replace, and
    on the very first page load nothing with that id exists yet — so
    clicking "Rotate encryption key" POSTed successfully (the rotation
    really started server-side) but htmx had nowhere to put the response,
    and the button visually did nothing. This is why curl-based
    "live verification" isn't sufficient for anything wired through
    htmx's own targeting: curl only proves the server produces the right
    HTML for a given request, never that the button that's supposed to
    trigger that request is actually connected to anything on the
    rendered page. Caught by a real headless-browser click-through
    (Playwright driving the actual login flow and clicking the actual
    button) after this exact question was asked directly. Fixed by
    wrapping that one line in `settings.html` in
    `<div id="settings-encryption-section">...</div>`, matching the id the
    htmx-response wrapper already used — re-verified with the same
    browser click-through end to end afterward. If another htmx form
    ever gets an `hx-target` pointed at an id, check that id is actually
    present on the *full-page* render, not only on the partial the form's
    own response swaps in.
- **v1.8: LDAP authentication configuration moved from `.env`-only to
  portal-editable**, following the exact seed-once-then-portal-authoritative
  model v1.5 established for the other eleven operational settings — see
  that section above for the general shape (`SettingsService.Bootstrap`
  seeds each of the nine `SettingLDAP*` keys from `.env` only if no row
  exists yet; from then on `/settings` and the database govern the live
  value). This does **not** change any part of the v1.4 authentication
  model itself (admin always local, every other role always LDAP once
  configured, fail-closed on no group match, JIT provisioning, live role
  re-sync on every login, semicolon-not-comma role-map delimiters, the
  refusal to promote an LDAP account to admin or reset its password) —
  only *where the configuration lives and how live it is* changes.
  `AuthService.ldapConfigured()` is the new integration point: instead of
  a static `ldapauth.Client` built once at boot from `config.Config` and
  held in `AuthOptions.LDAP`, `AuthOptions` now carries a `*SettingsService`
  and an `LDAPClientFactory func(ldapauth.Config) ldapauth.Client`;
  `ldapConfigured` reads `Settings.Current()` on every single login
  attempt and rebuilds a fresh client from whatever's live right now —
  cheap and safe because `ldapauth.NewLDAPClient` does no I/O itself, it
  just constructs a value that dials/binds lazily when `Authenticate` is
  actually called, the same "rebuild fresh from `Current()` on every use"
  pattern `SettingsService.EmailNotifier`/`TeamsNotifier` already
  established. `LDAPClientFactory` exists purely for test injection (a
  fake `ldapauth.Client` in `auth_service_test.go`) since
  `ldapauth.NewLDAPClient` returns a concrete `*LDAPClient`, not the
  `Client` interface, so it can't be assigned to a `func(...) Client`
  field directly without a wrapping closure — production always defaults
  to that closure when the factory is left nil. The cross-field validation
  config.Load used to enforce at boot (bind DN/password/base DN/user
  filter/group filter all required once the URL is set, exactly one `%s`
  in each filter, at least one role mapping non-empty) moved to
  `SettingsService.Update`'s new `validateLDAPPatch`, the same v1.5 move
  applied to the day-threshold and DigiCert-adjacent settings: a bad *seed*
  value should never block boot forever, only a bad *live edit* should be
  rejected. The portal form uses one group DN per line in a `<textarea>`
  for each of the three role-map fields, not a comma- or semicolon-joined
  single-line input — a deliberate UI choice (`splitLines`,
  `internal/delivery/http/settings_handler.go`) that sidesteps the
  comma-inside-a-DN problem entirely rather than asking an admin to
  remember a delimiter convention; `ldap_bind_password` is a write-only
  field with the same "blank keeps current, checkbox clears it" pattern
  `smtp_password`/`teams_webhook_url` already use. Live-verified end to end
  against a real running server and a real throwaway `slapd` instance (same
  seed data as the v1.4 verification — `uid=alice`/`bob`/`carol`,
  `sslgen-editors`/`sslgen-viewers` groups): LDAP configured **entirely
  from `/settings`**, with no `LDAP_URL` in `.env` at all, immediately
  allowing `alice` to log in and resolve to `editor` from the portal-saved
  role mapping; `bob` (no group membership) correctly denied with the
  fail-closed log line; a **live edit** to the role mapping (moving
  `carol`'s group from the viewer map to the editor map) took effect on
  her very next login with **no server restart** — she was JIT-provisioned
  as `viewer` on her first login and re-synced to `editor` on her second,
  purely from a portal save in between; and the write-only bind-password
  field correctly preserved its stored value across a settings save that
  left the password field blank.
- **v1.9: the pending-certificate detail page issues a certificate through
  one form with one "Sign with" dropdown, not two separate forms sitting
  side by side** (`POST /certificates/{id}/issue`,
  `handleCertificateIssue`, `CertificateService.GenerateRootCAAndSign`) —
  the two-forms layout (a "Self-sign" form, then a second "Sign with Root
  CA" form with its own dropdown) read as confusing rather than as two
  genuinely different actions, and a vault with no Root CA yet dead-ended
  the second form into a link to the Issuers page instead of just letting
  the admin make one right there. The dropdown now lists exactly three
  kinds of option: "Its own key (self-signed)", every uploaded/generated
  Root CA by name, and "+ Create a new Root CA…" — always present, so
  there's no more dead-end case. `sign_action`'s value is what the single
  handler switches on: empty/`"self"` calls the existing `SelfSign`,
  a Root CA's UUID calls the existing `SignWithRootCA` (both untouched —
  every other caller, `BulkRenewInternal` and `ApproveInternal`, still
  calls them directly as a service method, never through HTTP, so neither
  was affected by removing the two old routes), and `"new"` calls the new
  `GenerateRootCAAndSign`, which is deliberately nothing but
  `GenerateRootCA` followed by `SignWithRootCA` — no shared transaction,
  and that's an intentional choice, not an oversight: if signing fails
  after the CA already exists (the certificate's own stored CSR turns out
  to be unreadable, say), the freshly generated CA is left in place rather
  than rolled back, since it's still a perfectly valid, independently
  useful CA sitting on the Issuers page — unlike encryption-key rotation's
  all-or-nothing multi-row transaction, where a partial result would
  actively corrupt data, losing a freshly generated keypair to a rollback
  here would just be needless waste for a low-stakes, easily-retried
  failure. The "create a new CA" fields (name, subject, key
  algorithm/bits/curve, CA validity) reuse the exact same inputs as the
  Issuers page's own "Generate a Root CA" form and stay hidden until
  "+ Create a new Root CA…" is selected, via the existing generic
  `data-show-when="sign_action:new"` mechanism in `app.js` (already used
  elsewhere for the certificate request form's conditional fields) rather
  than any new JS. A successful "new" submission fires two audit entries —
  `AuditRootCAGenerated` then `AuditCertificateSignedByCA` — the same
  pairing convention a key download alongside a plain cert download
  already uses elsewhere in this app: one action, two things genuinely
  happened, both get their own trail entry. The two old routes
  (`POST /certificates/{id}/self-sign` and
  `POST /certificates/{id}/sign-with-root-ca`) are gone — they existed
  solely to serve this one page's two old forms, confirmed by grepping the
  whole codebase before removing them, so nothing else needed updating
  besides `admin_docs.html`'s description of the endpoint.
  - **Gotcha avoided here, learned from v1.7's rotate-button bug just
    before this**: this feature was live-verified with an actual headless
    browser clicking the actual dropdown and the actual button for all
    three paths (self-sign, an existing CA, and generate-a-new-CA), not
    just equivalent curl requests — curl alone would never have caught an
    `hx-target` pointed at a missing element, which is exactly what went
    wrong with the encryption-key rotation button. One thing the browser
    run did catch that was worth noting for next time: a first attempt at
    the "create new CA" browser test closed the page/browser about 500ms
    after clicking submit, and the in-flight request was cancelled
    server-side (`context canceled`) before a real RSA-4096 keygen had
    finished — not an application bug, just too short a wait in the test
    itself. The certificate involved was left cleanly in `pending` (no
    orphaned CA, no half-issued certificate), which is itself a useful
    confirmation that a cancelled request fails clean here; the real
    verification came from re-running the same click-through with a
    poll-until-the-flash-appears wait instead of a fixed short delay.

- **v1.10: the `/requests` "New request" panel hides itself right after a
  successful submission, but not after a validation error** (`app.js`'s
  `data-hide-on-success` listener, `data-flash-kind` on `flash-body`) — a
  requester submitting a ticket saw the form sit open afterward with a
  stale, already-submitted form still showing, instead of collapsing back
  the way it does when closed by hand. The naive fix — hide the panel on
  any successful `htmx:afterRequest` — is wrong here: every htmx-driven
  partial response in this codebase answers `http.StatusOK` regardless of
  success or failure (confirmed by grepping `certificate_request_handler.go`
  and the wider codebase: `StatusBadRequest`/`StatusUnprocessableEntity`
  are reserved solely for malformed-request parsing failures, never a
  normal validation error), distinguishing only via the flash message's
  `Kind` field — so `event.detail.successful` alone can't tell a real
  submission success from a rejected one (missing common name, etc.), both
  of which look identical at the HTTP layer. Fixed by adding
  `data-flash-kind="{{.Kind}}"` to the shared `flash-body` template (used
  by every OOB flash banner across the whole app, so this one small,
  low-risk attribute addition covers every future use of the same pattern,
  not just this one form) and having the listener check it — it only hides
  the panel when the flash kind isn't `"error"`. `data-hide-on-success="<id>"`
  on a form names the panel to hide (usually the one a
  `[data-toggle-target]` button already opened); when that button exists,
  its label is flipped back to the closed state too, exactly as if the
  panel had been closed by hand. Live-verified both branches with a real
  browser: a valid submission collapses the panel and resets the toggle
  label, while a submission missing the common name leaves the panel open
  with its error flash showing.

- **v1.11: an internal ticket's "Approve & sign" form defaults its SANs
  field to the ticket's common name, mirroring it live** (`ticket_detail.html`'s
  `#ticket-sans` textarea) — the same "default SAN to the CN" convenience
  the certificate-generation page already gives an editor, extended to the
  ticket queue. It can't reuse `app.js`'s existing CN-to-SANs `"input"`
  listener as-is, since that only fires on a live keystroke and the ticket's
  common name arrives already pre-filled server-side, not freshly typed —
  so the default has to be rendered server-side instead:
  `{{if $t.DNSNames}}{{join "\n" $t.DNSNames}}{{else}}{{$t.CommonName}}{{end}}`,
  with `data-auto-filled="1"` set only in the empty-DNSNames branch. That
  attribute is the same marker `app.js`'s own mirror writes on every
  keystroke, so once the field is rendered this way, the *existing* generic
  listener (unmodified) picks up mirroring for free if the approver edits
  the common name before submitting — verified live: editing the common
  name keeps updating SANs for as long as it's still just the auto-filled
  mirror, and typing directly into SANs stops that mirroring for good, even
  if the common name changes again afterward. A ticket with real requester
  DNSNames (a renewal, which copies them from the certificate being
  renewed) takes the other branch entirely — no `data-auto-filled`, shown
  as the actual joined names — so this never touches real content, only
  ever fills an actually-empty field.

- **v1.12: an approved external ticket can generate its own CSR before an
  admin has anything to submit to the outside CA, and pastes the CA's
  answer back into that exact same certificate record** (`GenerateCSRInput`/
  `CertificateRequestService.GenerateCSR`, `POST /tickets/{id}/generate-csr`,
  the ticket detail page's "Generate a CSR" / "CSR generated" sections) —
  previously the only aid an in-progress external ticket offered was
  "Attach the issued certificate", a bare paste-PEM form with an optional
  private-key field; there was no way to build a CSR at all without leaving
  the app. This reuses `PendingCertificateID`, a field that already existed
  on `certificate_requests` for exactly this shape of problem but was
  DigiCert-only until now (`DigiCertService.Submit` sets it the same way,
  seeding the CSR from the certificate being renewed instead of from
  ticket fields typed by hand) — `GenerateCSR` is its manual, no-external-API
  counterpart, and deliberately not renewal-only the way DigiCert submission
  is: DigiCert needs an existing certificate to seed subject/SANs from, but
  a brand-new external certificate has no such certificate yet, so here the
  admin fills the subject fields directly, prefilled from the ticket
  exactly like `ApproveInternal`'s form (SANs defaulting to the common name
  via the same v1.11 mechanism). The payoff is in `FulfillExternal`: when
  `PendingCertificateID` is set, the pasted certificate is attached to that
  same vault record via the existing `AttachCertificate` (matching it to
  the private key already stored there) instead of `Import`-ing a brand-new
  record — so a CSR generated this way, or via DigiCert, is handled
  identically once the certificate comes back, and the paste form's private
  key field is hidden entirely in that case (there is nothing for it to
  do — a stray paste there is simply ignored server-side too). Falls back
  to the original `Import`-based manual flow, unchanged, when no CSR was
  pre-generated. Verified both at the service level (a fake-repo test
  confirms the fulfilled certificate's ID equals the pre-generated one's,
  not a new record, and that a second `GenerateCSR` call on the same ticket
  is rejected) and live end to end: submitted an external ticket, approved
  it, generated a CSR through the UI, signed the extracted CSR PEM with a
  throwaway `openssl` CA standing in for a real external CA, pasted the
  resulting leaf back into "Attach the issued certificate", and confirmed
  in the database that `result_certificate_id` and `pending_certificate_id`
  ended up equal — one certificate row, not two.

- **v1.13: an internal renewal ticket can reuse the certificate being
  renewed's exact CSR and private key instead of always minting a fresh
  one, and the ticket-approval form gained the same full CSR configuration
  the certificate vault's own "Generate" page has, plus seven new EKU
  options** (`CertificateService.CloneCSR`, `ApproveInternalInput.
  ReuseExistingCSR`, `POST /tickets/{id}/approve-internal`). Two requests
  handled together since both touched the same form.
  - **Reuse-the-same-CSR renewal path.** `ApproveInternal` previously always
    called `CreateCSR` — even for a renewal ticket, it silently ignored
    `ExistingCertificateID` and minted a brand-new key pair every time.
    `CertificateService.CloneCSR` is the new alternative: it loads the
    certificate named by the ticket's `ExistingCertificateID`, requires it
    still has its own `CSRPEM` and `PrivateKeyPEM` on file (an issued
    certificate keeps both — `applyIssuedCert` never clears them, confirmed
    before building this), and copies them verbatim — ciphertext as-is, no
    decrypt/re-encrypt — into a **brand-new** pending certificate record
    along with the source's subject/SAN/EKU/key-algorithm fields. The
    source record itself is never touched. This still follows this app's
    standing "a renewal is always a new record, original kept as history"
    convention (`BulkRenewInternal`, ticket-driven renewals) — the new part
    is that the new record's public key is identical to the old one's, not
    freshly generated. `ApproveInternal` branches on
    `ReuseExistingCSR bool`: true requires `Type == RequestRenewal` and a
    non-nil `ExistingCertificateID` (rejected otherwise, before touching
    any certificate), and calls `CloneCSR` instead of `CreateCSR`; either
    way, the resulting record is then signed with `SignWithRootCA` exactly
    as before. The ticket-approval form only offers this choice
    (`csr_source` radio, "Generate a new CSR" default vs. "Reuse the
    existing certificate's CSR") when `CanReuseCSR` is true — the existing
    certificate actually has a reusable CSR/key on file — falling back
    silently to "generate a new CSR only" otherwise (an uploaded-with-no-key
    record, say), the same as a brand-new ticket. **Security tradeoff,
    confirmed explicitly rather than assumed**: reusing a private key
    across a renewal runs against the usual best practice of rotating keys
    on every renewal. The user was asked directly whether "reuse the same
    CSR" should mean literally the same key (vs. same subject/SAN/EKU with
    a fresh key, which would just be "new CSR" pre-filled) and chose the
    literal-key-reuse reading — this is an admin-only, per-ticket, opt-in
    choice, never the default, and the "generate a new CSR" option remains
    one click away on the same form.
  - **Full CSR configuration on ticket approval, for both new and renewal
    tickets.** The "Approve & sign" form only ever exposed common name,
    organization, SANs, key algorithm/bits, curve (P-256/P-384 only), and
    owner — missing organizational unit, country, province, locality,
    email, any EKU selection (hard-wired to the `server_auth`+`client_auth`
    default via `x509ExtKeyUsages`'s fallback, since the handler never sent
    `ExtKeyUsages` at all), notes, and the P-521 curve option, all of which
    the vault's own "Generate a CSR" tab already had. The form now mirrors
    that tab's full field set (same EKU chip-toggle markup, same
    `data-key-rsa`/`data-key-ecdsa` algorithm toggle, same three curve
    options) for both a `new`- and `renewal`-type ticket alike — there was
    no reason for the two ticket types to see different capability here.
    `decorateTicketView` now sets `view["EKUOptions"] =
    certutil.ExtKeyUsageOptions()` whenever the Root-CA list is loaded (the
    same condition gate `RootCAs` already used), and
    `handleTicketApproveInternal` reads `r.PostForm["eku"]` into
    `CSR.ExtKeyUsages`, exactly like `handleCertificateGenerate` already
    does for the vault's own form.
  - **Seven new Extended Key Usage options**, added to the single
    `certutil` vocabulary (`internal/pkg/certutil/csr.go`) so every existing
    call site — the vault's generate form, the ticket approval form, EKU
    summaries/pills on read-only views — picked them up for free with no
    per-call-site changes: `any` (Any Extended Key Usage, OID
    `2.5.29.37.0`), `ipsec_end_system`/`ipsec_tunnel`/`ipsec_user` (OIDs
    `1.3.6.1.5.5.7.3.5`/`.6`/`.7`), `smart_card_logon` (Microsoft OID
    `1.3.6.1.4.1.311.20.2.2`), `document_signing` (Microsoft Document
    Signing, OID `1.3.6.1.4.1.311.10.3.12` — confirmed with the user this
    meant the Microsoft/Authenticode OID, not Adobe's PDF signing, which
    doesn't define a distinct EKU OID at all), and `efs` (Encrypting File
    System, Microsoft OID `1.3.6.1.4.1.311.10.3.4`). The first four map onto
    `x509.ExtKeyUsage` constants the standard library already defines
    (`ekuToX509`); the last three don't — Go's `x509.ExtKeyUsage` enum
    simply has no constant for them — so they're carried through
    `x509.Certificate`'s separate `UnknownExtKeyUsage []asn1.
    ObjectIdentifier` field instead (new `ekuUnknownOIDs` map).
    `x509ExtKeyUsages` was reshaped to return both `(known []x509.
    ExtKeyUsage, unknown []asn1.ObjectIdentifier)` so `SelfSign`/`SignWithCA`
    can set both `ExtKeyUsage` and `UnknownExtKeyUsage` on the certificate
    template — the standard library merges both into one extended-key-usage
    extension on issue, so from the outside a `smart_card_logon` cert looks
    no different from a `code_signing` one. `DescribeExtKeyUsage` (reading
    an issued/uploaded certificate back) was extended to also scan
    `cert.UnknownExtKeyUsage` against `ekuUnknownOIDs`, so round-tripping any
    of the three "unknown" keys through self-sign, CA-signing, or importing
    a certificate that carries one of these OIDs from outside all correctly
    report the right label. The CSR extension-request path
    (`extKeyUsageExtension`, used to ask a CA to honour a requested EKU) was
    already purely OID-based via `ekuOIDs` and needed no change beyond
    adding entries for all seven new keys — it never depended on the
    standard library's enum in the first place. Covered by new tests in
    `certutil_test.go`: the four builtin-mapped keys round-trip through
    `SelfSign`, the three unknown-OID keys round-trip through both
    `SelfSign` and `SignWithCA` (confirming `UnknownExtKeyUsage` is actually
    populated and `ExtKeyUsage` stays empty for them), and
    `ExtKeyUsageOptions()` now lists all 13 keys.
  - **Unrelated pre-existing build break fixed in passing**: `cmd/server/
    main.go` still constructed `service.AuthOptions{LDAP: ldapClient,
    LDAPRoleMap: ...}` — fields that no longer exist on `AuthOptions` since
    v1.8 moved LDAP configuration to `SettingsService` (`Settings
    *SettingsService`, read live via `Settings.Current()` on every login
    attempt, per that section above). This left `go build ./...` broken at
    HEAD before this work started, unrelated to either feature above — it
    surfaced immediately when building to verify this change. Fixed by
    passing `Settings: settingsSvc` (already constructed earlier in `run()`
    for `SettingsService.Bootstrap`) and deleting the dead
    `ldapClient`/`ldapauth.NewLDAPClient` construction, which nothing else
    used once `AuthOptions` stopped taking a pre-built client. Also added
    the nine `LDAP*` fields to `main.go`'s `SeedValues.Settings` block,
    which was similarly missing them — without this, a fresh database would
    never seed LDAP settings from `.env` at all, silently leaving LDAP off
    until someone configured it by hand from `/settings`.
  - **Verification status, stated plainly**: `go build ./...`, `go vet
    ./...`, and `go test ./...` all pass, including new tests for
    `CloneCSR`/`ReuseExistingCSR` (a renewal that reuses a CSR produces a
    new certificate ID with an identical decrypted private key and CSR PEM
    to the source, rejects a non-renewal ticket, and rejects a source
    certificate with no stored key) and the new EKU options (see above), and
    `NewRenderer()` parses every template including the reworked ticket
    detail form with no error. **Live browser verification was not
    completed** — Docker Desktop would not bring its daemon up in this
    session (hung indefinitely past its normal few-second failure), and no
    local Postgres/`.env` was available as a fallback the way earlier phases
    used one. Unlike every phase before it, this section is **not**
    end-to-end confirmed against a running server — before trusting this in
    production, run through it by hand once Docker (or a local Postgres) is
    available: submit and approve a renewal ticket both ways (new CSR and
    reuse-existing-CSR, confirming the reused case's certificate shares its
    predecessor's public key/CSR), and generate+sign a new-type ticket
    through the expanded form with a non-default EKU selected (including at
    least one of the three new unknown-OID keys) to confirm the issued
    certificate actually carries it.

- **v1.14: ADCS (Active Directory Certificate Services) CES/CEP integration
  — a fourth "sign with" option on the pending-certificate detail page**
  (`internal/pkg/adcs`, `CertificateService.SignWithADCS`/`SetADCSClient`/
  `ADCSEnabled`, `POST /certificates/{id}/issue` with `sign_action=adcs`).
  Alongside self-sign, an in-app Root CA, and generate-a-new-Root-CA
  (v1.9's unified dropdown), an admin can now submit a pending certificate's
  stored CSR straight to a real Microsoft ADCS server and have it applied
  the moment ADCS issues it — no CSR export/re-import round trip needed.
  - **Scope decisions, made explicitly rather than assumed** (the user was
    asked before any code was written, since each materially changes the
    implementation): **username/password authentication**, not Windows
    Integrated (Kerberos) or client-certificate — the only one of ADCS's
    three CES auth profiles that works from a non-domain-joined,
    cross-platform Go process with no extra OS-specific dependency (no
    gokrb5, no SSPI). **CES only, no CEP** — policy discovery (MS-XCEP) is
    skipped entirely; the CA endpoint and certificate template name are
    fixed admin config (`ADCS_ENDPOINT`/`ADCS_TEMPLATE`), the same "fixed
    config, not discovered" shape `internal/pkg/digicert` already uses for
    its base URL. **A synchronous sign_action, not an async ticket-tracked
    flow like DigiCert** — ADCS is an internal CA issuing (in the common
    case) near-instantly, so this is modeled like `SelfSign`/
    `SignWithRootCA`: one request, one response, done — not
    `DigiCertService`'s submit-then-poll pattern with its own order-status
    tracking. A template requiring manual approval on the ADCS side returns
    a *pending* disposition with no certificate; `SignWithADCS` treats that
    as a plain error, since this app has no concept of an async wait on an
    internal signing path.
  - **Wire protocol**: MS-WSTEP (`RequestSecurityToken`/
    `RequestSecurityTokenResponse`, WS-Trust 1.3's "Issue" binding) over
    HTTPS, authenticated via a WS-Security `UsernameToken` (`PasswordText`,
    relying on the endpoint being HTTPS for confidentiality — the same
    assumption ADCS's own username/password CES profile makes). The
    request is built via `text/template` (`requestEnvelopeTemplate` in
    `internal/pkg/adcs/wstep.go`) rather than `encoding/xml` struct
    marshaling — WS-Security's namespace-prefixed, attribute-order-
    sensitive shape is far easier to get byte-for-byte right against
    Microsoft's published examples this way, and every dynamic value
    (username, password, endpoint, template name) is escaped through the
    template's `xmlesc` func. The certificate template is sent as a WS-Trust
    `AdditionalContext` item (`Name="CertificateTemplate"`), since a
    from-scratch PKCS#10 request this package builds carries no Microsoft
    template extension of its own — that's what a CEP-driven Windows client
    would normally stamp onto the request itself.
  - **Response parsing is deliberately lenient on namespaces**: the
    response structs (`internal/pkg/adcs/wstep.go`) use unqualified,
    namespace-less `encoding/xml` tags, which match a local element name
    regardless of its namespace URI — chosen because there's no live server
    to confirm exactly which namespace a given ADCS/IIS/WCF version
    actually uses, and Microsoft's own published examples aren't fully
    consistent about it either. The issued certificate arrives as a
    `BinarySecurityToken` wrapping a base64 "degenerate" PKCS#7 (certs
    only, no signature) — decoded via `go.mozilla.org/pkcs7`, the one new
    dependency this integration adds (no PKCS#7 support exists in Go's
    standard library, and hand-rolling ASN.1 parsing for it would be pure
    reinvention). **Ordering the returned certificates is correctness, not
    formatting**: a degenerate PKCS#7's certificate list is an unordered
    ASN.1 SET, so nothing guarantees the issued leaf is `Certificates[0]`
    the way it would be for a normally signed PKCS#7 —
    `orderCertificatesFromCSR` identifies the leaf by matching each
    returned certificate's public key against the original CSR's, not by
    assuming an order.
  - **`domain.Certificate` gained two fields**: `SignedByADCS bool` (the
    trust-class-affecting marker — `TrustClass()` now treats it the same
    as `SelfSigned`/`SignedByRootCAID != nil`: internal, since it's the
    org's own CA, not a publicly-trusted one) and `ADCSRequestID string`
    (purely informational — the request/serial ID ADCS's response reported,
    for looking the request up on the CA server later; may be empty even
    when `SignedByADCS` is true if the response didn't carry one). Unlike
    `SignedByRootCAID *uuid.UUID`, this is a plain bool rather than a
    foreign key — there's no in-app CA record to point at, ADCS's own CA
    lives entirely outside this app (migration `0015_adcs_integration.sql`).
  - **Config follows the DigiCert integration's exact "empty = off"
    pattern**: `ADCS_ENDPOINT` unset disables the whole integration (the
    "Submit to ADCS" option simply doesn't render); once set,
    `ADCS_USERNAME`/`ADCS_PASSWORD`/`ADCS_TEMPLATE` are all required, same
    fail-fast-at-boot cross-field check `DIGICERT_BASE_URL` gets.
    `ADCS_PASSWORD` is Docker-secrets-eligible via `ADCS_PASSWORD_FILE`,
    same convention as `SMTP_PASSWORD`/`TEAMS_WEBHOOK_URL`/
    `LDAP_BIND_PASSWORD`. Deliberately **env-only, not portal-editable** —
    matching DigiCert's own config, not the v1.5/v1.8 pattern LDAP/SMTP/
    Teams moved to; nothing about this decision is ADCS-specific, it's just
    staying consistent with how the other outside-CA integration is
    already configured.
  - **Verification status, stated plainly — same caveat
    `internal/pkg/digicert` already carries, and for the same reason**:
    there is no real ADCS server available to test against in this
    environment (it's a Windows Server role requiring AD infrastructure,
    not something installable in a quick local sandbox the way `slapd` was
    for the LDAP integration's live tests). What *is* verified: `go build`/
    `vet`/`test ./...` all pass; `internal/pkg/adcs`'s own tests exercise
    the full request→response round trip against a real `httptest.Server`
    — the server itself decodes the sent SOAP/WS-Security XML and asserts
    the username, template, and CSR bytes all arrived correctly, then
    returns a real, correctly-shaped RSTR response (built with a real
    `go.mozilla.org/pkcs7`-encoded degenerate certificate, not a stub) for
    the client to parse back into an `EnrollResult` — proving the request
    is well-formed SOAP+WS-Security and the response parser round-trips a
    correctly-shaped real response, not that a real ADCS server will
    accept or answer it identically. SOAP fault handling, a pending-
    disposition rejection, and the leaf-reordering-by-public-key logic all
    have dedicated tests too. `CertificateService.SignWithADCS` is tested
    against a fake `adcs.Client` (mirroring `fakeDigiCertClient`), covering
    `TrustClass()`/`SignedByADCS`/`ADCSRequestID` end to end at the service
    layer. **Before pointing this at production**, get access to a real
    ADCS test server and CES endpoint configured for username/password
    auth, then run through this checklist: (1) set `ADCS_ENDPOINT`/
    `ADCS_USERNAME`/`ADCS_PASSWORD`/`ADCS_TEMPLATE` and confirm the server
    logs "ADCS integration enabled" at boot; (2) generate a pending CSR in
    the vault, open its detail page, pick "Submit to ADCS" from the "Sign
    with" dropdown, and confirm a certificate actually comes back — if it
    errors here, the SOAP envelope shape in `buildRequestEnvelope` or the
    endpoint/auth configuration is what to check first (the error message
    will include ADCS's own SOAP Fault reason when there is one, e.g.
    "Access is denied." for a bad username/password or missing Enroll
    permission on the template); (3) confirm with `openssl x509 -in ... -
    noout -issuer -subject -dates` that the issued certificate's issuer is
    really the ADCS CA and its validity matches the template's configured
    policy, not the "Valid for" days field (which this path ignores); (4)
    confirm `TrustClass()` reads as Internal on the certificate list/detail
    page; (5) if the template involved has a chain (an issuing CA under a
    root), confirm the chain came back correctly ordered — download the
    full chain and verify it with `openssl verify -CAfile <root>
    -untrusted <intermediate> <leaf>`; (6) try a template that requires
    manual approval and confirm the pending-disposition case surfaces a
    clear error rather than silently doing nothing.

- **v1.15: seven fixes reported directly by the user after using the app**,
  handled together in one pass, technical docs updated as the last step per
  the user's own instruction.
  1. **The users admin page's role `<select>` was missing `name="role"`.**
     `templates/partials/user_table.html`'s per-row role dropdown
     (`hx-post="/users/{id}/role"`) had every other htmx attribute but no
     `name` attribute at all — htmx has nothing to serialize without one, so
     every role change silently posted an empty body and
     `handleUserRoleUpdate`'s `r.PostFormValue("role")` read `""`. One
     missing attribute; the "create new user" form's own role select right
     above it on the same page was fine, which is presumably why this went
     unnoticed for a while. Fixed by adding `name="role"`.
  2. **Local `.env` vs. server `/run/secrets/<name>` — three integrations
     (DigiCert, LDAP, and the brand-new ADCS from v1.14) were never wired
     into either Docker deployment path at all**, only reachable via
     `make run`/`go run` (which loads `.env` directly into the process via
     `loadDotEnv`, bypassing Docker's environment layer entirely).
     `docker-compose.yml`'s `environment:` block only passes through
     variables it explicitly lists — a var missing from that list never
     reaches the container regardless of what `.env` says — and
     `DIGICERT_API_KEY`/`DIGICERT_BASE_URL`/every `LDAP_*` var/every
     `ADCS_*` var (plus `RENEWAL_SWEEP_INTERVAL`) were all simply absent
     from it. Fixed by adding all of them (mirroring the existing
     `${VAR:-default}` convention). `docker-stack.yml` (the Swarm/production
     path) had the same gap for the non-secret half of each, and additionally
     never created `ssl_tower_ldap_bind_password`/`ssl_tower_adcs_password`
     Docker secrets at all even though both `LDAP_BIND_PASSWORD` and
     `ADCS_PASSWORD` were already in `config.go`'s `secretFileKeys` — fixed
     by adding the plain vars, the two `*_FILE` secret references, the two
     `secrets:` entries, and the matching `make docker-secrets` handling
     (same "skip and print a note if empty in `.env`" pattern already used
     for `SMTP_PASSWORD`/`TEAMS_WEBHOOK_URL`). `DIGICERT_API_KEY` itself
     stays a plain (non-secret) var in both files — not something this pass
     changed, just consistent with `config.go`'s own pre-existing
     `secretFileKeys` list not including it.
  3. **Two `Makefile`s.** `Makefile.txt` was a stale, git-tracked duplicate
     of `Makefile` — a byproduct of the `device_commit_files` sync gotcha
     already documented under "Known environment gotchas" below (it refuses
     to write a file literally named `Makefile`, so a sync produces
     `Makefile.txt` instead, and at some point that got committed alongside
     the real file rather than renamed over it). `Makefile` was confirmed as
     the actually-current, actually-used one (identical content plus this
     session's own edits); `Makefile.txt` was `git rm`'d. The gotcha note
     itself still stands — this was cleaning up one specific instance of it
     landing in the repo, not a change to the sync tool's behavior.
  4. **The font stack's "Inter" fallback read as generic AI/SaaS-template
     styling.** `tailwind.config.js`'s `fontFamily.sans` used to fall back
     through `Segoe UI` to `Inter` before hitting a bare `sans-serif` — the
     same default nearly every AI-scaffolded project ships with. Asked the
     user directly rather than guessing how far to take it (self-host a
     specific typeface vs. go fully system-native — the CSP's `default-src
     'self'` already blocks any external font CDN, so a Google-Fonts-style
     fix wasn't on the table either way); the user chose fully system-native.
     `Inter`/`ui-sans-serif` dropped entirely, `system-ui` alone leads the
     stack — it already resolves to each platform's real UI font (Segoe UI
     Variable, San Francisco, Roboto) with zero new assets and zero CSP
     change needed. Rebuilt `static/app.css` via the standalone Tailwind
     v3.4.17 binary (the Makefile's own downloader only has Darwin/Linux
     branches — fetched the Windows one directly for this dev machine).
  5. **An uploaded/generated Root CA had no detail view at all** — the
     Issuers page's list only ever showed name, common name, and key
     algorithm/size, with no way to see the full subject, fingerprint,
     validity dates, or the certificate PEM itself, even though
     `domain.RootCA` already stores all of it. Fixed with an inline
     `<details>`/`<summary>` expansion per row (`root_ca_section.html`),
     reusing the existing `fact`/`pem-block` partials the certificate detail
     page already uses — no new route or handler needed, since every field
     was already loaded into `.RootCAs`. The Delete button was deliberately
     moved to sit *outside* the `<details>` (as a sibling, not nested inside
     the `<summary>`) so clicking it doesn't also toggle the expansion open/
     closed via event bubbling.
  6. **Bulk-renewing internal certificates removed entirely**, per explicit
     request — not disabled, deleted: `CertificateService.BulkRenewInternal`/
     `BulkRenewInput`/`BulkRenewOutcome`, `handleCertificateBulkRenew`,
     the `POST /certificates/bulk-renew` route, the per-row selection
     checkboxes and the renew-selected bar in `certificate_table.html`
     (which changed from a `<form>` to a plain `<div>` — `id=
     "certificate-table"` still has to exist and still gets replaced
     wholesale via `outerHTML` by every other action on the page: generate,
     import, import-CSR, import-PFX, delete), the now-orphaned
     `AuditCertificateRenewed` action, and the dedicated test
     (`TestBulkRenewInternalMixedBatch`). A renewal ticket's own
     `ApproveInternal` (v1.2, unaffected) remains the only internal-renewal
     path; several doc comments elsewhere (`AutoDraftRenewals`,
     `DigiCertService.Submit`, a couple of interface doc comments) referenced
     the removed method by name purely for scoping rationale and were
     reworded rather than left dangling.
  7. **Outgoing email is now a simple branded HTML template, sent
     multipart/alternative alongside the original plain text** — not a
     redesign of the notification content itself, just how it's presented.
     New `internal/pkg/notify/template.go`: `renderHTMLBody(subject, body)`
     splits the plain-text body on blank lines into `<p>` paragraphs and
     wraps them in `htmlEmailTemplate`, a single-card, table-based layout
     (table-based specifically because that's the one layout model
     consistently honoured across real-world email clients, unlike flexbox/
     grid) with inline styles only — no external CSS/fonts/images, matching
     this app's own "nothing from third-party origins" CSP posture even
     though email delivery has no CSP of its own to enforce it. Every
     dynamic value (subject and body both, since either can carry a
     certificate common name or other data tracing back to a requester) is
     HTML-escaped via `html.EscapeString` before insertion — this content is
     rendered by the *recipient's* mail client, so escaping has to happen
     here, there's nothing downstream to fall back on. `buildMIME` (used by
     the fixed alert-recipient `Send`) and `buildMultipartMIME` (used by
     `SendWithAttachment`, the ticket-certificate-delivery path) both now
     build their body via a new shared `buildAlternativeBody` helper — a
     nested `multipart/alternative` part (text then html) that
     `buildMultipartMIME` places as the first part of its outer
     `multipart/mixed`, ahead of any attachments, so the two code paths
     share one HTML-rendering implementation rather than duplicating it.
     `buildMIME` changed signature to return an error (multipart-writer
     construction can, in principle, fail) — its one caller (`Send`) updated
     to match. Existing tests updated for the new nested structure
     (`TestBuildMultipartMIME` now descends into the alternative part before
     reaching the attachment parts) and a new test
     (`TestRenderHTMLBodySplitsParagraphsAndEscapes`) confirms both the
     paragraph splitting and the HTML-escaping directly. A CodeQL rescan
     after this surfaced a third instance of the same "the query's dataflow
     summary conflates unrelated `Write([]byte)` implementations" tool
     limitation already documented in the CodeQL section below
     (`go/reflected-xss` on an HTTP middleware helper that has no actual
     call relationship with the `notify` package at all) — confirmed by
     checking imports directly, not assumed.
  - **Verification**: `go build`/`vet`/`test ./...` all pass, including new/
    updated tests for items 1 (n/a — pure template fix, verified by reading
    the resulting HTML) and 7 above. A CodeQL rescan after all seven fixes
    shows the same set of already-reviewed findings from v1.13/v1.14 plus
    the one new, confirmed-false-positive `go/reflected-xss` case documented
    below — nothing else new. **Live browser verification was not performed
    this session** (no running Postgres instance available) — the role-
    update fix (item 1) and the Root CA detail expansion (item 4) are purely
    template/markup changes that should be clicked through by hand before
    relying on this in production, same caveat as v1.13/v1.14's own
    unverified-live sections.

- **v1.16: ADCS configuration moved from `.env`-only to portal-editable**,
  the exact same move v1.8 made for LDAP (see that section above for the
  general shape) — `ADCS_ENDPOINT`/`ADCS_USERNAME`/`ADCS_PASSWORD`/
  `ADCS_TEMPLATE` are now only a first-boot seed (`SettingsService.Bootstrap`
  seeds each from `.env` only if no row exists yet; from then on `/settings`
  and the database govern the live value). This does not change any part
  of the v1.14 CES/CEP model itself — only *where the configuration lives
  and how live it is* changes. The boot-time cross-field check config.go
  used to enforce (`ADCS_USERNAME`/`PASSWORD`/`TEMPLATE` required once
  `ADCS_ENDPOINT` is set) moved to `SettingsService.Update`'s new
  `validateADCSPatch`, mirroring `validateLDAPPatch` exactly — a bad *seed*
  should never block boot, only a bad *live edit* should be rejected.
  `CertificateService` no longer holds a static `adcs.Client` wired once at
  boot (`SetADCSClient` is gone) — it now holds an `adcsClientFactory func
  (adcs.Config) adcs.Client` (`SetADCSClientFactory`, test-injection only,
  mirroring `AuthOptions.LDAPClientFactory`'s role for LDAP) and
  `SignWithADCS` builds a fresh client from `settings.Current()` on every
  call, the same "always current" pattern `SettingsService.EmailNotifier`/
  `TeamsNotifier` already established — an admin's portal edit takes effect
  on the very next "Submit to ADCS" click, no restart needed.
  `ADCSPassword` is a write-only field in the `/settings` UI (never
  pre-filled with the real stored value; blank keeps what's stored; an
  explicit "Clear the stored password" checkbox is the only way to wipe
  it), the same convention `SMTPPassword`/`TeamsWebhookURL`/
  `LDAPBindPassword` already use. Covered by new tests mirroring the
  existing LDAP ones exactly: `TestUpdateAcceptsValidADCSConfig`,
  `TestUpdateRejectsADCSMissingRequiredField`,
  `TestUpdateWithoutADCSEndpointIgnoresOtherADCSFields` (settings-service
  layer), plus the existing `SignWithADCS` tests updated to configure ADCS
  via a settings snapshot and inject a fake client through
  `SetADCSClientFactory` instead of the now-removed `SetADCSClient`.
  `go build`/`vet`/`test ./...` all pass. **Live browser verification of
  the new `/settings` ADCS section was not performed this session** (no
  running Postgres instance available) — click through a save (endpoint +
  username + password + template, then a blank-password re-save to confirm
  the stored password survives) before relying on this in production, same
  caveat as this file's other unverified-live sections.

- **v1.17: primary accent recolored from blue to a brand red, scoped
  deliberately narrowly** — a new `brand` color (`tailwind.config.js`,
  shades `400`/`500`) replaces every literal `sky-500`/`sky-400` Tailwind
  utility that was acting as the primary-action/focus-ring/checkbox-radio
  accent: `.btn-primary`'s button face (`web/input.css`), every
  `focus:ring-*` on a text input/textarea, every checkbox/radio's
  `text-*`/`focus:ring-*` accent color, the `.chip-toggle-label`'s keyboard-
  focus ring, and the page-wide text-selection highlight color
  (`layout.html`'s `selection:bg-*`). `brand-500` is a fixed literal hex
  (`#E4002B`, a best-known approximation of OCBC's brand red — confirmed
  with the user directly that an approximation was acceptable rather than
  an exact brand-guideline hex; adjust the two hex values in
  `tailwind.config.js` if a precise one is supplied later), not
  theme-variable-backed — matching how the `sky-500`/`sky-400` it replaced
  was never theme-toggled either.
  - **Deliberately left blue, confirmed with the user rather than assumed**:
    the semantic `hue-sky`/`hue-sky-strong` tokens (links, "Internal"
    trust-class badges, the LDAP-account badge, the light/dark-aware nav
    active-state highlight, informational panels like "Already on file"
    duplicate-fingerprint notices and the login page's `.Notice` banner,
    and the certificates page's intake-method tab selection state) are
    untouched — these are a different semantic meaning (informational/
    selected, not primary-action) from what was asked to change. This
    mattered in practice: several literal `sky-500`/`sky-400` occurrences
    sit on the *same element* as a `text-hue-sky` class (e.g. the
    certificates page's selected intake tab, the EKU chip picker's
    `peer-checked:` state, the "Internal" badge's background+ring framing
    its own `hue-sky` text) — converting only the ones with no `hue-sky`
    companion on the same line, rather than every literal `sky-500`/
    `sky-400` string in the codebase, is what kept those coherent instead
    of producing a badge with a red ring around blue text.
  - **Deliberately kept distinct from `hue-rose`** (the existing danger/
    critical/destructive color — Reject, Delete, critical-expiry status):
    confirmed with the user that the new brand red and the existing danger
    red should read as different signals, not the same one.
    `hue-rose`/`hue-rose-strong` are untouched; `brand-500`'s hex is a
    purer, more orange-leaning red than `rose-500`'s pink-leaning one
    (`#f43f5e`), so a primary "Generate"/"Save" button and a "Delete"
    button don't visually blend into the same warning-color family.
  - Rebuilt `static/app.css` via the standalone Tailwind v3.4.17 binary
    (same Windows-binary-fetched-directly workaround the v1.15 font change
    needed, since the Makefile's own downloader has no Windows branch).
    Verified the compiled output directly rather than assuming the source
    edit took effect: `.btn-primary`'s and `:hover`'s `background-color`
    resolve to `rgb(228 0 43)`/`rgb(235 64 96)` (the two brand hexes in
    decimal), and every `hue-sky`-paired occurrence found in a final
    repo-wide sweep was confirmed to still carry its original `sky-500`/
    `sky-400` value, untouched.
  - `go build`/`vet`/`test ./...` all pass (this is a CSS/template-only
    change with no Go logic touched). **Live browser verification was not
    performed this session** (no running Postgres instance available) —
    click through the app in both themes before relying on this in
    production, particularly to confirm the "Internal" badges/tab-selection
    states still read clearly as blue/informational next to the new red
    primary buttons.

## CodeQL

A local CodeQL setup exists for cheap, targeted static analysis — running a
scan and reading pinpointed findings costs far fewer tokens than grepping/
reading broadly through the codebase for the same class of bug. The CLI
(`codeql`, 2.26.2 via chocolatey) was already on this machine; the Go query
pack is pinned to `codeql/go-queries@1.6.0` (the latest, 1.6.9, needs a newer
CLI than what's installed here — its manifest format isn't backward
compatible). `.codeql/` (the built database + SARIF output) is gitignored —
rebuildable, not source.

```bash
codeql database create .codeql/go-db --language=go --source-root=. --overwrite
codeql database analyze .codeql/go-db codeql/go-queries@1.6.0:codeql-suites/go-security-and-quality.qls --format=sarifv2.1.0 --output=.codeql/results.sarif
```

**Two real findings fixed** from the first scan (v1.13 follow-up): `safeNext`
(`internal/delivery/http/auth_handler.go`) and the theme toggle's inline
redirect check (`internal/delivery/http/theme_handler.go`) both only rejected
a leading `//` — not `/\`, which some browsers normalize to `//` before ever
making the request, so `/\evil.com` was a live open-redirect bypass on both
the login `next` param and the theme cookie's `redirect` param. The theme
handler's copy was deleted entirely in favor of calling the shared
`safeNext`, so this exact class of bug (the same check duplicated and
verified twice) can't happen again. Separately, `internal/pkg/notify/
email.go`'s `buildMIME`/`buildMultipartMIME` spliced `From`/`To`/`Subject`
into raw header lines via `fmt.Fprintf(..., "%s\r\n", ...)` with no CR/LF
stripping — a `\r\n` in the ticket "send by email" recipient (admin-typed,
never validated) or a certificate request's requester-supplied common name
(feeding the subject) could inject an extra header (e.g. `Bcc:`) or smuggle
content past the intended message (CWE-93/CWE-640). Fixed with a
`sanitizeHeaderValue` helper applied to all three fields in both builders.
Both fixes are covered by unit tests that round-trip a real payload through
`net/mail.ReadMessage`/`safeNext` directly, rather than trusting a rescan.

**Known false positives / tool limitations, not re-litigated on a future
scan**: `go/cookie-secure-not-set` on both `Secure:` cookie fields in
`auth_middleware.go` — the query only recognizes a literal `true`, but both
are correctly parameterized by `COOKIE_SECURE`/`cookieSecure`, not
hardcoded. `go/incorrect-integer-conversion` on `config.go`'s `int32(reqInt(
"DB_MAX_CONNS"))` — a real gap (no overflow check) but boot-time config
parsing from `.env`/the environment, not attacker-reachable input; low
priority. More surprisingly, **both real fixes above are still flagged by
a rescan** even after being fixed and unit-tested — not because the fix is
incomplete, but because of two separate tool limitations worth knowing
before trusting a bare "still flagged" reading in the future:
`go/unvalidated-url-redirection`'s barrier detection doesn't recognize a
hand-rolled validator function (`safeNext`) as clearing taint, and
`go/email-injection`'s sink is the *final composed message* passed to
`smtp.SendMail`/`w.Write`, not the header-construction step specifically —
it can't distinguish "safe body content" from "unsafe header content," and
flags any dynamic email content by design. Both call sites carry a
`// codeql[query-id]` comment with the reasoning — note that this
suppression-comment convention is only interpreted by GitHub's code-scanning
*upload* step (`github/codeql-action`), not by the local `codeql database
analyze` CLI used here, so it's inert for this local workflow today (it
would take effect automatically if this repo is ever wired into GitHub Code
Scanning) — the comments are left in purely as human-readable justification
at the flagged line.

**A third case of the same tool-limitation class, added when the v1.15
email-template work (see below) started tripping it**: `go/reflected-xss`
on `statusRecorder.Write` in `middleware.go` — a generic byte-count-tracking
`http.ResponseWriter` wrapper used by every response in the app. The
reported path runs from `internal/pkg/notify/email.go`'s new HTML-email
template builder through this `Write` call, which would be a real finding
if it were a real call chain — it isn't: `middleware.go` imports nothing
from this project at all (confirmed directly, not just plausible), and no
`internal/delivery/http` file imports `internal/pkg/notify`. The query's
dataflow summary conflates every `Write([]byte) (int, error)`-shaped
function as interchangeable (`bytes.Buffer.Write`, an SMTP `net.Conn`'s
`Write`, and `http.ResponseWriter.Write` all match that same shape), so a
value that only ever reaches an SMTP socket gets reported as reaching an
HTTP response too. Same `// codeql[go/reflected-xss]` comment convention as
the other two, same caveat about it being inert for the local CLI.

## Conventions

- New DB schema changes go in `internal/database/migrations/NNNN_name.sql`,
  applied automatically at boot — never hand-edit an already-shipped
  migration file.
- Handlers stay thin: parse/validate input, call a service method, render a
  page or partial. Business logic and audit-recording calls belong in
  handlers only at the "record on success" call site — the actual rule logic
  lives in `internal/service`.
- htmx is the only client-side interactivity mechanism; there is no inline
  JavaScript (the CSP forbids it). `static/app.js` is a small set of
  delegated listeners (copy buttons, banner dismissal, form resets) and every
  page must keep working with it disabled.
- Status badge classes and similar view-only decisions that need to be
  Tailwind-purge-safe are chosen in Go (`internal/delivery/http/render.go`)
  rather than composed as dynamic strings in templates;
  `tailwind.config.js` scans the Go sources for this reason.
- When adding a new `@layer components` class to `web/input.css`, apply it to
  at least one template *before* running `make css` for a production build —
  Tailwind purges any class it doesn't find referenced in scanned content.

## Commands

```bash
make env               # generate .env from .env.example (idempotent; prints admin password once)
make docker             # env + docker compose up --build — local dev, the primary way to run this
make docker-image      # build the app image, tagged for a Swarm deploy
make docker-secrets    # create every Docker secret docker-stack.yml needs (idempotent)
make docker-stack-deploy # docker-image + docker-secrets + `docker stack deploy` (production)
make db           # Postgres 16 in Docker only, for running the Go binary on the host
make run          # go run ./cmd/server (migrations apply automatically at boot)
make css          # rebuild internal/delivery/http/static/app.css from web/input.css
make css-watch    # same, on every change
make test         # go test ./...
make vet          # go vet ./...
make tidy         # go mod tidy
```

`make docker` is the default path for a full clean run. For iterating on Go
code directly (faster feedback than a container rebuild), use `make db` +
`make run`.

## Known environment gotchas

- **`device_commit_files` (Cowork desktop bridge) refuses to write a file
  literally named `Makefile`** — "protected file." If syncing this repo to a
  connected local folder via that path, the file lands as `Makefile.txt`;
  rename it to `Makefile` locally before running any `make` target.
- **`device_commit_files` also refuses to write `.env`** — "Writing to .env
  is not permitted via remote tools," presumably because it can hold
  secrets. A generated/updated value (e.g. a new `APP_ENCRYPTION_KEY` or
  `SESSION_SECRET`) has to be handed to the user as text in chat for them to
  paste in manually — it can't be synced like every other file in this repo.
- Building the app's own Docker image inside a sandboxed cloud dev
  environment can fail at the `apk add` / `go mod download` step if the
  sandbox intercepts outbound TLS with a CA the fresh build stage doesn't
  trust yet. This is an artifact of that kind of environment, not the
  Dockerfile — do not "fix" the Dockerfile to route around it (e.g.
  switching Alpine to a plain-HTTP mirror). A real deploy target trusts the
  system CA bundle normally. When verifying changes in such an environment,
  prefer running the Go binary natively against a real `docker compose up -d
  postgres` container over building the app's own image.
- **`slapd`/`ldap-utils` (OpenLDAP) install cleanly via `apt-get` in this
  kind of sandboxed cloud dev environment**, unlike Docker above — used for
  `internal/pkg/ldapauth`'s live tests (`client_live_test.go`). One
  install-time snag: the packaged `slapd` postinst is interactive (prompts
  for an admin password) and there's no controlling tty in this kind of
  environment, so it falls back through Readline/Dialog/Teletype frontends
  and installs with a blank/default config. Don't fight that — ignore the
  package's own auto-configured instance entirely and run a second,
  throwaway `slapd` by hand instead: a classic (non-`cn=config`) `slapd.conf`
  needs `modulepath /usr/lib/ldap` + `moduleload back_mdb.la` before
  `database mdb`, or slapd fails immediately with "Unrecognized database
  type (mdb)" — the mdb backend is a dynamically-loaded module in this
  build, not compiled in. From there, `slapd -f slapd.conf -h
  "ldap://127.0.0.1:<port>/"` backgrounded, `ldapadd` an LDIF seeding the
  base DN/OUs/users/groups, and it's a fully real directory server for
  `go-ldap/ldap/v3` to bind and search against — no fake needed.