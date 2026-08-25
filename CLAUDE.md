# CLAUDE.md

Guidance for Claude Code (or any coding agent) working in this repository.

## What this is

**SSL Admin** (repo name `ssl-generator`) — a certificate vault and CSR
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
- **Three roles**: `admin` (also manages accounts, `CanManageUsers()`),
  `editor` (full read-write on monitors/CSRs, `CanWrite()`), `viewer`
  (read-only, including CSR downloads). Every write route re-checks the
  caller's role server-side.
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
make env          # generate .env from .env.example (idempotent; prints admin password once)
make docker        # env + docker compose up --build — the primary way to run this
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
