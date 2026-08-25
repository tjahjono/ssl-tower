# SSL Admin Roadmap

Turning the certificate generator into an always-on SSL Admin: public
certificate monitoring, key material locked behind login, proactive alerts,
and a record of who touched what.

**Status: all 6 original phases done and verified against a running stack,
plus 10 follow-on phases (7-16).**
Owner: Giovanni Tjahjono.

Source of truth for the original plan: the "SSL Admin Roadmap" artifact
(`https://claude.ai/code/artifact/c26a391a-f7de-48e7-862c-bc57c0970d93`).
This file mirrors it and records what actually shipped.

## Decisions locked along the way

Recorded so a later session doesn't have to re-litigate them. (Also captured
in `CLAUDE.md`, which is the version to keep in sync going forward.)

| Decision | Choice | Why |
| --- | --- | --- |
| Second factor | TOTP authenticator app | No SMTP/SMS dependency to stand up; works offline; the standard for Authenticator / Authy / 1Password. |
| Account model | Three roles — admin, editor, viewer | Read-only vs. read-write was the ask. Admin split out on top, since granting logins is a different power than generating a CSR. |
| Monitoring access | Public read, gated write | A certificate is already public the moment it's served over TLS. Mutating actions stay behind login so the app can't be used to probe arbitrary hosts anonymously. |
| Certificate model | Cert-first display, one endpoint per monitor, duplicate-fingerprint warning | Ships faster than full multi-endpoint monitors and still fixes the real problem: a wildcard certificate serving many sites shouldn't read as many unrelated things to watch. |
| Alert channels | Email + Microsoft Teams | Matches how the team is actually notified today. |
| Form styling | Tailwind-consistent inputs & selects everywhere | Native selects and inputs currently break out of the dark theme. |

Phases are ordered by dependency: alerting needs certificate-first monitoring
in place, the audit log needs accounts to exist, and the form pass runs last
so it covers every page built along the way instead of styling things twice.

## Phase 0 — Docker Compose, the default path — Done

Running the stack should be one command, with no manual key-generation step
first.

- Dropped the `full` profile gate — `docker compose up --build` starts
  Postgres and the app together.
- `make env` creates `.env` with a generated `APP_ENCRYPTION_KEY` and
  `SESSION_SECRET` on first run, idempotent after that; `make docker` depends
  on it.
- `.dockerignore` added — the build was copying `.env` straight into image
  layers before this.
- Verified against a real build: compiled the actual Dockerfile, ran it
  against Postgres over the Compose network, confirmed migrations applied
  and the dashboard served a 200.

## Phase 1 — Monitoring becomes certificate-first — Done

A monitor represents a certificate, not a website — a wildcard cert can
cover a dozen of the latter.

- Leads with issuer, expiry, and full SAN coverage instead of just the
  hostname typed in.
- Warns when a new endpoint's fingerprint matches a certificate already
  being tracked.
- Groups monitors by issuing CA; flags it when an endpoint's issuer changes
  between checks.
- Health flags per certificate: weak signature (SHA-1/MD5), undersized keys,
  incomplete chain, self-signed.

Verified: fixed a missing `"sort"` import, `HasCertificate()` keying off
`Subject` instead of `LeafPEM`, and `ListEnabled()` failing to hydrate
latest-check data — confirmed via a live server boot against real
certificates.

## Phase 2 — Alerting — Done

Nobody should learn about an expiry by opening the dashboard and checking.

- Email delivery via SMTP (STARTTLS or implicit TLS), configured through the
  environment.
- Microsoft Teams delivery via an incoming webhook.
- Threshold triggers — 30 / 7 / 1 day, expired, unreachable, issuer changed —
  fired once per state change, not every sweep.
- Both channels are independently opt-in; leaving both unset is a fully
  supported no-op configuration (boot-time warning only).

Verified against local mock SMTP/webhook servers — no real SMTP credentials
or Teams webhook URL have been supplied for this environment, so live
third-party delivery is unverified but the mechanism (env-var-gated,
safe-no-op-when-unconfigured) is confirmed working.

## Phase 3 — Login with MFA — Done

A real front door for CSRs and key material; monitoring stays open.

- `users`, `sessions`, `recovery_codes`, `login_attempts` tables.
- Password + TOTP login, QR enrollment, one-time recovery codes.
- Role checks enforced server-side — admin / editor / viewer — on every CSR
  route and every monitoring write route.
- First-boot bootstrap from `ADMIN_EMAIL` / `ADMIN_INITIAL_PASSWORD`, forcing
  password change and MFA enrollment on first login.

Verified live end-to-end: CSRF double-submit on the login form itself,
forced onboarding order (password change → MFA enrollment) before any other
authenticated route, a wrong TOTP code rejected, a recovery code consumed
exactly once, and role gating enforced by the middleware chain
(`requireAuth` / `requireWrite` / `requireAdmin`) rather than only hidden in
the UI — confirmed a viewer session gets a 403 from the API directly.

## Phase 4 — Audit log — Done

Who did what, and when — especially for anything that touches a private
key.

- `audit_log` table keyed to the acting user (`ON DELETE SET NULL` so a
  deleted account doesn't lose its history).
- Logged: logins and failed logins, user and role changes, monitor add /
  delete / pause / manual check, CSR create / attach / self-sign / delete,
  and every private-key-bearing download (`.key`, `.pfx`, `.zip` — not plain
  certificate downloads).
- Admin-only audit view at `/audit`, filterable by actor email, action, and
  date range.

Verified live: exercised every logged action against a real database and
confirmed each row (actor, action, target, IP, timestamp) via direct SQL
inspection, including that recording is non-blocking and failures there
never break the underlying mutation.

## Phase 5 — Tailwind form pass — Done

Every input and select matches the rest of the app — run last so it covers
the new pages above too, instead of styling things twice.

- Shared input/select treatment: focus ring, dark surface, custom chevron,
  disabled state — extracted into `@layer components` classes
  (`.field-label`, `.field-input`, `.field-input-bare`, `.btn-primary`,
  `.btn-secondary`, `.btn-ghost`) in `web/input.css`.
- Applied across every existing and newly-built form (17 template files),
  including the Phase 3 auth pages and the Phase 4 audit page.

Verified with zero visual regression via before/after screenshot comparison
and a real browser form submission.

## Phase 6 — Verify — Done

Prove every claim above against a running stack, not just against the code.

- `docker compose up --build` end to end, from a clean checkout — validated
  by running the app binary natively against a genuinely fresh
  `docker compose up -d postgres` container (a sandbox-specific TLS-trust
  limitation blocked building the app's *own* image inside this dev
  environment specifically; see `CLAUDE.md`'s gotchas section — this doesn't
  affect a normal deploy target). Migrations-from-zero exercised fully.
- Dashboard reachable with no session; every write action blocked without
  one.
- A wrong TOTP code is rejected; a recovery code works once and is then
  spent.
- A viewer account is blocked server-side from a write route, not just
  hidden in the UI.
- Audit log captures a login, a monitor edit, and a key download —
  confirmed via direct SQL inspection of `audit_log`.
- Stale docs/config fixed as part of this pass: `docker-compose.yml` and
  `.env.example` were missing the Phase 3 session/admin-bootstrap env vars;
  `README.md`'s security section previously and incorrectly claimed the app
  "ships without authentication."
- Alert-on-expiring-certificate (email + Teams firing together) verified
  against local mock servers only, per the Phase 2 note above — no live
  SMTP/Teams credentials have been provided.

## Phase 7 — Lock down monitoring reads, narrow the login form — Done

A follow-up requested after the original 6 phases shipped: tighten access
further, and fix a layout complaint on the login screen.

- **Access model tightened.** The dashboard (`GET /`, plus its `/summary`
  auto-refresh partial) is now the *only* route reachable without a session
  — superseding the original Phase 0-era "public read, gated write" decision
  for monitoring. `GET /monitors`, `/monitors/list`, `/monitors/issuers`,
  `/monitors/{id}`, and `/monitors/{id}/download` now all require
  `requireAuth`; the corresponding write routes were already gated and are
  unchanged. CSR routes were already fully session-gated from Phase 3.
- **Dashboard no longer leaks CSR data to anonymous visitors.** The
  dashboard's "Recent signing requests" section previously fetched and
  rendered CSR common names for anyone, public route or not — inconsistent
  with CSRs otherwise always requiring a session to read. It's now only
  fetched and shown when the visitor is signed in.
- **Login form narrowed** from `max-w-sm` (384px) to `max-w-xs` (320px) —
  it read as too wide. The MFA-challenge and change-password pages
  immediately after login still use `max-w-sm`; flagged as a possible
  follow-up if the user wants the whole auth flow visually consistent.
- `README.md` and `CLAUDE.md` updated to match the new access model.
- **Sidebar nav trimmed to match.** With Monitoring, Issuers, and Signing
  requests all requiring a session now, showing them to an anonymous visitor
  just meant every click bounced to `/login`. The nav now shows only
  "Dashboard" when signed out; the full set (plus Users/Audit log for
  admins) reappears once signed in. Verified with a real session cookie
  against the live app: `Dashboard: 2, Monitoring: 0, Issuers: 0, Signing
  requests: 0` anonymous vs. all present when authenticated.

## Phase 8 — Remove built-in config defaults — Done

Another follow-up: `internal/config/config.go` was silently applying a
hardcoded fallback (`env("HTTP_ADDR", ":8080")` and friends) for most
settings, so a genuinely missing `.env` var would go unnoticed — the app
just quietly ran on values baked into the binary instead of what was
supposedly configured.

- Rewrote `config.Load()` to draw a hard line: a setting is either
  **required** — must resolve to a real value from the environment, or
  `Load()` returns an error naming every missing/invalid one at once — or
  **optional by design**, meaning its empty value is itself a meaningful
  feature toggle (`SMTP_HOST`, `SESSION_SECRET`, `ADMIN_EMAIL`, etc. — see
  `CLAUDE.md`). No third category, no silent substitution.
- This surfaced a real gap: `docker-compose.yml` never actually set
  `APP_ENV`, `DB_MAX_CONNS`, `DB_CONNECT_TIMEOUT`, `CHECK_TIMEOUT`, or
  `CHECK_WORKERS` — the app container was relying entirely on the
  now-removed Go-level defaults for those five. Added them to the
  `environment:` block using the same `${VAR:-default}` Compose-level
  convenience the file already used for every optional var, so
  `docker compose up --build` still works without a `.env` file, and a real
  `.env` (via `make env`/`make docker`) takes over once it exists.
- This also surfaced that `make run` never actually loaded `.env` into the
  process — it only "worked" before because `go run` fell back to
  hardcoded defaults. Fixed `make run` to source `.env` itself (and fail
  with a clear message if `.env` doesn't exist yet), so the documented
  `make env && make db && make run` flow is now actually self-sufficient.
- Verified live: booting with no environment at all now fails immediately
  and lists every missing required variable by name; a single missing var
  (tested by unsetting just `APP_ENV`) fails with exactly one line naming
  it; booting against the real `.env` via the fixed `make run` still comes
  up clean.
- `README.md` and `CLAUDE.md` updated: the configuration table now marks
  each variable required or optional, and `.env.example` is called out as
  the actual source of default values, not the Go binary.

## Phase 9 — Load .env from the app itself — Done

Phase 8 made `config.Load()` strict about requiring real values, but it
still only ever read `os.Getenv` — it never actually loaded `.env` into the
process. That meant `go run ./cmd/server` (or a directly-run binary) always
failed with every required variable reported missing, unless something
external — a shell `source .env`, an IDE run-config, `make run`'s old
manual sourcing — had already exported it. This surfaced from a real report:
running via `go run cmd/server/main.go` and via `docker` both hit the same
"config: missing or invalid settings" wall.

- Added `loadDotEnv(".env")` to `internal/config/config.go`, called at the
  top of `Load()`. It parses `.env` from the process's current working
  directory and calls `os.Setenv` for each key — but only if that key isn't
  already set in the real environment. A real env var (shell, `docker
  compose`, systemd, a scheduler) always wins; `.env` just fills in
  whatever's missing. A missing `.env` file is not an error — that's the
  normal case inside the Docker image, which deliberately never contains
  one (see `.dockerignore`).
- Simplified `make run` back to a plain `go run ./cmd/server` — the manual
  `set -a; . ./.env; set +a` sourcing from Phase 8 is now redundant, since
  the binary loads `.env` itself.
- Verified live, reproducing the exact failure first: `go run
  cmd/server/main.go` in a completely clean environment (`env -i`) with
  `.env` present now boots cleanly instead of erroring. Confirmed precedence
  by setting `HTTP_ADDR=:9191` as a real env var alongside a `.env` that
  still said `:8080` — the server came up on `:9191`, proving a real env var
  beats `.env`. Confirmed the no-`.env`-at-all case still fails with a clear
  message instead of a crash (temporarily moved `.env` aside, ran, restored
  it). `go build`/`vet`/`test` all pass throughout.
- `README.md` and `CLAUDE.md` updated: config loads `.env` itself now, and
  running the binary directly (not just through `make`) needs no manual
  environment setup as long as `.env` sits next to where it's run from.

## Phase 10 — The certificate vault — Done

Replaced endpoint monitoring and the standalone CSR feature with one unified
certificate vault, per the roadmap's certificate-vault pivot. This was the
biggest single change in the project: new domain type, new table, new
service, new repository, new handlers, new templates, and the removal of
everything endpoint-monitoring-shaped.

- **Domain**: `internal/domain/csr.go` and `internal/domain/monitor.go` are
  gone, replaced by `internal/domain/certificate.go`'s `Certificate` — the
  old `CSR` struct extended with `Origin` (`generated`/`uploaded`), `Owner`,
  and the health-finding fields ported from `Check` (`Subject`, `Issuer`,
  `SignatureAlgorithm`, `PublicKeyAlgorithm`, `KeySize`, `ChainLength`,
  `FingerprintSHA256`). `CheckStatus` (ok/expiring/critical/expired) is kept
  as the expiry-health type so `render.go`'s badge/dot helpers and every
  template needed no rewrite beyond a wording tweak — `StatusError` (a live
  TLS handshake failure) is gone since there's no handshake left to fail.
- **Migration**: `0006_certificate_vault.sql` renames `csrs` → `certificates`
  (preserving existing rows), adds the new columns, drops the
  `csrs_key_algorithm_check` constraint (an uploaded cert can be RSA,
  ECDSA, Ed25519, or something this app doesn't specifically recognise —
  not just the two the CSR generator itself produces), and drops
  `monitor_checks`/`monitors` entirely.
- **Service**: `internal/service/certificate_service.go` replaced
  `csr_service.go` and `monitor_service.go`. Kept `CreateCSR`/
  `AttachCertificate`/`SelfSign`/`Export`/`PrivateKey` (renamed from the CSR
  service, logic unchanged) and added the new intake paths: `Import` (PEM,
  reusing `certutil.ParseCertificatesPEM`/`MatchesKey`), `ImportPFX` (uses a
  new `certutil.DecodePKCS12` wrapper around the already-vendored
  `go-pkcs12` library's `DecodeChain`), and `BulkImportPFX` (loops
  `ImportPFX` over a batch, one shared password, each file succeeds or
  fails independently). A certificate can be filed without its private key
  (`HasPrivateKey()` gates which downloads are offered).
- **Alerting adapted**: `AlertService.Evaluate` now takes a `*Certificate`
  instead of a `(*Monitor, *Check)` pair, classifying by `DaysRemaining()`
  against the same warning/critical/final thresholds. `AlertUnreachable`
  and the issuer-changed notification branch are gone — nothing is
  "unreachable" any more. The old `Scheduler` (a TLS-handshake sweeper) is
  replaced by `internal/service/alert_sweeper.go`'s `AlertSweeper`, a much
  simpler periodic DB scan (`ALERT_SWEEP_INTERVAL`, new required config var
  — replaces `CHECK_INTERVAL`/`CHECK_TIMEOUT`/`CHECK_WORKERS`, all gone,
  since there's no handshake left to time out or parallelize).
- **Delivery**: `certificate_handler.go` replaced `csr_handler.go` and
  `monitor_handler.go`. Routes moved from `/monitors*`+`/csrs*` to a single
  `/certificates*` tree (`GET /certificates`, `POST /certificates/generate`,
  `POST /certificates/import`, `POST /certificates/import-pfx`, per-id
  detail/attach/self-sign/delete/download). `/checks/run` is gone — nothing
  left to sweep on demand.
- **Access control**: download routes stayed `requireAuth` at the route
  level, but `handleCertificateDownload` now checks role per requested
  `format` — admin for everything, editor additionally allowed for
  `FormatCSR` only, viewer never. This is Phase 10's other locked decision
  (certificate/key downloads admin-only) — see `CLAUDE.md`.
- **Templates**: new `pages/certificates.html` (generate-CSR form, PEM
  upload form, PFX bulk-upload form as three tabs — plain `data-tab-button`/
  `data-tab-panel` markup wired up in `static/app.js`, no new framework),
  `pages/certificate_detail.html`, `pages/certificate_issuers.html`,
  `partials/certificate_table.html`, `partials/certificate_detail.html`.
  `dashboard.html` and `layout.html`'s nav rewired to Certificates; the old
  monitor/csr page and partial templates are deleted.
- Verified live against a real Postgres instance (native `pg_ctlcluster`,
  `docker` unavailable in this sandbox): migration `0006` applied cleanly
  against a database that already had Phase 0-9's schema, `csrs` renamed to
  `certificates` in place. Exercised end-to-end over HTTP with real
  sessions: generated + self-signed a CSR, downloaded it as PFX and
  round-tripped that file through `openssl pkcs12 -info`; imported a
  certificate+key as PEM; bulk-imported two `.pfx` bundles in one request
  (both succeeded independently); confirmed download gating — admin got
  every format, an editor got the CSR only (403 on `.pfx`/`.key`), a viewer
  got 403 on everything including delete; confirmed every page (dashboard,
  vault, detail, issuers, users, audit) rendered with no template errors.
  `go build`/`vet`/`test ./...` all pass.

## Phase 11 — Weak-certificate flags — Done

Folded into Phase 10's implementation rather than a separate pass, since
the domain rewrite was the natural place to port it: `Certificate.
HealthFindings()` is `Check.HealthFindings()` moved over near-verbatim —
weak signature (MD5/SHA1), undersized key (RSA<2048, ECDSA<256),
self-signed, and no-intermediates-supplied all check the same fields,
now populated once at intake (`applyIssuedCert` in
`certificate_service.go`) instead of on every periodic check. "Issuer
changed" was dropped per the roadmap's plan — it only made sense with a
periodic re-check that could notice a change; here a renewed or replaced
certificate is simply a new record.

- Findings surface as a note-count pill on the certificate table (amber if
  any finding is a warning) and a full "Certificate health" panel on the
  detail page — both ported from the old monitor detail page's layout.
- Domain tests ported and extended: `internal/domain/certificate_test.go`
  covers every finding case (previously in `monitor_test.go` against
  `Check`) plus a new `TestHealthStatusClassification` for the
  warning/critical/expired boundary math against `Certificate.NotAfter`.
- Verified live: the self-signed certificate created during Phase 10's
  manual testing correctly showed a "Self-signed" health finding on its
  detail page.

## Phase 12 — Configurable extended key usage — Done

The user described the real-world flow (generate a CSR + key, get it signed
by an external CA, attach the result, download in whatever format IT needs)
and confirmed it already matched Phase 10's implementation — the one gap was
that extended key usage was hardcoded to server+client auth on self-sign and
never requested at all in a generated CSR.

- `certutil` owns the EKU vocabulary end to end so domain/delivery never
  import crypto/x509 for it: six keys (`server_auth`, `client_auth`,
  `code_signing`, `email_protection`, `timestamping`, `ocsp_signing`), each
  with a label, an OID (for the CSR's extension-request attribute), and an
  `x509.ExtKeyUsage` mapping (for self-sign and for reading back an issued
  leaf's actual EKU via `DescribeExtKeyUsage`).
- `Certificate.ExtKeyUsage []string` is single-purpose but dual-meaning by
  lifecycle stage: while pending, it's what the operator requested at CSR
  time (shown as "Extended key usage (requested)"); the moment a certificate
  becomes issued — self-signed, CA-attached, PEM-imported, or PFX-imported —
  `applyIssuedCert` overwrites it with whatever the issued leaf actually
  carries, since a CA is free to honour, ignore, or override the request.
  New migration `0007_ext_key_usage.sql` adds the backing `TEXT[]` column.
- `CreateCSR`'s generate form gained an EKU checkbox group (server+client
  pre-checked, matching the old hardcoded default); the CSR itself carries
  the selection as a standard extension-request attribute (OID 2.5.29.37) —
  honoured by an internal/private CA reading the request, though most public
  CAs decide EKU from their own product profile regardless. Self-signing
  always applies exactly what was requested, since the app is the issuer.
- Verified live against real Postgres: generating + immediately self-signing
  with `code_signing` selected showed "Code Signing" as the issued EKU;
  a pending CSR requesting `server_auth` showed "Extended key usage
  (requested): Server Authentication"; importing a certificate with OCSP
  Signing baked in (via openssl) correctly derived "OCSP Signing" with no
  user input. The CA-overrides-the-request case (attach a cert signed with a
  different EKU than was asked for) is covered by
  `TestAttachCertificateOverwritesExtKeyUsageWithIssuedLeaf` rather than live
  testing, since simulating an external CA signing with the app's own stored
  key isn't meaningfully different from the unit test.

## Phase 13 — Import a CSR generated elsewhere — Done

The user pointed out that a CSR + key isn't always generated through this
app — sometimes it's made on their own laptop with `openssl` before this
tool is even involved. There was no way to bring that pair into the vault:
"Generate" always mints its own key, and "Upload" assumes an already-issued
certificate.

- New third tab on the certificate vault page, "Import CSR + key": paste a
  CSR and its matching private key; owner/notes are optional. Landed as
  `CertificateService.ImportCSR` / `POST /certificates/import-csr`
  (`requireWrite`, same as every other intake path).
- Nothing is retyped: common name, organization/OU/country/province/
  locality, DNS/IP SANs, and any extended key usage the CSR itself requests
  (via its extension-request attribute) are all read directly off the
  pasted CSR with `certutil.ParseCSRPEM`/`DescribeRequestedExtKeyUsage`. The
  key is rejected if it doesn't match the CSR's public key — new
  `certutil.MatchesCSRKey`, sharing its comparison logic with the existing
  `MatchesKey` via an extracted `publicKeyMatches` helper.
- The resulting record is `Origin: generated`, `Status: pending` — every
  respect identical to a CSR this app minted itself, so it flows through
  the exact same attach-the-CA's-answer, self-sign, and download paths with
  no special-casing anywhere else in the service or delivery layers.
- New audit action `certificate_csr_imported`, distinct from
  `certificate_imported` (which is for already-issued PEM/PFX uploads) —
  worth telling apart in the log since this path takes in private key
  material the app didn't generate.
- Verified live against real Postgres: generated a CSR + key with `openssl`
  (SANs and `clientAuth` EKU baked in via `-addext`), imported it, and
  confirmed the detail page showed the correct common name, both SANs,
  organization, and "Extended key usage (requested): Client Authentication"
  — all read off the CSR with no manual re-entry. Self-signed that same
  record and confirmed the issued certificate still carried Client
  Authentication, then downloaded it as a full-chain PEM successfully.

## Phase 14 — Shared form styling, public request/renew guide — Done

Two independent requests handled together since both touched the
certificate vault page: bring a few form controls in line with the app's
own styling conventions, and give the org a public page explaining the
request/renewal workflow without needing an account first.

- **Dropdowns and EKU picker restyled.** `key_algorithm`/`key_bits`/
  `key_curve` on the generate form, the role picker on `users.html`, and the
  format picker on `partials/download.html` all had a hand-rolled utility
  string duplicating `.field-input` instead of using it — fixed to match
  the filter dropdowns, which already did this correctly. The EKU checkbox
  list is now a row of toggle-able pills instead of native checkboxes: new
  `.chip-toggle-input`/`.chip-toggle-label` components in `web/input.css`
  (a visually-hidden but keyboard/screen-reader-accessible input as a
  `peer`, styled via a sibling `<span>` and `peer-checked:`). `peer` itself
  can't go inside `@apply` — Tailwind rejects that — so it's a literal class
  alongside `chip-toggle-input` on the `<input>` in the template, not folded
  into the component class. `make css` was run to rebuild `static/app.css`
  from the new source (this sandbox already had the standalone `tailwindcss`
  binary cached from `make`'s own bootstrap in an earlier phase).
- **Public request/renew guide.** New `GET /help`, alongside the dashboard
  the only route that skips `requireAuth` — deliberately, since the whole
  point is that someone without an account yet can read how to get one
  used. `help_handler.go` renders static prose (`pages/help.html`); nothing
  queries the database, so there's nothing session-gated to leak. Covers
  requesting a new certificate (five numbered steps, generate-or-import →
  send the CSR to a CA → attach → download), renewing one (a fresh CSR
  early, not an in-place operation), the role matrix, the download-format
  table, and a self-sign caution. Nav gained a "Help" link outside the
  `{{if .User}}` block so it shows for anonymous and signed-in visitors
  alike. `CLAUDE.md`'s "only the dashboard is public" locked decision is
  updated to name both routes and why Help is safe to add to that list.
- Verified live: `go build`/`vet`/`test`/`gofmt` all clean; an anonymous
  `curl` to `/help` returns 200 with the guide and a highlighted "Help" nav
  entry; the certificate generate form serves `field-input`-styled selects
  and six `chip-toggle` pills for EKU, and the compiled `static/app.css`
  actually contains the new component classes (checked directly, since a
  missed `make css` after adding an `@layer components` class is a silent
  "class exists in source, purged from output" bug this project has flagged
  before).

## Phase 15 — Public dashboard content, admin-editable Help, clearer intake options — Done

Four requests handled together since three touched the dashboard/Help
surface and the fourth was a quick, isolated styling pass:

- **Full certificate list on the dashboard, public and read-only.** The
  "Recent certificates" section was previously gated behind
  `{{if .User}}` and capped at six. It's now "All certificates" — every
  record, unconditionally, for every visitor. This is a deliberate,
  explicit widening of `CLAUDE.md`'s "only the dashboard and Help are
  public" decision: an anonymous visitor already saw unhealthy certificates
  in "Needs attention"; now they see the full list the same way. What's
  still withheld from an anonymous visitor: the cards render as plain
  `<div>`s, not links, when `.User` is nil, so there's no path from the
  dashboard into a detail page (which holds CSR/key material) without
  signing in — `handleDashboard` in `certificate_handler.go` no longer
  gates or truncates the list it fetches, it's the template that decides
  whether a card is clickable.
- **CA information on the dashboard.** A new "Certificate authorities"
  section reuses `service.GroupByIssuer` (already built for the
  authenticated `/certificates/issuers` page) directly in `handleDashboard`
  — issuer name and certificate count per group, no per-certificate detail,
  same public/read-only treatment as the list above.
- **Admin-editable Help content.** `GET /help` used to be pure static HTML
  baked into `help.html`. It's now backed by a new `site_content` table
  (migration `0008_site_content.sql`) — `domain.SiteContent` /
  `SiteContentRepository`, `repository/postgres.SiteContentRepository`, and
  `service.SiteContentService`, wired through `main.go` and `NewServer`
  exactly like every other repository → service → delivery slice in this
  app. `GET/POST /help/edit` (admin-only, `requireAdmin`) lets an admin
  replace the page body with raw HTML via a textarea; the original guide
  is preserved verbatim as `service.DefaultHelpContent`, served whenever no
  row exists yet, so the page is never blank on a fresh deploy. **Trust
  note, flagged explicitly rather than left implicit:** the saved content
  is rendered unescaped (`template.HTML`) on a page anyone can view without
  logging in. This is intentionally scoped to admin-only — the same trust
  level an admin already holds over every account and every certificate's
  key material — but it is a new capability (a compromised or careless
  admin account can now inject arbitrary markup/script into a public page),
  not merely a data change. Saves are audited
  (`AuditHelpContentUpdated = "help_content_updated"`).
- **Certificate intake options made visible.** The four ways to bring in a
  certificate (Generate a CSR, Import CSR + key, Upload PEM + key, Upload
  PKCS#12) were a row of small text pills, easy to miss — especially the
  newer Import-CSR option. They're now a `grid gap-3 sm:grid-cols-2
  lg:grid-cols-4` of cards, each with an icon, name, and one-line
  description, still driven by the same `data-tabs`/`data-tab-button`/
  `data-tab-panel` mechanism in `app.js` — no JS changes needed, since the
  existing `TAB_ACTIVE`/`TAB_INACTIVE` class-toggle arrays apply equally to
  a card as to a pill.
- Verified live: `go build`/`vet`/`test`/`gofmt` all clean; `NewRenderer()`
  parses every template with no error; against real Postgres (migration
  `0008` applied automatically at boot) an anonymous `curl /` shows the
  full certificate list and CA breakdown with non-clickable cards, an
  anonymous `curl /help/edit` redirects to login, a signed-in admin sees
  the "Edit this page" link and clickable dashboard cards, a full
  login → MFA → edit → save round trip replaced the Help body and the
  public `/help` page reflected it immediately (including the "Last
  updated by" line), the change was recorded in the audit log as
  `help_content_updated`, and the row was then deleted so the live
  database is left on the default content rather than the test edit.

### Phase 15 follow-up — richer public dashboard detail — Done

A quick follow-on to Phase 15's "All certificates"/"Certificate authorities"
sections: the same read-only, no-login public view now surfaces more detail
per the same trust boundary (no CSR text, no key material).

- **"All certificates" is now a table**, not a card grid, with columns for
  Subject and Issuer (common name, via the existing `SubjectCommonName`/
  `IssuerCommonName` helpers), Extended key usage (`ekuSummary`), Expires
  (formatted date plus the existing human "in N days" string), and Health —
  the same status badge (`badgeClass`/`dotClass`/`statusLabel`) already used
  in "Needs attention", or a neutral "Pending" pill for anything not yet
  issued. The Certificate column stays a plain, non-clickable `<span>` for
  an anonymous visitor and an `<a>` into the detail page for a signed-in
  one, same as before.
- **"Certificate authorities" gained per-CA stats**: issued vs. pending
  count and the soonest upcoming expiry within that CA's certificates, via
  a new `issuerSummary` template func in `render.go` (`IssuerSummaryStats`)
  that reduces an `IssuerGroup`'s certificates — no new service-layer code,
  since `GroupByIssuer` already provides everything needed.
- Verified live: `go build`/`vet`/`test`/`gofmt` clean, `NewRenderer()`
  parses with no error, and against real Postgres an anonymous `curl /`
  shows populated Subject/Issuer/EKU/Expires/Health columns and per-CA
  issued/pending/next-expiry stats, while a signed-in admin still sees
  clickable certificate links in the same table.

## Phase 16 — Admin chain editing, certificates-first vault page, light/dark theme, docked account footer, Help nav reorder, technical docs — Done

Six requests handled together as one batch:

- **Admin can edit and validate a certificate's chain.** New
  `certutil.ValidateChain(leaf, chain)` (`internal/pkg/certutil/chain.go`)
  checks signature linkage (`leaf.CheckSignatureFrom(chain[0])`, and each
  subsequent link), CA flags (`BasicConstraintsValid && IsCA`), and validity
  windows — deliberately **not** against any trust store, since this app's
  chains are as likely to terminate at an internal, self-signed root as a
  public one. `CertificateService.UpdateChain` parses the pasted PEM with
  the same `certutil.ParseCertificatesPEM`/`EncodeCertificatePEM` used
  everywhere else; a hard parse failure blocks the save
  (`domain.Invalid`), but a chain that parses fine and merely fails
  logical validation still saves, with every issue reported back in the
  flash message — matching the Phase 15 "Help save always succeeds,
  validation is informational" precedent. New route
  `POST /certificates/{id}/chain` (`requireAdmin`); new audit action
  `AuditCertificateChainEdited`. Covered by real crypto-based tests in
  `chain_test.go` (ECDSA chains built with `x509.CreateCertificate`): a
  properly signed chain validates, a chain in the wrong order doesn't, an
  expired intermediate is caught, and an empty chain is trivially valid.
- **Certificates menu opens on the list, not the intake form.** `/certificates`
  now renders the certificate list and the CA breakdown first — the intake
  section (Generate/Import/Upload, unchanged internally) is collapsed by
  default behind a top-right "Add a certificate" button. This stays one
  route/one page (no new `/certificates/new`) — the button is a
  `data-toggle-target="add-certificate"` element handled by a small new
  generic toggle handler in `app.js` (`data-toggle-target` /
  `data-toggle-label-open` / `data-toggle-label-closed`, with
  `scrollIntoView` on open), the same delegated-listener pattern as the
  existing `data-tabs` mechanism — no new route, no framework.
- **Full light + dark theme, manual toggle.** Rather than doubling every
  class with Tailwind's `dark:` variant across 19 templates, the palette is
  now a set of CSS custom properties consumed through semantic Tailwind
  colors using the `rgb(var(--color-x) / <alpha-value>)` pattern (so
  opacity modifiers like `/40` keep working): `surface` (page background),
  `card` (panels/dropdowns), `line` (borders/rings/dividers), `ink`/
  `ink-1`..`ink-6` (text shades), and `hue-emerald`/`hue-amber`/
  `hue-orange`/`hue-rose`/`hue-sky` (+ `-strong` variants) for status/badge/
  link text. Dark values live on bare `:root` in `web/input.css`, light
  overrides on `:root[data-theme="light"]`, and `tailwind.config.js` maps
  each token name to its CSS variable. The toggle itself is a plain `theme`
  cookie (`light`/`dark`, default `dark`) read server-side by
  `themeFromRequest(r)` and stamped onto `<html data-theme="...">` at
  render time — zero client-side JavaScript, zero flash-of-wrong-theme,
  consistent with this app's no-inline-script CSP and htmx-first philosophy.
  `POST /theme` (public, cosmetic, no session needed) flips the cookie and
  redirects back to wherever the toggle was clicked, rejecting a
  protocol-relative `redirect` value to avoid becoming an open redirect.
  Every template was retokenized from the old literal `slate`/`white`
  classes to the new semantic ones; a handful of intentional exceptions
  stayed literal (the QR code's solid white background in
  `mfa_enroll.html`, a couple of neutral `slate-400`/`slate-500` accents).
- **Docked account footer.** The sidebar `<aside>` is now
  `lg:sticky lg:top-0 lg:h-screen` with the `<nav>` set to
  `lg:overflow-y-auto lg:overflow-x-visible` — the nav list scrolls
  internally on a short viewport while the theme toggle and
  account/sign-out block stay pinned at the bottom of the screen instead of
  scrolling away with the page.
- **Help moved after Audit log for admins.** For a signed-in admin
  (`.User.Role.CanManageUsers`), the Help link now renders last in the
  sidebar — after Users, Audit log, and the new Technical docs link.
  Everyone else (anonymous visitors, editors, viewers) keeps Help in its
  original position, right after Dashboard, since it's their primary
  self-service entry point.
- **Technical docs page for admins.** New `GET /admin/docs`
  (`requireAdmin`) — static content, no database reads, documenting the
  layering (`delivery/http → service → domain ← repository/postgres`), the
  exact middleware order (`recoverer` → `requestLogger` → `securityHeaders`
  → `csrfProtect` → `loadSession` → mux → `requireAuth`/`requireWrite`/
  `requireAdmin`), and nine request-flow narratives (sign in with MFA,
  generate a CSR, import a CSR + key, upload a certificate, attach a CA's
  response, self-sign, edit a chain, download/export, edit Help, switch
  theme) each naming the exact handler → service method → repo/certutil
  calls involved. Unlike Help, there's no admin-editable version of this
  page — editing it means editing the page itself, since it's documentation
  about the code rather than data from it.
- Verified live: `go build`/`vet`/`test`/`gofmt` all clean; `NewRenderer()`
  parses every template including the new `admin_docs.html` with no error;
  `make css` rebuilt `static/app.css` and the new `surface`/`card`/`line`/
  `ink-*`/`hue-*` classes and both light/dark `--color-*` variable blocks
  survived Tailwind's purge. Against a real Postgres + running server:
  the theme toggle flips `data-theme` and the cookie correctly and a
  protocol-relative redirect is rejected; the admin nav shows Help last
  (Dashboard → Certificates → Users → Audit log → Technical docs → Help)
  while the anonymous/login nav keeps Help second; `/admin/docs` redirects
  an anonymous visitor to login and renders for an admin; `/certificates`
  opens on the list + CA breakdown with the intake section collapsed, and
  the "Add a certificate" button reveals it; a chain edit with a
  well-formed but non-matching intermediate saved successfully and
  reported the specific signature-mismatch issue in the flash, while an
  unparseable chain was rejected outright without saving. Screenshotted
  the dashboard, certificate vault (both collapsed and expanded), a
  certificate detail page, the technical docs page, and the login page in
  both themes.

## Open items

- Real SMTP credentials and a real Microsoft Teams incoming webhook URL have
  never been supplied. Alerting is built, wired, and verified against local
  mocks; only live third-party delivery is unverified. No action needed
  unless/until real credentials are provided.
- `Makefile` sync note: if this repo is synced to a local folder through a
  tool that refuses to write a file literally named `Makefile`, it may land
  as `Makefile.txt` — rename it back to `Makefile` before running `make`
  targets. (See `CLAUDE.md`.)
