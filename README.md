# SSL Admin

A certificate vault: generate signing requests with their key pairs or upload
certificates you already have, export the result in whatever encoding the target
platform wants, and get alerted before any of it expires — all behind role-gated
logins with MFA and a full audit trail.

Go · PostgreSQL · htmx · Tailwind CSS. No SPA, no build step at runtime: templates
and static assets are embedded in the binary.

---

## What it does

**Certificate vault**

A certificate enters the vault one of three ways, and all land in the same table with the same
downloads, health checks, and expiry alerts once they're in:

- *Generate* — an RSA (2048/3072/4096) or ECDSA (P-256/P-384/P-521) key pair plus a CSR. Subject
  fields, DNS SANs and IP SANs; the common name is always added to the SAN list. Pick the
  extended key usage(s) — server auth, client auth, code signing, email protection, timestamping,
  OCSP signing — requested via the CSR's extension-request attribute; an internal CA can honour it,
  though most public CAs decide EKU from their own product profile regardless. Paste the
  certificate your CA issues back in — it's rejected if it doesn't match the stored private key,
  and a pasted full chain is split into leaf + intermediates automatically. Self-sign from the
  same key when you need staging up before the CA responds — self-signing always applies exactly
  the EKU you requested, since this app is the issuer.
- *Import a CSR + key* — already generated a signing request and its key somewhere else (your own
  laptop with `openssl`, say) instead of through this page? Paste both in. Subject, SANs, and any
  EKU the CSR itself requests are read straight off the pasted CSR rather than retyped, and it's
  filed as a pending certificate — the key is rejected if it doesn't match — ready for the exact
  same attach/self-sign/download flow as one generated in-app.
- *Upload* — a certificate you already have, either as a PEM triplet (certificate, optional chain,
  optional private key — pasted as text) or a PKCS#12 (`.pfx`/`.p12`) bundle. Bulk-upload several
  `.pfx` files at once with a shared password, the way a CA or a Windows export usually hands over
  a batch; each file succeeds or fails independently. A certificate can be filed without its
  private key too, for reference — downloads that need the key just aren't offered for it.

There is no live endpoint monitoring: expiry is read from the certificate's own `notAfter`, not a
TLS handshake against a server. Every certificate carries an `Owner`/team tag and an `Origin`
(generated or uploaded) so an IT team can tell at a glance who to ask about it. The extended key
usage shown on a certificate's detail page is whatever was requested while it's still pending, and
whatever the issued leaf actually carries once it's attached, self-signed, or uploaded — a CA is
free to have honoured, ignored, or overridden the request.

**Weak-certificate flags**

Every issued certificate is checked once, at the moment it's issued or uploaded, for hygiene
problems independent of expiry: a weak signature algorithm (MD5/SHA-1), an undersized key (RSA
under 2048 bits, ECDSA under 256), whether it's self-signed, and whether intermediates were
supplied alongside it. These show up as notes on the certificate table and a "Certificate health"
panel on its detail page.

**Downloads**

| Format | Extension | Contents | Typical target |
| --- | --- | --- | --- |
| PEM chain | `.pem` | leaf + intermediates | nginx, Apache, HAProxy |
| Certificate | `.crt` | leaf only, PEM | most Unix servers |
| DER | `.der` / `.cer` | leaf only, binary | Java keystores, Windows |
| PKCS#7 | `.p7b` | certificate chain, DER | Windows / IIS |
| PKCS#12 | `.pfx` / `.p12` | key + leaf + chain, password protected | IIS, Azure, Java, load balancers |
| Private key | `.key` | PKCS#8 PEM | pairs with the certificate |
| Signing request | `.csr` | PEM | send to the CA |
| Bundle | `.zip` | all of the above | hand-off |

PKCS#12 defaults to modern encryption (AES-256-CBC / SHA-256); tick **legacy** for
RC2/3DES when the target is old Windows, Java 8 or an appliance. A certificate filed
without its private key offers a `.pfx` trust store instead of a key store, and skips
`.key`/full `.zip` entirely.

Downloads are role-gated (see Accounts below): **only an admin can download a
certificate or any key material.** The one carve-out is the bare signing request
(`.csr`, no key involved) — an editor can still export that to send to a CA.

**Alerting**

- Email (SMTP, STARTTLS or implicit TLS) and/or a Microsoft Teams incoming webhook —
  either, both, or neither; each is independently opt-in via its own env vars.
- Fires once per state change — a certificate crossing the warning/critical/final
  threshold, or recovering (replaced by a fresh one) — never on every sweep.
- Checked immediately whenever a certificate is generated, issued, or uploaded, and
  again on a periodic background sweep (`ALERT_SWEEP_INTERVAL`) that catches a
  certificate quietly crossing a threshold with no action of its own.
- Fully optional: leave both channels unconfigured and the app logs a boot-time
  warning and simply doesn't send anything.

**Accounts, roles, and MFA**

- Three roles: **admin** (manages accounts, and the only role that can download a
  certificate or key material), **editor** (full read-write on the certificate
  vault, plus exporting a bare signing request), **viewer** (read-only, no downloads
  at all).
- The certificate dashboard and the `/help` request/renew guide are the only
  pages reachable without an account. The dashboard's certificate list and
  CA breakdown are deliberately public and read-only there (cards aren't
  clickable for an anonymous visitor — following one into the vault still
  needs a session). Everything else — the certificate vault, account and
  admin pages, and editing Help itself — needs a session even to read;
  creating, changing, or deleting anything additionally needs an editor or
  admin role.
- The Help page's content is admin-editable (`/help/edit`) rather than fixed
  in the binary — an admin can rewrite the request/renew guide from the UI,
  with the original guide as the built-in default until they do.
- TOTP-based MFA (any standard authenticator app) is mandatory, enforced server-side
  before any other authenticated route — not just hidden in the UI. Ten single-use
  recovery codes are issued at enrollment.
- Every write route checks the caller's role server-side; a viewer session gets a
  403 from the API, not just a hidden button.

**Audit log**

- Every login (success and failure), account change, certificate mutation, and
  private-key download is recorded with actor, timestamp, target, and client IP.
- Admin-only, filterable by actor email, action, and date range.

---

## Running it

**Docker Compose is the primary path** — one command brings up Postgres and the app together:

```bash
make docker                   # generates .env on first run, then builds + starts everything
```

Then open <http://localhost:8080>. `make docker` depends on `make env`, which creates
`.env` from `.env.example` and fills in a random `APP_ENCRYPTION_KEY`, `SESSION_SECRET`,
and `ADMIN_INITIAL_PASSWORD` the first time it runs — printing the generated admin
password once — and leaves `.env` alone on every run after that, so your keys and
accounts survive a rebuild. Plain `docker compose up --build` works too, but skips
that step, so private keys go unencrypted and no admin account is bootstrapped
unless `.env` already exists.

Sign in with `admin@example.com` and the password `make env` printed (or whatever
you set `ADMIN_INITIAL_PASSWORD` to). You'll be forced to change it, then enroll MFA
with an authenticator app, before you can do anything else.

Stop everything with `docker compose down` (add `-v` to also drop the Postgres volume).

**Local Go toolchain instead**, if you'd rather run the binary on the host and only
containerize Postgres — requires Go 1.24+ and PostgreSQL 13+ (`gen_random_uuid()` is
used, no extension needed):

```bash
make env                      # once, to generate .env
make db                       # Postgres 16 in Docker on :5432
make run                      # migrations apply automatically at boot
```

`make run` is just `go run ./cmd/server` — nothing Make-specific about how it picks
up `.env`; the binary loads it itself, so running the built binary
(`./bin/server`) or `go run ./cmd/server` directly from the repo root works the
same way, no manual exporting needed.

### Configuration

The app loads `.env` itself on boot — from the current working directory, no shell
sourcing or extra tooling needed — and layers it beneath whatever's already in the
real environment (a variable set by your shell, `docker compose`'s `environment:`
block, or a process manager always wins over `.env`; `.env` just fills in the rest).
`.env.example` is the full list of settings and the only source of defaults; the
binary has none of its own. Everything marked **required** below must resolve to a
real value from one of those two places or the app refuses to start, printing
exactly which variables are missing. Everything marked **optional** is a feature
toggle whose empty value is itself meaningful (the feature is just off).

| Variable | Required? | Purpose |
| --- | --- | --- |
| `HTTP_ADDR` | required | listen address |
| `DATABASE_URL` | required | connection string |
| `DB_MAX_CONNS` / `DB_CONNECT_TIMEOUT` | required | Postgres pool sizing and connect timeout |
| `ALERT_SWEEP_INTERVAL` | required | how often the background sweeper re-checks every issued certificate's expiry |
| `EXPIRY_WARNING_DAYS` / `EXPIRY_CRITICAL_DAYS` / `EXPIRY_FINAL_DAYS` | required | expiry thresholds, in descending order |
| `SESSION_IDLE_TIMEOUT` / `SESSION_ABSOLUTE_TIMEOUT` | required | a session's inactivity limit and hard lifetime cap |
| `COOKIE_SECURE` | required | mark session/CSRF cookies `Secure`; `true` once behind TLS |
| `SMTP_PORT` | required | only meaningful once `SMTP_HOST` is set, but still needs a value |
| `APP_ENCRYPTION_KEY` | optional | base64 32 bytes; encrypts stored private keys with AES-256-GCM — empty stores them as plaintext PEM |
| `SESSION_SECRET` | optional | base64 32 bytes; signs the short-lived pending-MFA token — empty falls back to an ephemeral, restart-sensitive secret |
| `ADMIN_EMAIL` / `ADMIN_INITIAL_PASSWORD` | optional | bootstraps the first admin account on an empty database; ignored once any account exists |
| `SMTP_HOST` / `SMTP_USERNAME` / `SMTP_PASSWORD` | optional | email alert channel; leave `SMTP_HOST` empty to disable it |
| `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | optional | sender and comma-separated recipients for email alerts |
| `TEAMS_WEBHOOK_URL` | optional | Microsoft Teams incoming webhook; leave empty to disable Teams alerts |

`make env` creates `.env` from `.env.example` — which already has a sensible value
for every required variable — then overwrites just `APP_ENCRYPTION_KEY`,
`SESSION_SECRET`, and `ADMIN_INITIAL_PASSWORD` with freshly generated ones. Rotating
`APP_ENCRYPTION_KEY` by hand makes existing stored keys unreadable — there is no
re-wrap migration. Alerting and the very first admin account are both opt-in: leave
their env vars unset and the app logs a boot-time warning and keeps running without
them (though with no admin account, nobody can sign in until one is bootstrapped by
setting `ADMIN_EMAIL`/`ADMIN_INITIAL_PASSWORD` and restarting).

---

## Layout

```
cmd/server/                     entry point: config → db → repos → services → http
internal/
  config/                       environment configuration
  database/                     pgx pool + embedded SQL migrations (applied at boot)
  domain/                       entities, validation, repository interfaces (ports)
  repository/postgres/          pgx implementations — the only place SQL lives
  service/                      business rules: the certificate vault, alerting, the alert sweeper
  delivery/http/                router, handlers, templates, static assets
    templates/pages/            one full page each, rendered through layout.html
    templates/partials/         htmx fragments, reused by both pages and swaps
  pkg/certutil/                 keys, CSRs, PKCS#12 encode/decode, export encoders
  pkg/secret/                   AES-256-GCM envelope encryption for key material
  pkg/authcrypto/                password hashing, session tokens, recovery codes
  pkg/notify/                    email (SMTP) and Microsoft Teams alert senders
web/input.css                   Tailwind source
```

Dependencies point inward: `delivery → service → domain ← repository`. The domain
package declares the repository interfaces and imports neither pgx nor net/http, so
the services can be tested against fakes and the storage engine is swappable.

### htmx

Handlers return either a full page or a named fragment, from the same template set:

- the certificate table refreshes on search/filter input (`hx-get`, `hx-include` the filter form)
  and after every create/import/delete, which re-render it via `hx-target`/`hx-swap`;
- the dashboard tiles auto-refresh every 60s via their own `/summary` partial;
- flash banners come back as out-of-band swaps, so any response can update them.

There is no inline JavaScript — the CSP forbids it. `static/app.js` is ~60 lines of
delegated listeners for copy buttons, banner dismissal and form resets, and every
page works without it.

### Tailwind

The stylesheet is prebuilt into `internal/delivery/http/static/app.css` and embedded,
so running the app needs no Node toolchain. Rebuild it after editing templates:

```bash
make css          # one-shot, downloads the standalone Tailwind CLI into ./bin
make css-watch    # rebuild on change
```

`tailwind.config.js` scans the Go sources too, because the status badge classes are
chosen in `internal/delivery/http/render.go` rather than in markup.

---

## Testing

```bash
make test
```

The certificate and encryption packages are covered directly: CSR generation and SAN
handling, key/certificate matching, self-signing, every export format round-tripped
back through a parser, weak-certificate health findings, issuer grouping, alert
threshold classification and dedupe, and the AES-GCM sealer.

---

## Security notes

- The certificate dashboard and `/help` are the only routes reachable
  without a session, by design; every other route — every certificate read,
  every write, editing Help itself — is gated behind one, enforced
  server-side in the route middleware, not just hidden in the UI. Downloads
  are gated further still: only an admin can download a certificate or key
  material (an editor may still export a bare `.csr`).
- The dashboard's public certificate list and CA breakdown are read-only:
  common name, key/status/origin, and SAN summary only — no CSR text, no
  key material, and the cards aren't links for an anonymous visitor.
- The Help page's saved content is rendered as raw, unescaped HTML and is
  writable only by an admin (`/help/edit`) — the same trust tier an admin
  already has over accounts and key material, but note that it now extends
  to injecting markup into a page that requires no session to view.
- MFA (TOTP) is mandatory for every account, enforced before any other
  authenticated route. Passwords are hashed with bcrypt; session tokens are opaque
  random values, SHA-256-hashed before storage, so a database leak never exposes a
  usable session or password.
- CSRF is enforced on every mutating request via a double-submit cookie, including
  the login form itself.
- Set `APP_ENCRYPTION_KEY` so private keys are encrypted at rest with AES-256-GCM.
- The database holds private keys (and, once written, password hashes and session
  data); treat backups accordingly.
- Responses set `X-Frame-Options: DENY`, `nosniff`, and a CSP with no third-party origins.
- Downloads are served with `Cache-Control: no-store`.
- Every login, account change, certificate mutation, and private-key download is
  recorded in the admin-only audit log (`/audit`).
- `COOKIE_SECURE=false` by default so local HTTP development works; set it `true`
  once the app sits behind TLS, so session and CSRF cookies are never sent in the clear.
