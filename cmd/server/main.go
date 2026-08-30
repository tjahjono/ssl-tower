// Command server runs the SSL Tower certificate vault.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ivangiovn/ssl-generator/internal/config"
	"github.com/ivangiovn/ssl-generator/internal/database"
	delivery "github.com/ivangiovn/ssl-generator/internal/delivery/http"
	"github.com/ivangiovn/ssl-generator/internal/domain"
	"github.com/ivangiovn/ssl-generator/internal/pkg/authcrypto"
	"github.com/ivangiovn/ssl-generator/internal/pkg/digicert"
	"github.com/ivangiovn/ssl-generator/internal/pkg/ldapauth"

	"github.com/ivangiovn/ssl-generator/internal/pkg/secret"
	"github.com/ivangiovn/ssl-generator/internal/repository/postgres"
	"github.com/ivangiovn/ssl-generator/internal/service"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := newLogger(cfg.AppEnv)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBConnectTimout)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("connected to postgres")

	if err := database.Migrate(ctx, pool, log); err != nil {
		return err
	}

	// SettingsService owns every portal-editable operational setting (see
	// CLAUDE.md's v1.5 "config → portal" locked decision). Bootstrap is
	// safe to call on every boot: it only seeds a key from cfg when
	// app_settings has no row for it yet, exactly like AuthService.
	// Bootstrap below — from the first successful boot against a given
	// database onward, /settings and the database are authoritative and
	// these cfg values are ignored.
	settingsRepo := postgres.NewSettingsRepository(pool)
	settingsSvc := service.NewSettingsService(settingsRepo, log)
	seed := service.SeedValues{
		Settings: domain.AppSettings{
			ExpiryWarningDays:  cfg.ExpiryWarningDays,
			ExpiryCriticalDays: cfg.ExpiryCriticalDays,
			ExpiryFinalDays:    cfg.ExpiryFinalDays,
			SMTPHost:           cfg.SMTPHost,
			SMTPPort:           cfg.SMTPPort,
			SMTPUsername:       cfg.SMTPUsername,
			SMTPPassword:       cfg.SMTPPassword,
			AlertEmailFrom:     cfg.AlertFrom,
			AlertEmailTo:       cfg.AlertTo,
			TeamsWebhookURL:    cfg.TeamsWebhookURL,
			TicketSLADays:      cfg.TicketSLADays,
		},
		EncryptionKey: cfg.EncryptionKey,
	}
	if err := settingsSvc.Bootstrap(ctx, seed); err != nil {
		return err
	}

	// The encryption key is read straight from storage (bypassing
	// SettingsService's cached AppSettings snapshot — see
	// EncryptionKeyValue's doc comment) to build the sealer CertificateService
	// starts with. From here on the *only* supported way to change it is
	// CertificateService.RotateEncryptionKey, which re-encrypts every stored
	// private key and swaps the live sealer atomically — never by editing
	// APP_ENCRYPTION_KEY and restarting.
	encryptionKey, err := settingsSvc.EncryptionKeyValue(ctx)
	if err != nil {
		return err
	}
	sealer, err := secret.NewSealer(encryptionKey)
	if err != nil {
		return err
	}
	if !sealer.Enabled() {
		log.Warn("the vault's encryption key is not set — private keys will be stored unencrypted (set it from /settings)")
	}

	// repository -> service -> delivery
	certRepo := postgres.NewCertificateRepository(pool)
	rootCARepo := postgres.NewRootCARepository(pool)
	rotationRepo := postgres.NewEncryptionRotationRepository(pool)

	certSvc := service.NewCertificateService(certRepo, rootCARepo, rotationRepo, sealer, settingsSvc, log, service.CertificateOptions{
		WarningPercent:  cfg.ExpiryWarningPercent,
		CriticalPercent: cfg.ExpiryCriticalPercent,
	})

	alertSvc := service.NewAlertService(certRepo, settingsSvc, log, service.AlertThresholds{
		WarningPercent:  cfg.ExpiryWarningPercent,
		CriticalPercent: cfg.ExpiryCriticalPercent,
	})
	if alertSvc.Enabled() {
		log.Info("alerting enabled", "email", settingsSvc.EmailNotifier().Enabled(), "teams", settingsSvc.TeamsNotifier().Enabled())
	} else {
		log.Warn("alerting is not configured — set SMTP/ALERT_EMAIL_* and/or the Teams webhook from /settings to enable it")
	}
	certSvc.SetAlerter(alertSvc)

	sweeper := service.NewAlertSweeper(certSvc, log, cfg.AlertSweepInterval)
	go sweeper.Run(ctx)

	userRepo := postgres.NewUserRepository(pool)
	sessionSecret := cfg.SessionSecret
	if sessionSecret == "" {
		// Only tolerable because it just makes the short-lived "password
		// verified, awaiting MFA" token restart-sensitive — full sessions
		// are unaffected, since those are random opaque values looked up in
		// the sessions table, not signed by this secret.
		generated, err := authcrypto.RandomToken(32)
		if err != nil {
			return err
		}
		sessionSecret = generated
		log.Warn("SESSION_SECRET is not set — using an ephemeral secret for this run; a restart mid-MFA-login will require signing in again")
	}
	var ldapClient ldapauth.Client
	if cfg.LDAPURL != "" {
		ldapClient = ldapauth.NewLDAPClient(ldapauth.Config{
			URL:          cfg.LDAPURL,
			BindDN:       cfg.LDAPBindDN,
			BindPassword: cfg.LDAPBindPassword,
			BaseDN:       cfg.LDAPBaseDN,
			UserFilter:   cfg.LDAPUserFilter,
			GroupFilter:  cfg.LDAPGroupFilter,
		})
		log.Info("LDAP authentication enabled", "url", cfg.LDAPURL,
			"editor_groups", len(cfg.LDAPRoleMapEditor), "viewer_groups", len(cfg.LDAPRoleMapViewer),
			"requester_groups", len(cfg.LDAPRoleMapRequester))
	} else {
		log.Info("LDAP authentication is not configured — set LDAP_URL to enable it")
	}

	authSvc := service.NewAuthService(userRepo, log, service.AuthOptions{
		SessionSecret:   sessionSecret,
		IdleTimeout:     cfg.SessionIdleTimeout,
		AbsoluteTimeout: cfg.SessionAbsoluteTimeout,
		Issuer:          "SSL Tower",
		LDAP:            ldapClient,
		LDAPRoleMap: service.LDAPRoleMapping{
			Editor:    cfg.LDAPRoleMapEditor,
			Viewer:    cfg.LDAPRoleMapViewer,
			Requester: cfg.LDAPRoleMapRequester,
		},
	})
	if err := authSvc.Bootstrap(ctx, cfg.AdminEmail, cfg.AdminInitialPassword); err != nil {
		log.Warn("account bootstrap skipped", "error", err)
	}

	auditRepo := postgres.NewAuditRepository(pool)
	auditSvc := service.NewAuditService(auditRepo, log)

	contentRepo := postgres.NewSiteContentRepository(pool)
	contentSvc := service.NewSiteContentService(contentRepo)

	requestRepo := postgres.NewCertificateRequestRepository(pool)
	requestSvc := service.NewCertificateRequestService(requestRepo, certSvc, settingsSvc, log)

	if cfg.RenewalSweepInterval > 0 {
		renewalSweeper := service.NewRenewalSweeper(requestSvc, log, cfg.RenewalSweepInterval)
		go renewalSweeper.Run(ctx)
	} else {
		log.Info("renewal auto-drafting is not configured — set RENEWAL_SWEEP_INTERVAL to enable it")
	}

	var digiCertClient digicert.Client
	if cfg.DigiCertAPIKey != "" {
		digiCertClient = digicert.NewHTTPClient(cfg.DigiCertBaseURL, cfg.DigiCertAPIKey)
		log.Info("DigiCert integration enabled", "base_url", cfg.DigiCertBaseURL)
	} else {
		log.Info("DigiCert integration is not configured — set DIGICERT_API_KEY to enable it")
	}
	digiCertSvc := service.NewDigiCertService(requestRepo, certSvc, digiCertClient, log)

	server, err := delivery.NewServer(certSvc, sweeper, authSvc, auditSvc, contentSvc, requestSvc, digiCertSvc, settingsSvc, log, cfg.CookieSecure)
	if err != nil {
		return err
	}
	return server.Serve(ctx, cfg.HTTPAddr)
}

func newLogger(env string) *slog.Logger {
	level := slog.LevelInfo
	if env == "development" {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if env == "production" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
