// Command server runs the SSL Admin certificate vault.
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
	"github.com/ivangiovn/ssl-generator/internal/pkg/authcrypto"
	"github.com/ivangiovn/ssl-generator/internal/pkg/notify"
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

	sealer, err := secret.NewSealer(cfg.EncryptionKey)
	if err != nil {
		return err
	}
	if !sealer.Enabled() {
		log.Warn("APP_ENCRYPTION_KEY is not set — private keys will be stored unencrypted")
	}

	// repository -> service -> delivery
	certRepo := postgres.NewCertificateRepository(pool)

	certSvc := service.NewCertificateService(certRepo, sealer, log, service.CertificateOptions{
		WarningDays:  cfg.ExpiryWarningDays,
		CriticalDays: cfg.ExpiryCriticalDays,
	})

	emailNotifier := notify.NewEmailNotifier(notify.EmailConfig{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort,
		Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
		From: cfg.AlertFrom, To: cfg.AlertTo,
	})
	teamsNotifier := notify.NewTeamsNotifier(cfg.TeamsWebhookURL)
	alertSvc := service.NewAlertService(certRepo, emailNotifier, teamsNotifier, log, service.AlertThresholds{
		WarningDays:  cfg.ExpiryWarningDays,
		CriticalDays: cfg.ExpiryCriticalDays,
		FinalDays:    cfg.ExpiryFinalDays,
	})
	if alertSvc.Enabled() {
		log.Info("alerting enabled", "email", emailNotifier.Enabled(), "teams", teamsNotifier.Enabled())
	} else {
		log.Warn("alerting is not configured — set SMTP_HOST/ALERT_EMAIL_* and/or TEAMS_WEBHOOK_URL to enable it")
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
	authSvc := service.NewAuthService(userRepo, log, service.AuthOptions{
		SessionSecret:   sessionSecret,
		IdleTimeout:     cfg.SessionIdleTimeout,
		AbsoluteTimeout: cfg.SessionAbsoluteTimeout,
		Issuer:          "SSL Admin",
	})
	if err := authSvc.Bootstrap(ctx, cfg.AdminEmail, cfg.AdminInitialPassword); err != nil {
		log.Warn("account bootstrap skipped", "error", err)
	}

	auditRepo := postgres.NewAuditRepository(pool)
	auditSvc := service.NewAuditService(auditRepo, log)

	contentRepo := postgres.NewSiteContentRepository(pool)
	contentSvc := service.NewSiteContentService(contentRepo)

	server, err := delivery.NewServer(certSvc, sweeper, authSvc, auditSvc, contentSvc, log, cfg.CookieSecure)
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
