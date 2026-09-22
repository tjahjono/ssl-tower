package service

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ivangiovn/ssl-generator/internal/domain"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeAlertRepo is an in-memory stand-in for the persistence AlertService
// needs, letting the dedupe logic be tested without a real database.
type fakeAlertRepo struct {
	levels    map[uuid.UUID]int
	setCalls  int
	lastLevel int
}

func newFakeAlertRepo() *fakeAlertRepo {
	return &fakeAlertRepo{levels: map[uuid.UUID]int{}}
}

func (f *fakeAlertRepo) AlertLevel(_ context.Context, id uuid.UUID) (int, error) {
	return f.levels[id], nil
}

func (f *fakeAlertRepo) SetAlertLevel(_ context.Context, id uuid.UUID, level int) error {
	f.levels[id] = level
	f.setCalls++
	f.lastLevel = level
	return nil
}

// newTestSettingsService builds a SettingsService with its live snapshot
// pre-loaded directly (bypassing Bootstrap/Reload's repo round-trip, which
// tests in this package don't need) — settings.current is unexported but
// this file lives in the same package, so it can be set directly. Every
// notifier it builds is empty configuration (Enabled() == false), so tests
// exercise the dedupe/threshold logic without attempting any real network
// I/O.
func newTestSettingsService(s domain.AppSettings) *SettingsService {
	svc := NewSettingsService(nil, discardLogger())
	svc.current.Store(&s)
	return svc
}

// newTestAlertService builds an AlertService whose day-based thresholds come
// from settings (portal-editable as of v1.5) and whose percent-based
// thresholds come from thresholds (still static/env-only).
func newTestAlertService(repo AlertRepository, settings domain.AppSettings, thresholds AlertThresholds) *AlertService {
	return NewAlertService(repo, newTestSettingsService(settings), discardLogger(), thresholds)
}

func certAfterDays(d int) *domain.Certificate {
	na := time.Now().Add(time.Duration(d)*24*time.Hour + time.Hour)
	return &domain.Certificate{ID: uuid.New(), CommonName: "example.com", Status: domain.CertIssued, NotAfter: &na}
}

func TestAlertLevelForThresholds(t *testing.T) {
	svc := newTestAlertService(newFakeAlertRepo(),
		domain.AppSettings{ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1},
		AlertThresholds{})

	cases := []struct {
		name string
		c    *domain.Certificate
		want AlertLevel
	}{
		{"healthy, far from expiry", certAfterDays(90), AlertNone},
		{"just inside warning window", certAfterDays(30), AlertWarning},
		{"just inside critical window", certAfterDays(7), AlertCritical},
		{"just inside final window", certAfterDays(1), AlertFinal},
		{"already past notAfter", certAfterDays(-3), AlertFinal},
		{"never issued (nil NotAfter)", &domain.Certificate{Status: domain.CertIssued}, AlertNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := svc.levelFor(tc.c); got != tc.want {
				t.Fatalf("levelFor() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvaluateFiresOncePerStateChange(t *testing.T) {
	repo := newFakeAlertRepo()
	svc := newTestAlertService(repo,
		domain.AppSettings{ExpiryWarningDays: 30, ExpiryCriticalDays: 7, ExpiryFinalDays: 1},
		AlertThresholds{})
	id := uuid.New()
	cert := func(days int) *domain.Certificate {
		na := time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour)
		return &domain.Certificate{ID: id, CommonName: "example.com", Status: domain.CertIssued, NotAfter: &na}
	}

	// First evaluation at warning level: this is a new level, must persist it.
	svc.Evaluate(context.Background(), cert(20))
	if repo.setCalls != 1 || repo.lastLevel != int(AlertWarning) {
		t.Fatalf("expected one SetAlertLevel(Warning) call, got calls=%d last=%d", repo.setCalls, repo.lastLevel)
	}

	// Second evaluation, still ~20 days left (steady state): must NOT re-persist.
	svc.Evaluate(context.Background(), cert(20))
	if repo.setCalls != 1 {
		t.Fatalf("expected no additional SetAlertLevel call for a steady-state condition, got calls=%d", repo.setCalls)
	}

	// Escalates to critical: new level, must persist again.
	svc.Evaluate(context.Background(), cert(5))
	if repo.setCalls != 2 || repo.lastLevel != int(AlertCritical) {
		t.Fatalf("expected escalation to persist Critical, got calls=%d last=%d", repo.setCalls, repo.lastLevel)
	}

	// Recovers (a fresh, longer-lived certificate would be a new record in
	// practice, but the level-reset logic itself only cares about the delta):
	// must reset to None so a future re-degradation alerts again.
	svc.Evaluate(context.Background(), cert(90))
	if repo.setCalls != 3 || repo.lastLevel != int(AlertNone) {
		t.Fatalf("expected recovery to reset level to None, got calls=%d last=%d", repo.setCalls, repo.lastLevel)
	}

	// Re-degrades to the same Warning level as before recovery: must alert
	// again now that the level was reset, not stay silent forever.
	svc.Evaluate(context.Background(), cert(20))
	if repo.setCalls != 4 || repo.lastLevel != int(AlertWarning) {
		t.Fatalf("expected re-degradation after recovery to alert again, got calls=%d last=%d", repo.setCalls, repo.lastLevel)
	}
}

func TestEvaluateIgnoresNilAndPendingInputs(t *testing.T) {
	repo := newFakeAlertRepo()
	svc := newTestAlertService(repo, domain.AppSettings{}, AlertThresholds{})
	svc.Evaluate(context.Background(), nil)
	var nilSvc *AlertService
	nilSvc.Evaluate(context.Background(), &domain.Certificate{})
	svc.Evaluate(context.Background(), &domain.Certificate{Status: domain.CertPending})
	if repo.setCalls != 0 {
		t.Fatalf("expected nil/pending inputs to be a no-op, got %d SetAlertLevel calls", repo.setCalls)
	}
}
