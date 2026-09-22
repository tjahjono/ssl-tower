package service

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// AlertSweeper periodically re-evaluates every issued certificate against
// the configured alerting thresholds. It replaces the old endpoint-checking
// Scheduler (Phase 10 dropped live TLS handshakes entirely) — there is
// nothing left to check over the network, only expiry dates already on
// file, so a sweep is just a cheap DB scan plus notification sends.
type AlertSweeper struct {
	certs    *CertificateService
	log      *slog.Logger
	interval time.Duration

	lastRun atomic.Int64 // unix seconds
	running atomic.Bool
}

// NewAlertSweeper builds the background sweeper.
func NewAlertSweeper(certs *CertificateService, log *slog.Logger, interval time.Duration) *AlertSweeper {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return &AlertSweeper{certs: certs, log: log, interval: interval}
}

// Run blocks until ctx is cancelled, sweeping every interval. A sweep that is
// still running when the next tick arrives is skipped rather than overlapped.
func (s *AlertSweeper) Run(ctx context.Context) {
	s.log.Info("alert sweeper started", "interval", s.interval.String())

	// Give the HTTP server a moment to come up before the first sweep.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		s.sweep(ctx)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.log.Info("alert sweeper stopped")
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

// LastRun reports when the last sweep finished.
func (s *AlertSweeper) LastRun() time.Time {
	sec := s.lastRun.Load()
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// Interval exposes the configured sweep period.
func (s *AlertSweeper) Interval() time.Duration { return s.interval }

func (s *AlertSweeper) sweep(ctx context.Context) {
	if !s.running.CompareAndSwap(false, true) {
		s.log.Warn("alert sweep skipped, previous run still in flight")
		return
	}
	defer s.running.Store(false)

	start := time.Now()
	n, err := s.certs.AlertSweep(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("alert sweep failed", "error", err)
		}
		return
	}
	s.lastRun.Store(time.Now().Unix())
	s.log.Info("alert sweep complete", "certificates", n, "duration", time.Since(start).String())
}
