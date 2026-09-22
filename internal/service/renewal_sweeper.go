package service

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// RenewalSweeper periodically drafts renewal tickets for internal
// certificates approaching expiry, mirroring AlertSweeper's shape but on its
// own instance and its own cadence — see
// CertificateRequestService.AutoDraftRenewals for what a sweep actually
// does. Deliberately a separate ticker from the alert sweeper's, rather than
// tacked onto its tick, so the two can be re-tuned independently — "how
// often do we re-check expiry for alerting" and "how often do we draft
// renewal tickets" are different operational questions even though they
// scan overlapping data.
type RenewalSweeper struct {
	requests *CertificateRequestService
	log      *slog.Logger
	interval time.Duration

	lastRun atomic.Int64 // unix seconds
	running atomic.Bool
}

// NewRenewalSweeper builds the background sweeper.
func NewRenewalSweeper(requests *CertificateRequestService, log *slog.Logger, interval time.Duration) *RenewalSweeper {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return &RenewalSweeper{requests: requests, log: log, interval: interval}
}

// Run blocks until ctx is cancelled, sweeping every interval. A sweep that is
// still running when the next tick arrives is skipped rather than overlapped.
func (s *RenewalSweeper) Run(ctx context.Context) {
	s.log.Info("renewal sweeper started", "interval", s.interval.String())

	// Give the HTTP server — and the alert sweeper's own initial sweep — a
	// moment to settle before the first run.
	timer := time.NewTimer(10 * time.Second)
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
			s.log.Info("renewal sweeper stopped")
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

// LastRun reports when the last sweep finished.
func (s *RenewalSweeper) LastRun() time.Time {
	sec := s.lastRun.Load()
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// Interval exposes the configured sweep period.
func (s *RenewalSweeper) Interval() time.Duration { return s.interval }

func (s *RenewalSweeper) sweep(ctx context.Context) {
	if !s.running.CompareAndSwap(false, true) {
		s.log.Warn("renewal sweep skipped, previous run still in flight")
		return
	}
	defer s.running.Store(false)

	start := time.Now()
	n, err := s.requests.AutoDraftRenewals(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("renewal sweep failed", "error", err)
		}
		return
	}
	s.lastRun.Store(time.Now().Unix())
	if n > 0 {
		s.log.Info("renewal sweep complete", "tickets_drafted", n, "duration", time.Since(start).String())
	}
}
