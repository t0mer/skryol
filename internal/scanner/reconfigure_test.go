package scanner

import (
	"log/slog"
	"testing"

	"github.com/t0mer/skryol/internal/config"
)

func newTestScanner(cfg config.ScannerConfig) *Scanner {
	return &Scanner{log: slog.Default(), cfg: cfg}
}

func TestReconfigureUpdatesGuardrails(t *testing.T) {
	s := newTestScanner(config.ScannerConfig{
		Schedule:         "0 3 * * *",
		MaxHostsPerAsset: 256,
		MaxConcurrency:   4,
	})
	if err := s.buildCron(s.config().Schedule); err != nil {
		t.Fatalf("initial cron: %v", err)
	}
	defer s.Stop()

	err := s.Reconfigure(config.ScannerConfig{
		Schedule:         "0 3 * * *", // unchanged
		MaxHostsPerAsset: 64,
		MaxConcurrency:   8,
	})
	if err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	got := s.config()
	if got.MaxHostsPerAsset != 64 || got.MaxConcurrency != 8 {
		t.Fatalf("guardrails not applied: %+v", got)
	}
}

func TestReconfigureReschedules(t *testing.T) {
	s := newTestScanner(config.ScannerConfig{Schedule: "0 3 * * *"})
	if err := s.buildCron(s.config().Schedule); err != nil {
		t.Fatalf("initial cron: %v", err)
	}
	defer s.Stop()

	if err := s.Reconfigure(config.ScannerConfig{Schedule: "*/5 * * * *"}); err != nil {
		t.Fatalf("reschedule: %v", err)
	}
	if s.config().Schedule != "*/5 * * * *" {
		t.Fatalf("schedule not updated: %q", s.config().Schedule)
	}
}

func TestReconfigureRejectsBadCronKeepsOld(t *testing.T) {
	s := newTestScanner(config.ScannerConfig{Schedule: "0 3 * * *", MaxConcurrency: 4})
	if err := s.buildCron(s.config().Schedule); err != nil {
		t.Fatalf("initial cron: %v", err)
	}
	defer s.Stop()

	err := s.Reconfigure(config.ScannerConfig{Schedule: "not a cron", MaxConcurrency: 9})
	if err == nil {
		t.Fatal("expected error for invalid cron")
	}
	// The previous schedule must be preserved after a rejected reconfigure.
	if s.config().Schedule != "0 3 * * *" {
		t.Fatalf("schedule changed despite invalid cron: %q", s.config().Schedule)
	}
}
