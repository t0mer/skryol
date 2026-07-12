// Package scanner drives scheduled and on-demand scans of assets: it resolves
// targets, pulls host data from Shodan through the rate-limited client, persists
// the raw report plus normalized findings, and hands the result to an optional
// post-processor (diff/scoring/alerts).
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/keys"
	"github.com/t0mer/skryol/internal/metrics"
	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/shodan"
)

// Processor is an optional post-scan hook (diff + scoring + alerts). It runs
// after a scan and its findings have been persisted.
type Processor interface {
	ProcessScan(ctx context.Context, asset models.Asset, scan *models.Scan, findings []models.Finding) error
}

// Scanner orchestrates scans.
type Scanner struct {
	db      *db.DB
	client  *shodan.Client
	keys    *keys.Service
	log     *slog.Logger
	metrics *metrics.Metrics

	cfgMu sync.RWMutex // guards cfg (live-reconfigurable)
	cfg   config.ScannerConfig

	processor Processor

	cronMu sync.Mutex // guards cron
	cron   *cron.Cron

	batchMu sync.Mutex // serializes batch runs
}

// New builds a Scanner.
func New(database *db.DB, client *shodan.Client, keySvc *keys.Service, m *metrics.Metrics, log *slog.Logger, cfg config.ScannerConfig) *Scanner {
	return &Scanner{db: database, client: client, keys: keySvc, metrics: m, log: log, cfg: cfg}
}

// SetProcessor installs the post-scan processor.
func (s *Scanner) SetProcessor(p Processor) { s.processor = p }

// config returns a snapshot of the current scanner configuration.
func (s *Scanner) config() config.ScannerConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// Start schedules the daily batch. It does not block.
func (s *Scanner) Start() error {
	return s.buildCron(s.config().Schedule)
}

// buildCron replaces the running cron with a fresh one bound to schedule.
func (s *Scanner) buildCron(schedule string) error {
	c := cron.New()
	_, err := c.AddFunc(schedule, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		if _, err := s.ScanAll(ctx); err != nil {
			s.log.Error("scheduled scan batch failed", "err", err)
		}
	})
	if err != nil {
		return fmt.Errorf("scheduling scan (%q): %w", schedule, err)
	}
	c.Start()

	s.cronMu.Lock()
	old := s.cron
	s.cron = c
	s.cronMu.Unlock()
	if old != nil {
		old.Stop()
	}
	s.log.Info("scan scheduler started", "schedule", schedule)
	return nil
}

// Reconfigure applies new scanner settings to the running process: guardrails
// take effect on the next scan, and the cron is rebuilt when the schedule
// changes. An invalid cron expression is rejected and the previous schedule and
// its running cron are left untouched.
func (s *Scanner) Reconfigure(cfg config.ScannerConfig) error {
	old := s.config()
	if cfg.Schedule != old.Schedule {
		// Validate before committing so a bad expression can't stop scans.
		if _, err := cron.ParseStandard(cfg.Schedule); err != nil {
			return fmt.Errorf("invalid schedule %q: %w", cfg.Schedule, err)
		}
	}

	s.cfgMu.Lock()
	s.cfg = cfg
	s.cfgMu.Unlock()

	if cfg.Schedule != old.Schedule {
		if err := s.buildCron(cfg.Schedule); err != nil {
			// Roll back to the previous known-good schedule.
			s.cfgMu.Lock()
			s.cfg.Schedule = old.Schedule
			s.cfgMu.Unlock()
			return err
		}
	}
	return nil
}

// Stop halts the scheduler.
func (s *Scanner) Stop() {
	s.cronMu.Lock()
	c := s.cron
	s.cronMu.Unlock()
	if c != nil {
		c.Stop()
	}
}

// BatchResult summarizes a fleet-wide run.
type BatchResult struct {
	Total   int `json:"total"`
	OK      int `json:"ok"`
	Partial int `json:"partial"`
	Failed  int `json:"failed"`
}

// ScanAll scans every enabled asset with bounded concurrency.
func (s *Scanner) ScanAll(ctx context.Context) (*BatchResult, error) {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	assets, err := s.db.ListEnabledAssets(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing assets: %w", err)
	}

	// Refresh credits before the batch so key selection is well-informed.
	s.client.RefreshCredits(ctx)
	s.keys.PersistPoolState(ctx)

	if !s.client.Pool().HasUsable() {
		return nil, errors.New("no healthy Shodan keys available; aborting batch")
	}

	result := &BatchResult{Total: len(assets)}
	var mu sync.Mutex

	cfg := s.config()
	conc := cfg.MaxConcurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, a := range assets {
		a := a
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			scan, err := s.ScanAsset(ctx, a)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				s.log.Error("asset scan errored", "asset", a.Value, "err", err)
				result.Failed++
				return
			}
			switch scan.Status {
			case models.ScanOK:
				result.OK++
			case models.ScanPartial:
				result.Partial++
			default:
				result.Failed++
			}
		}()
	}
	wg.Wait()

	s.keys.PersistPoolState(ctx)
	if n, err := s.db.PruneRawScans(ctx, cfg.RetentionDays); err != nil {
		s.log.Warn("pruning raw scans failed", "err", err)
	} else if n > 0 {
		s.log.Info("pruned raw scan reports", "count", n)
	}

	s.log.Info("scan batch complete", "total", result.Total, "ok", result.OK, "partial", result.Partial, "failed", result.Failed)
	return result, nil
}

// ScanAsset performs a full scan of one asset and persists it.
func (s *Scanner) ScanAsset(ctx context.Context, a models.Asset) (*models.Scan, error) {
	started := time.Now().UTC()
	scan := &models.Scan{
		AssetID:   a.ID,
		StartedAt: started,
		Status:    models.ScanOK,
	}

	targets, err := s.resolveTargets(ctx, a)
	if err != nil {
		return s.persistFailed(ctx, a, scan, fmt.Sprintf("target resolution: %v", err))
	}

	// Optional on-demand rescan through Shodan's scan API.
	if a.Rescan {
		s.maybeRescan(ctx, targets)
	}

	rawByTarget := map[string]json.RawMessage{}
	errByTarget := map[string]string{}
	var allFindings []models.Finding
	okCount := 0

	for _, ip := range targets {
		hr, raw, herr := s.client.Host(ctx, ip)
		if errors.Is(herr, shodan.ErrHostNotFound) {
			// No data is a valid result (asset offline / unindexed).
			rawByTarget[ip] = raw
			okCount++
			continue
		}
		if herr != nil {
			errByTarget[ip] = herr.Error()
			s.log.Warn("host lookup failed", "asset", a.Value, "ip", ip, "err", herr)
			continue
		}
		rawByTarget[ip] = raw
		okCount++

		findings, _ := shodan.MapHost(hr)
		for _, f := range findings {
			allFindings = append(allFindings, toModelFinding(f))
		}
	}

	// Determine status.
	switch {
	case okCount == 0:
		return s.persistFailed(ctx, a, scan, summarizeErrors(errByTarget))
	case len(errByTarget) > 0:
		scan.Status = models.ScanPartial
	default:
		scan.Status = models.ScanOK
	}

	// Aggregate raw report.
	rawDoc := map[string]any{
		"asset":   a.Value,
		"type":    a.Type,
		"targets": rawByTarget,
		"errors":  errByTarget,
	}
	rawBytes, _ := json.Marshal(rawDoc)
	scan.RawJSON = rawBytes

	// Derived summary counts.
	applyCounts(scan, allFindings)
	finished := time.Now().UTC()
	scan.FinishedAt = &finished
	if len(errByTarget) > 0 {
		scan.Error = summarizeErrors(errByTarget)
	}

	if err := s.db.CreateScan(ctx, scan, allFindings); err != nil {
		return nil, fmt.Errorf("persisting scan: %w", err)
	}

	s.recordMetrics(a, scan)

	if s.processor != nil {
		if err := s.processor.ProcessScan(ctx, a, scan, allFindings); err != nil {
			s.log.Error("post-scan processing failed", "asset", a.Value, "err", err)
		}
	}
	return scan, nil
}

func (s *Scanner) persistFailed(ctx context.Context, a models.Asset, scan *models.Scan, msg string) (*models.Scan, error) {
	scan.Status = models.ScanFailed
	scan.Error = msg
	finished := time.Now().UTC()
	scan.FinishedAt = &finished
	scan.RawJSON = []byte(`{}`)
	if err := s.db.CreateScan(ctx, scan, nil); err != nil {
		return nil, fmt.Errorf("persisting failed scan: %w", err)
	}
	s.recordMetrics(a, scan)
	s.log.Warn("asset scan failed", "asset", a.Value, "error", msg)
	return scan, nil
}

func (s *Scanner) maybeRescan(ctx context.Context, ips []string) {
	sub, err := s.client.SubmitScan(ctx, ips)
	if err != nil {
		s.log.Warn("on-demand rescan submit failed", "err", err)
		return
	}
	deadline := time.Now().Add(time.Duration(s.config().RescanTimeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.client.ScanStatus(ctx, sub.ID)
		if err != nil {
			s.log.Warn("rescan status poll failed", "id", sub.ID, "err", err)
			return
		}
		if st.Status == "DONE" {
			s.log.Info("on-demand rescan complete", "id", sub.ID)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	s.log.Warn("on-demand rescan timed out; using existing Shodan data", "id", sub.ID)
}

func (s *Scanner) recordMetrics(a models.Asset, scan *models.Scan) {
	s.metrics.ScansTotal.WithLabelValues(string(scan.Status)).Inc()
	if scan.FinishedAt != nil {
		s.metrics.ScanDuration.WithLabelValues(string(a.Type)).Observe(scan.FinishedAt.Sub(scan.StartedAt).Seconds())
	}
}

// toModelFinding converts a normalized shodan finding to the persistence model.
func toModelFinding(f shodan.Finding) models.Finding {
	detail, _ := json.Marshal(f.Detail)
	return models.Finding{
		TargetIP: f.TargetIP,
		Kind:     string(f.Kind),
		Severity: string(f.Severity),
		CVSS:     f.CVSS,
		Key:      f.Key,
		Detail:   detail,
	}
}

// applyCounts derives summary metrics from the finding set.
func applyCounts(scan *models.Scan, findings []models.Finding) {
	var highest float64
	ports, cves, critical := 0, 0, 0
	for _, f := range findings {
		switch f.Kind {
		case string(shodan.KindPort):
			ports++
		case string(shodan.KindCVE):
			cves++
			if f.CVSS > highest {
				highest = f.CVSS
			}
		}
		if f.Severity == string(shodan.SeverityCritical) {
			critical++
		}
	}
	scan.OpenPortsCount = ports
	scan.CVECount = cves
	scan.CriticalCount = critical
	scan.HighestCVSS = highest
}

func summarizeErrors(errByTarget map[string]string) string {
	if len(errByTarget) == 0 {
		return "scan failed"
	}
	for ip, e := range errByTarget {
		return fmt.Sprintf("%s: %s (and %d more)", ip, e, len(errByTarget)-1)
	}
	return "scan failed"
}
