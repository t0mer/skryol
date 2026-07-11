// Package processor runs after each scan: it computes the deterministic score,
// records score history, diffs against the previous scan, persists the diff, and
// hands the result to an optional alert evaluator.
package processor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/diff"
	"github.com/t0mer/skryol/internal/metrics"
	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/scoring"
)

// AlertEvaluator evaluates alert rules against a completed scan and its diff.
type AlertEvaluator interface {
	Evaluate(ctx context.Context, asset models.Asset, scan *models.Scan, summary models.DiffSummary) error
}

// WeightsProvider supplies the current scoring weights (tunable via settings).
type WeightsProvider func(ctx context.Context) scoring.Weights

// Processor implements scanner.Processor.
type Processor struct {
	db      *db.DB
	metrics *metrics.Metrics
	log     *slog.Logger
	weights WeightsProvider

	evaluator AlertEvaluator
}

// New builds a Processor. If weights is nil, the documented defaults are used.
func New(database *db.DB, m *metrics.Metrics, log *slog.Logger, weights WeightsProvider) *Processor {
	if weights == nil {
		weights = func(context.Context) scoring.Weights { return scoring.DefaultWeights() }
	}
	return &Processor{db: database, metrics: m, log: log, weights: weights}
}

// SetAlertEvaluator installs the alert evaluator hook.
func (p *Processor) SetAlertEvaluator(e AlertEvaluator) { p.evaluator = e }

// ProcessScan scores, records history, diffs, and evaluates alerts.
func (p *Processor) ProcessScan(ctx context.Context, asset models.Asset, scan *models.Scan, findings []models.Finding) error {
	// 1. Score.
	res := scoring.Score(findings, p.weights(ctx))
	score := res.Score
	scan.Score = &score
	scan.Grade = res.Grade

	// 2. Previous successful scan for delta + diff.
	var prev *models.Scan
	var prevFindings []models.Finding
	if ps, err := p.db.LatestSuccessfulScan(ctx, asset.ID, scan.ID); err == nil {
		prev = ps
		if pf, ferr := p.db.ListFindingsByScan(ctx, ps.ID); ferr == nil {
			prevFindings = pf
		}
	} else if !errors.Is(err, db.ErrNotFound) {
		p.log.Warn("loading previous scan for diff failed", "asset", asset.Value, "err", err)
	}

	var delta *int
	if prev != nil && prev.Score != nil {
		d := score - *prev.Score
		delta = &d
		scan.ScoreDelta = &d
	}

	// 3. Persist score/grade/delta.
	if err := p.db.UpdateScanScore(ctx, scan.ID, score, res.Grade, delta); err != nil {
		p.log.Error("persisting score failed", "asset", asset.Value, "err", err)
	}
	if err := p.db.InsertScorePoint(ctx, asset.ID, scan.StartedAt, score, res.Grade); err != nil {
		p.log.Warn("recording score history failed", "asset", asset.Value, "err", err)
	}
	p.metrics.AssetScore.WithLabelValues(asset.Value).Set(float64(score))

	// 4. Diff + persist.
	summary := diff.Compute(prev, scan, prevFindings, findings)
	summaryJSON, _ := json.Marshal(summary)
	dm := &models.Diff{
		AssetID:    asset.ID,
		FromScanID: summary.FromScanID,
		ToScanID:   scan.ID,
		Summary:    summaryJSON,
	}
	if err := p.db.CreateDiff(ctx, dm); err != nil {
		p.log.Warn("persisting diff failed", "asset", asset.Value, "err", err)
	}

	// 5. Alerts.
	if p.evaluator != nil {
		if err := p.evaluator.Evaluate(ctx, asset, scan, summary); err != nil {
			p.log.Error("alert evaluation failed", "asset", asset.Value, "err", err)
		}
	}
	return nil
}
