package db

import (
	"context"
	"encoding/json"

	"github.com/t0mer/skryol/internal/scoring"
)

// storedSettings is the JSON persisted in the singleton settings row.
type storedSettings struct {
	ScoringWeights *scoring.Weights `json:"scoring_weights,omitempty"`
}

func (d *DB) loadStored(ctx context.Context) (storedSettings, error) {
	var raw string
	if err := d.QueryRowContext(ctx, `SELECT data_json FROM settings WHERE id = 1`).Scan(&raw); err != nil {
		return storedSettings{}, err
	}
	var s storedSettings
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s, nil
}

func (d *DB) saveStored(ctx context.Context, s storedSettings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx,
		`UPDATE settings SET data_json = ?, updated_at = ? WHERE id = 1`, string(b), nowUTC())
	return err
}

// GetScoringWeights returns the persisted weights, or documented defaults when
// none are stored.
func (d *DB) GetScoringWeights(ctx context.Context) scoring.Weights {
	s, err := d.loadStored(ctx)
	if err != nil || s.ScoringWeights == nil {
		return scoring.DefaultWeights()
	}
	return *s.ScoringWeights
}

// SaveScoringWeights persists a new weight table.
func (d *DB) SaveScoringWeights(ctx context.Context, w scoring.Weights) error {
	s, err := d.loadStored(ctx)
	if err != nil {
		s = storedSettings{}
	}
	s.ScoringWeights = &w
	return d.saveStored(ctx, s)
}
