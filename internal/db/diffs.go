package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/t0mer/skryol/internal/models"
)

// CreateDiff stores a computed diff summary.
func (d *DB) CreateDiff(ctx context.Context, diff *models.Diff) error {
	diff.ID = uuid.NewString()
	now := nowUTC()
	diff.CreatedAt = parseTime(now)
	_, err := d.ExecContext(ctx,
		`INSERT INTO diffs (id, asset_id, from_scan_id, to_scan_id, summary_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		diff.ID, diff.AssetID, nullIfEmpty(diff.FromScanID), diff.ToScanID, rawOrEmpty(diff.Summary), now)
	if err != nil {
		return fmt.Errorf("inserting diff: %w", err)
	}
	return nil
}

// LatestDiff returns the most recent diff for an asset.
func (d *DB) LatestDiff(ctx context.Context, assetID string) (*models.Diff, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, asset_id, from_scan_id, to_scan_id, summary_json, created_at
		 FROM diffs WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1`, assetID)
	diff, err := scanDiff(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &diff, nil
}

func scanDiff(s scanner) (models.Diff, error) {
	var diff models.Diff
	var from sql.NullString
	var summary, created string
	if err := s.Scan(&diff.ID, &diff.AssetID, &from, &diff.ToScanID, &summary, &created); err != nil {
		return diff, err
	}
	if from.Valid {
		diff.FromScanID = from.String
	}
	diff.Summary = []byte(summary)
	diff.CreatedAt = parseTime(created)
	return diff, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
