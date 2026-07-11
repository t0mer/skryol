package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/t0mer/skryol/internal/models"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// CreateAsset inserts a new asset, assigning an ID and timestamps. The asset's
// Value must already be normalized/validated by the caller.
func (d *DB) CreateAsset(ctx context.Context, a *models.Asset) error {
	a.ID = uuid.NewString()
	now := nowUTC()
	_, err := d.ExecContext(ctx,
		`INSERT INTO assets (id, type, value, label, notes, enabled, rescan, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, string(a.Type), a.Value, a.Label, a.Notes, boolToInt(a.Enabled), boolToInt(a.Rescan), now, now,
	)
	if err != nil {
		return fmt.Errorf("inserting asset: %w", err)
	}
	a.CreatedAt = parseTime(now)
	a.UpdatedAt = a.CreatedAt
	return nil
}

// ListAssets returns all assets ordered by creation time.
func (d *DB) ListAssets(ctx context.Context) ([]models.Asset, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, type, value, label, notes, enabled, rescan, created_at, updated_at
		 FROM assets ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing assets: %w", err)
	}
	defer rows.Close()

	var out []models.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListEnabledAssets returns only the enabled assets.
func (d *DB) ListEnabledAssets(ctx context.Context) ([]models.Asset, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, type, value, label, notes, enabled, rescan, created_at, updated_at
		 FROM assets WHERE enabled = 1 ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing enabled assets: %w", err)
	}
	defer rows.Close()
	var out []models.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAsset fetches a single asset by ID.
func (d *DB) GetAsset(ctx context.Context, id string) (*models.Asset, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, type, value, label, notes, enabled, rescan, created_at, updated_at
		 FROM assets WHERE id = ?`, id)
	a, err := scanAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateAsset persists mutable fields of an asset.
func (d *DB) UpdateAsset(ctx context.Context, a *models.Asset) error {
	now := nowUTC()
	res, err := d.ExecContext(ctx,
		`UPDATE assets SET type = ?, value = ?, label = ?, notes = ?, enabled = ?, rescan = ?, updated_at = ?
		 WHERE id = ?`,
		string(a.Type), a.Value, a.Label, a.Notes, boolToInt(a.Enabled), boolToInt(a.Rescan), now, a.ID,
	)
	if err != nil {
		return fmt.Errorf("updating asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	a.UpdatedAt = parseTime(now)
	return nil
}

// DeleteAsset removes an asset (cascading to its scans/findings).
func (d *DB) DeleteAsset(ctx context.Context, id string) error {
	res, err := d.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAsset(s scanner) (models.Asset, error) {
	var a models.Asset
	var typ string
	var enabled, rescan int
	var created, updated string
	if err := s.Scan(&a.ID, &typ, &a.Value, &a.Label, &a.Notes, &enabled, &rescan, &created, &updated); err != nil {
		return a, err
	}
	a.Type = models.AssetType(typ)
	a.Enabled = enabled != 0
	a.Rescan = rescan != 0
	a.CreatedAt = parseTime(created)
	a.UpdatedAt = parseTime(updated)
	return a, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
