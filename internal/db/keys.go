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

// CreateShodanKey inserts a new key row. Ciphertext must already be encrypted.
func (d *DB) CreateShodanKey(ctx context.Context, k *models.ShodanKey) error {
	k.ID = uuid.NewString()
	now := nowUTC()
	if k.Health == "" {
		k.Health = "unknown"
	}
	if k.RatePerSecond <= 0 {
		k.RatePerSecond = 1.0
	}
	_, err := d.ExecContext(ctx,
		`INSERT INTO shodan_keys (id, label, ciphertext, enabled, rate_per_second, query_credits, scan_credits, plan, health, last_error, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Label, k.Ciphertext, boolToInt(k.Enabled), k.RatePerSecond, k.QueryCredits, k.ScanCredits, k.Plan, k.Health, k.LastError, now, now,
	)
	if err != nil {
		return fmt.Errorf("inserting shodan key: %w", err)
	}
	k.CreatedAt = parseTime(now)
	k.UpdatedAt = k.CreatedAt
	return nil
}

// ListShodanKeys returns all keys including ciphertext (for the pool loader).
func (d *DB) ListShodanKeys(ctx context.Context) ([]models.ShodanKey, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, label, ciphertext, enabled, rate_per_second, query_credits, scan_credits, plan, health, last_error, last_used_at, last_checked_at, created_at, updated_at
		 FROM shodan_keys ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing shodan keys: %w", err)
	}
	defer rows.Close()
	var out []models.ShodanKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetShodanKey fetches a key by ID (including ciphertext).
func (d *DB) GetShodanKey(ctx context.Context, id string) (*models.ShodanKey, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, label, ciphertext, enabled, rate_per_second, query_credits, scan_credits, plan, health, last_error, last_used_at, last_checked_at, created_at, updated_at
		 FROM shodan_keys WHERE id = ?`, id)
	k, err := scanKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// UpdateShodanKeyMeta updates label/enabled/rate (not the secret).
func (d *DB) UpdateShodanKeyMeta(ctx context.Context, id, label string, enabled bool, rate float64) error {
	res, err := d.ExecContext(ctx,
		`UPDATE shodan_keys SET label = ?, enabled = ?, rate_per_second = ?, updated_at = ? WHERE id = ?`,
		label, boolToInt(enabled), rate, nowUTC(), id)
	if err != nil {
		return fmt.Errorf("updating shodan key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateShodanKeySecret replaces the encrypted secret.
func (d *DB) UpdateShodanKeySecret(ctx context.Context, id, ciphertext string) error {
	res, err := d.ExecContext(ctx,
		`UPDATE shodan_keys SET ciphertext = ?, health = 'unknown', last_error = '', updated_at = ? WHERE id = ?`,
		ciphertext, nowUTC(), id)
	if err != nil {
		return fmt.Errorf("updating shodan key secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateShodanKeyState persists live credit/health state from the pool.
func (d *DB) UpdateShodanKeyState(ctx context.Context, id string, queryCredits, scanCredits int, plan, health, lastErr string, lastUsed, lastChecked *time.Time) error {
	_, err := d.ExecContext(ctx,
		`UPDATE shodan_keys SET query_credits = ?, scan_credits = ?, plan = ?, health = ?, last_error = ?, last_used_at = ?, last_checked_at = ?, updated_at = ?
		 WHERE id = ?`,
		queryCredits, scanCredits, plan, health, lastErr, timePtr(lastUsed), timePtr(lastChecked), nowUTC(), id)
	if err != nil {
		return fmt.Errorf("updating shodan key state: %w", err)
	}
	return nil
}

// DeleteShodanKey removes a key.
func (d *DB) DeleteShodanKey(ctx context.Context, id string) error {
	res, err := d.ExecContext(ctx, `DELETE FROM shodan_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting shodan key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanKey(s scanner) (models.ShodanKey, error) {
	var k models.ShodanKey
	var enabled int
	var lastUsed, lastChecked sql.NullString
	var created, updated string
	if err := s.Scan(&k.ID, &k.Label, &k.Ciphertext, &enabled, &k.RatePerSecond, &k.QueryCredits, &k.ScanCredits, &k.Plan, &k.Health, &k.LastError, &lastUsed, &lastChecked, &created, &updated); err != nil {
		return k, err
	}
	k.Enabled = enabled != 0
	if lastUsed.Valid && lastUsed.String != "" {
		t := parseTime(lastUsed.String)
		k.LastUsedAt = &t
	}
	if lastChecked.Valid && lastChecked.String != "" {
		t := parseTime(lastChecked.String)
		k.LastCheckedAt = &t
	}
	k.CreatedAt = parseTime(created)
	k.UpdatedAt = parseTime(updated)
	return k, nil
}

func timePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
