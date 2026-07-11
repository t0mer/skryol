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

// CreateRule inserts an alert rule and its channel mappings atomically.
func (d *DB) CreateRule(ctx context.Context, r *models.AlertRule) error {
	r.ID = uuid.NewString()
	now := nowUTC()
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO alert_rules (id, scope, asset_id, condition, params_json, enabled, cooldown_seconds, severity, label, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, string(r.Scope), nullIfEmpty(r.AssetID), r.Condition, rawOrEmpty(r.Params),
		boolToInt(r.Enabled), r.CooldownSeconds, r.Severity, r.Label, now, now); err != nil {
		return fmt.Errorf("inserting rule: %w", err)
	}
	if err := replaceRuleChannelsTx(ctx, tx, r.ID, r.ChannelIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.CreatedAt = parseTime(now)
	r.UpdatedAt = r.CreatedAt
	return nil
}

// UpdateRule replaces a rule and its channel mappings.
func (d *DB) UpdateRule(ctx context.Context, r *models.AlertRule) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE alert_rules SET scope = ?, asset_id = ?, condition = ?, params_json = ?, enabled = ?, cooldown_seconds = ?, severity = ?, label = ?, updated_at = ?
		 WHERE id = ?`,
		string(r.Scope), nullIfEmpty(r.AssetID), r.Condition, rawOrEmpty(r.Params),
		boolToInt(r.Enabled), r.CooldownSeconds, r.Severity, r.Label, nowUTC(), r.ID)
	if err != nil {
		return fmt.Errorf("updating rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := replaceRuleChannelsTx(ctx, tx, r.ID, r.ChannelIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceRuleChannelsTx(ctx context.Context, tx *sql.Tx, ruleID string, channelIDs []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM alert_channel_map WHERE rule_id = ?`, ruleID); err != nil {
		return fmt.Errorf("clearing channel map: %w", err)
	}
	for _, cid := range channelIDs {
		if cid == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO alert_channel_map (rule_id, channel_id) VALUES (?, ?)`, ruleID, cid); err != nil {
			return fmt.Errorf("mapping channel: %w", err)
		}
	}
	return nil
}

// DeleteRule removes a rule (cascading its channel map).
func (d *DB) DeleteRule(ctx context.Context, id string) error {
	res, err := d.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetRule fetches a rule with its channel IDs.
func (d *DB) GetRule(ctx context.Context, id string) (*models.AlertRule, error) {
	row := d.QueryRowContext(ctx, ruleSelectCols+` WHERE id = ?`, id)
	r, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.ChannelIDs, err = d.ruleChannels(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRules returns all rules with their channel IDs.
func (d *DB) ListRules(ctx context.Context) ([]models.AlertRule, error) {
	rows, err := d.QueryContext(ctx, ruleSelectCols+` ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing rules: %w", err)
	}
	defer rows.Close()
	var out []models.AlertRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].ChannelIDs, err = d.ruleChannels(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RulesForAsset returns enabled rules applicable to an asset (global + scoped).
func (d *DB) RulesForAsset(ctx context.Context, assetID string) ([]models.AlertRule, error) {
	rows, err := d.QueryContext(ctx,
		ruleSelectCols+` WHERE enabled = 1 AND (scope = 'global' OR (scope = 'asset' AND asset_id = ?)) ORDER BY created_at ASC`,
		assetID)
	if err != nil {
		return nil, fmt.Errorf("listing rules for asset: %w", err)
	}
	defer rows.Close()
	var out []models.AlertRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].ChannelIDs, err = d.ruleChannels(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *DB) ruleChannels(ctx context.Context, ruleID string) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT channel_id FROM alert_channel_map WHERE rule_id = ?`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RecordAlertEvent inserts an alert firing into the audit log.
func (d *DB) RecordAlertEvent(ctx context.Context, e *models.AlertEvent) error {
	e.ID = uuid.NewString()
	_, err := d.ExecContext(ctx,
		`INSERT INTO alert_events (id, rule_id, asset_id, condition, fired_at, dedup_key, payload_json, delivered_json, severity)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, nullIfEmpty(e.RuleID), nullIfEmpty(e.AssetID), e.Condition,
		fmtTime(e.FiredAt), e.DedupKey, rawOrEmpty(e.Payload), rawOrEmpty(e.Delivered), e.Severity)
	return err
}

// LastAlertEvent returns the most recent event time for a dedup key, or zero.
func (d *DB) LastAlertEvent(ctx context.Context, dedupKey string) (time.Time, error) {
	row := d.QueryRowContext(ctx,
		`SELECT fired_at FROM alert_events WHERE dedup_key = ? ORDER BY fired_at DESC LIMIT 1`, dedupKey)
	var fired string
	if err := row.Scan(&fired); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return parseTime(fired), nil
}

// ListAlertEvents returns recent alert events, newest first.
func (d *DB) ListAlertEvents(ctx context.Context, limit int) ([]models.AlertEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.QueryContext(ctx,
		`SELECT id, rule_id, asset_id, condition, fired_at, dedup_key, payload_json, delivered_json, severity
		 FROM alert_events ORDER BY fired_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AlertEvent
	for rows.Next() {
		var e models.AlertEvent
		var ruleID, assetID sql.NullString
		var fired, payload, delivered string
		if err := rows.Scan(&e.ID, &ruleID, &assetID, &e.Condition, &fired, &e.DedupKey, &payload, &delivered, &e.Severity); err != nil {
			return nil, err
		}
		e.RuleID = ruleID.String
		e.AssetID = assetID.String
		e.FiredAt = parseTime(fired)
		e.Payload = []byte(payload)
		e.Delivered = []byte(delivered)
		out = append(out, e)
	}
	return out, rows.Err()
}

const ruleSelectCols = `SELECT id, scope, asset_id, condition, params_json, enabled, cooldown_seconds, severity, label, created_at, updated_at FROM alert_rules`

func scanRule(s scanner) (models.AlertRule, error) {
	var r models.AlertRule
	var scope, condition, params, severity, label, created, updated string
	var assetID sql.NullString
	var enabled, cooldown int
	if err := s.Scan(&r.ID, &scope, &assetID, &condition, &params, &enabled, &cooldown, &severity, &label, &created, &updated); err != nil {
		return r, err
	}
	r.Scope = models.AlertScope(scope)
	r.AssetID = assetID.String
	r.Condition = condition
	r.Params = []byte(params)
	r.Enabled = enabled != 0
	r.CooldownSeconds = cooldown
	r.Severity = severity
	r.Label = label
	r.CreatedAt = parseTime(created)
	r.UpdatedAt = parseTime(updated)
	return r, nil
}
