package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/t0mer/skryol/internal/models"
)

// CreateChannel inserts a channel with an already-encrypted config ciphertext.
func (d *DB) CreateChannel(ctx context.Context, c *models.Channel) error {
	c.ID = uuid.NewString()
	now := nowUTC()
	_, err := d.ExecContext(ctx,
		`INSERT INTO channels (id, type, label, ciphertext, enabled, needs_credentials, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, string(c.Type), c.Label, c.Ciphertext, boolToInt(c.Enabled), boolToInt(c.NeedsCredentials), now, now)
	if err != nil {
		return fmt.Errorf("inserting channel: %w", err)
	}
	c.CreatedAt = parseTime(now)
	c.UpdatedAt = c.CreatedAt
	return nil
}

// ListChannels returns all channels including ciphertext.
func (d *DB) ListChannels(ctx context.Context) ([]models.Channel, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, type, label, ciphertext, enabled, needs_credentials, created_at, updated_at
		 FROM channels ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing channels: %w", err)
	}
	defer rows.Close()
	var out []models.Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetChannel fetches a channel by ID.
func (d *DB) GetChannel(ctx context.Context, id string) (*models.Channel, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, type, label, ciphertext, enabled, needs_credentials, created_at, updated_at
		 FROM channels WHERE id = ?`, id)
	c, err := scanChannel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateChannel replaces label/enabled/ciphertext of a channel.
func (d *DB) UpdateChannel(ctx context.Context, c *models.Channel) error {
	res, err := d.ExecContext(ctx,
		`UPDATE channels SET type = ?, label = ?, ciphertext = ?, enabled = ?, needs_credentials = ?, updated_at = ?
		 WHERE id = ?`,
		string(c.Type), c.Label, c.Ciphertext, boolToInt(c.Enabled), boolToInt(c.NeedsCredentials), nowUTC(), c.ID)
	if err != nil {
		return fmt.Errorf("updating channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteChannel removes a channel.
func (d *DB) DeleteChannel(ctx context.Context, id string) error {
	res, err := d.ExecContext(ctx, `DELETE FROM channels WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanChannel(s scanner) (models.Channel, error) {
	var c models.Channel
	var typ string
	var enabled, needs int
	var created, updated string
	if err := s.Scan(&c.ID, &typ, &c.Label, &c.Ciphertext, &enabled, &needs, &created, &updated); err != nil {
		return c, err
	}
	c.Type = models.ChannelType(typ)
	c.Enabled = enabled != 0
	c.NeedsCredentials = needs != 0
	c.CreatedAt = parseTime(created)
	c.UpdatedAt = parseTime(updated)
	return c, nil
}
