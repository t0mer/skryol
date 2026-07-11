package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// User is a login account (single-admin model in practice).
type User struct {
	ID           string
	Username     string
	PasswordHash string
}

// APIToken is a hashed bearer token.
type APIToken struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// GetUserByUsername fetches a user, or ErrNotFound.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := d.QueryRowContext(ctx, `SELECT id, username, password_hash FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// CountUsers returns the number of user accounts.
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

// UpsertUser creates or updates a user's password hash by username.
func (d *DB) UpsertUser(ctx context.Context, username, passwordHash string) error {
	now := nowUTC()
	_, err := d.ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at`,
		uuid.NewString(), username, passwordHash, now, now)
	if err != nil {
		return fmt.Errorf("upserting user: %w", err)
	}
	return nil
}

// CreateToken stores a hashed token and returns its record.
func (d *DB) CreateToken(ctx context.Context, label, tokenHash string) (*APIToken, error) {
	id := uuid.NewString()
	now := nowUTC()
	if _, err := d.ExecContext(ctx,
		`INSERT INTO tokens (id, label, token_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, label, tokenHash, now); err != nil {
		return nil, fmt.Errorf("creating token: %w", err)
	}
	return &APIToken{ID: id, Label: label, CreatedAt: parseTime(now)}, nil
}

// TokenExists reports whether a token hash is present, and touches last_used_at.
func (d *DB) TokenExists(ctx context.Context, tokenHash string) (bool, error) {
	var id string
	err := d.QueryRowContext(ctx, `SELECT id FROM tokens WHERE token_hash = ?`, tokenHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, _ = d.ExecContext(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`, nowUTC(), id)
	return true, nil
}

// ListTokens returns token metadata (never the hash).
func (d *DB) ListTokens(ctx context.Context) ([]APIToken, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, label, created_at, last_used_at FROM tokens ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		var created string
		var lastUsed sql.NullString
		if err := rows.Scan(&t.ID, &t.Label, &created, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt = parseTime(created)
		if lastUsed.Valid && lastUsed.String != "" {
			tt := parseTime(lastUsed.String)
			t.LastUsedAt = &tt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteToken revokes a token by ID.
func (d *DB) DeleteToken(ctx context.Context, id string) error {
	res, err := d.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
