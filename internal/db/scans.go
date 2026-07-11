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

// CreateScan inserts a scan and its findings atomically, assigning IDs.
func (d *DB) CreateScan(ctx context.Context, s *models.Scan, findings []models.Finding) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	now := nowUTC()
	s.CreatedAt = parseTime(now)

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin scan tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO scans (id, asset_id, started_at, finished_at, status, score, grade, highest_cvss, cve_count, critical_count, open_ports_count, score_delta, raw_json, error, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.AssetID, fmtTime(s.StartedAt), fmtTimePtr(s.FinishedAt), string(s.Status),
		intPtr(s.Score), s.Grade, s.HighestCVSS, s.CVECount, s.CriticalCount, s.OpenPortsCount,
		intPtr(s.ScoreDelta), rawOrEmpty(s.RawJSON), s.Error, now,
	); err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO findings (id, scan_id, asset_id, target_ip, kind, severity, cvss, key, detail_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare finding insert: %w", err)
	}
	defer stmt.Close()

	for i := range findings {
		f := &findings[i]
		f.ID = uuid.NewString()
		f.ScanID = s.ID
		f.AssetID = s.AssetID
		if _, err := stmt.ExecContext(ctx,
			f.ID, f.ScanID, f.AssetID, f.TargetIP, f.Kind, f.Severity, f.CVSS, f.Key, rawOrEmpty(f.Detail), now,
		); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan: %w", err)
	}
	return nil
}

// UpdateScanScore sets the computed score/grade/delta for a scan.
func (d *DB) UpdateScanScore(ctx context.Context, scanID string, score int, grade string, delta *int) error {
	_, err := d.ExecContext(ctx,
		`UPDATE scans SET score = ?, grade = ?, score_delta = ? WHERE id = ?`,
		score, grade, intPtr(delta), scanID)
	return err
}

// GetScan fetches a scan by ID (including raw JSON).
func (d *DB) GetScan(ctx context.Context, id string) (*models.Scan, error) {
	row := d.QueryRowContext(ctx, scanSelectCols+` WHERE id = ?`, id)
	s, err := scanScan(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ListScansByAsset returns scans for an asset, newest first, without raw JSON.
func (d *DB) ListScansByAsset(ctx context.Context, assetID string, limit int) ([]models.Scan, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.QueryContext(ctx, scanSelectColsNoRaw+` WHERE asset_id = ? ORDER BY started_at DESC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()
	var out []models.Scan
	for rows.Next() {
		s, err := scanScan(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// LatestSuccessfulScan returns the most recent ok/partial scan for an asset,
// optionally excluding a given scan ID. Returns ErrNotFound if none exists.
func (d *DB) LatestSuccessfulScan(ctx context.Context, assetID, excludeID string) (*models.Scan, error) {
	row := d.QueryRowContext(ctx,
		scanSelectCols+` WHERE asset_id = ? AND status IN ('ok','partial') AND id != ? ORDER BY started_at DESC LIMIT 1`,
		assetID, excludeID)
	s, err := scanScan(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ListFindingsByScan returns all findings for a scan.
func (d *DB) ListFindingsByScan(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, scan_id, asset_id, target_ip, kind, severity, cvss, key, detail_json, created_at
		 FROM findings WHERE scan_id = ? ORDER BY kind, key`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	var out []models.Finding
	for rows.Next() {
		var f models.Finding
		var detail string
		var created string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.AssetID, &f.TargetIP, &f.Kind, &f.Severity, &f.CVSS, &f.Key, &detail, &created); err != nil {
			return nil, err
		}
		f.Detail = []byte(detail)
		f.CreatedAt = parseTime(created)
		out = append(out, f)
	}
	return out, rows.Err()
}

// InsertScorePoint appends a point to an asset's score history.
func (d *DB) InsertScorePoint(ctx context.Context, assetID string, at time.Time, score int, grade string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO score_history (id, asset_id, at, score, grade) VALUES (?, ?, ?, ?, ?)`,
		uuid.NewString(), assetID, fmtTime(at), score, grade)
	return err
}

// ScoreHistory returns an asset's score history in chronological order.
func (d *DB) ScoreHistory(ctx context.Context, assetID string, limit int) ([]models.ScorePoint, error) {
	if limit <= 0 {
		limit = 365
	}
	rows, err := d.QueryContext(ctx,
		`SELECT at, score, grade FROM score_history WHERE asset_id = ? ORDER BY at ASC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ScorePoint
	for rows.Next() {
		var p models.ScorePoint
		var at string
		if err := rows.Scan(&at, &p.Score, &p.Grade); err != nil {
			return nil, err
		}
		p.At = parseTime(at)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PruneRawScans clears raw_json on scans older than the retention window,
// keeping the row and its summary metrics. A retentionDays <= 0 is a no-op.
func (d *DB) PruneRawScans(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	res, err := d.ExecContext(ctx,
		`UPDATE scans SET raw_json = '{}' WHERE started_at < ? AND raw_json != '{}'`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

const scanSelectCols = `SELECT id, asset_id, started_at, finished_at, status, score, grade, highest_cvss, cve_count, critical_count, open_ports_count, score_delta, raw_json, error, created_at FROM scans`
const scanSelectColsNoRaw = `SELECT id, asset_id, started_at, finished_at, status, score, grade, highest_cvss, cve_count, critical_count, open_ports_count, score_delta, '{}' AS raw_json, error, created_at FROM scans`

func scanScan(s scanner, withRaw bool) (models.Scan, error) {
	var sc models.Scan
	var finished, score, scoreDelta sql.NullInt64
	var finishedAt sql.NullString
	var status, grade, rawJSON, errStr, started, created string
	if err := s.Scan(&sc.ID, &sc.AssetID, &started, &finishedAt, &status, &score, &grade,
		&sc.HighestCVSS, &sc.CVECount, &sc.CriticalCount, &sc.OpenPortsCount, &scoreDelta,
		&rawJSON, &errStr, &created); err != nil {
		return sc, err
	}
	_ = finished
	sc.StartedAt = parseTime(started)
	if finishedAt.Valid && finishedAt.String != "" {
		t := parseTime(finishedAt.String)
		sc.FinishedAt = &t
	}
	sc.Status = models.ScanStatus(status)
	sc.Grade = grade
	if score.Valid {
		v := int(score.Int64)
		sc.Score = &v
	}
	if scoreDelta.Valid {
		v := int(scoreDelta.Int64)
		sc.ScoreDelta = &v
	}
	if withRaw {
		sc.RawJSON = []byte(rawJSON)
	}
	sc.Error = errStr
	sc.CreatedAt = parseTime(created)
	return sc, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return nowUTC()
	}
	return t.UTC().Format(time.RFC3339)
}

func fmtTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func intPtr(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func rawOrEmpty(r []byte) string {
	if len(r) == 0 {
		return "{}"
	}
	return string(r)
}
