package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/t0mer/skryol/internal/models"
)

// AssetSummaries returns every asset joined with its most recent scan's derived
// metrics, for the dashboard ranking table.
func (d *DB) AssetSummaries(ctx context.Context) ([]models.AssetSummary, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT a.id, a.type, a.value, a.label, a.enabled,
		       s.id, s.status, s.score, s.grade, s.highest_cvss, s.cve_count, s.critical_count, s.open_ports_count, s.started_at
		FROM assets a
		LEFT JOIN scans s ON s.id = (
			SELECT id FROM scans WHERE asset_id = a.id ORDER BY started_at DESC LIMIT 1
		)
		ORDER BY a.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.AssetSummary
	for rows.Next() {
		var s models.AssetSummary
		var typ, value, label string
		var enabled int
		var scanID, status, grade, started sql.NullString
		var score, cve, critical, ports sql.NullInt64
		var highest sql.NullFloat64
		if err := rows.Scan(&s.AssetID, &typ, &value, &label, &enabled,
			&scanID, &status, &score, &grade, &highest, &cve, &critical, &ports, &started); err != nil {
			return nil, err
		}
		s.Type = typ
		s.Value = value
		s.Label = label
		s.Enabled = enabled != 0
		if scanID.Valid {
			s.LastScanID = scanID.String
			s.Status = status.String
			s.Grade = grade.String
			if score.Valid {
				v := int(score.Int64)
				s.Score = &v
			}
			s.HighestCVSS = highest.Float64
			s.CVECount = int(cve.Int64)
			s.CriticalCount = int(critical.Int64)
			s.OpenPortsCount = int(ports.Int64)
			if started.Valid {
				t := parseTime(started.String)
				s.LastScannedAt = &t
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// FleetScoreTrend returns the average score per day across all assets, over the
// last `days` days.
func (d *DB) FleetScoreTrend(ctx context.Context, days int) ([]models.TrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	rows, err := d.QueryContext(ctx, `
		SELECT substr(at, 1, 10) AS day, AVG(score) AS avg_score
		FROM score_history
		WHERE at >= ?
		GROUP BY day ORDER BY day ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.TrendPoint
	for rows.Next() {
		var p models.TrendPoint
		if err := rows.Scan(&p.Date, &p.AvgScore); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
