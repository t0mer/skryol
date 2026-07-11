package models

import (
	"encoding/json"
	"time"
)

// ScanStatus is the outcome of an asset scan.
type ScanStatus string

const (
	ScanOK      ScanStatus = "ok"
	ScanPartial ScanStatus = "partial"
	ScanFailed  ScanStatus = "failed"
)

// Scan is one scan of an asset, storing the full raw Shodan report(s) plus
// derived summary metrics.
type Scan struct {
	ID             string          `json:"id"`
	AssetID        string          `json:"asset_id"`
	StartedAt      time.Time       `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
	Status         ScanStatus      `json:"status"`
	Score          *int            `json:"score,omitempty"`
	Grade          string          `json:"grade,omitempty"`
	HighestCVSS    float64         `json:"highest_cvss"`
	CVECount       int             `json:"cve_count"`
	CriticalCount  int             `json:"critical_count"`
	OpenPortsCount int             `json:"open_ports_count"`
	ScoreDelta     *int            `json:"score_delta,omitempty"`
	RawJSON        json.RawMessage `json:"raw_json,omitempty"`
	Error          string          `json:"error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Finding is a normalized, persisted observation belonging to a scan.
type Finding struct {
	ID        string          `json:"id"`
	ScanID    string          `json:"scan_id"`
	AssetID   string          `json:"asset_id"`
	TargetIP  string          `json:"target_ip"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	CVSS      float64         `json:"cvss"`
	Key       string          `json:"key"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// ScorePoint is a single point in an asset's score history time series.
type ScorePoint struct {
	At    time.Time `json:"at"`
	Score int       `json:"score"`
	Grade string    `json:"grade"`
}
