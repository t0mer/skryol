package models

import (
	"encoding/json"
	"time"
)

// Diff records a structured comparison between two scans of an asset.
type Diff struct {
	ID         string          `json:"id"`
	AssetID    string          `json:"asset_id"`
	FromScanID string          `json:"from_scan_id"`
	ToScanID   string          `json:"to_scan_id"`
	Summary    json.RawMessage `json:"summary"`
	CreatedAt  time.Time       `json:"created_at"`
}

// FindingChange describes a finding that appeared or disappeared between scans.
type FindingChange struct {
	Kind     string          `json:"kind"`
	Key      string          `json:"key"`
	TargetIP string          `json:"target_ip"`
	Severity string          `json:"severity"`
	CVSS     float64         `json:"cvss"`
	Detail   json.RawMessage `json:"detail,omitempty"`
}

// CVSSChange records a CVSS score change for a finding present in both scans.
type CVSSChange struct {
	Kind     string  `json:"kind"`
	Key      string  `json:"key"`
	TargetIP string  `json:"target_ip"`
	FromCVSS float64 `json:"from_cvss"`
	ToCVSS   float64 `json:"to_cvss"`
}

// DiffSummary is the serialized structured diff between two scans.
type DiffSummary struct {
	FromScanID  string          `json:"from_scan_id"`
	ToScanID    string          `json:"to_scan_id"`
	Added       []FindingChange `json:"added"`
	Removed     []FindingChange `json:"removed"`
	CVSSChanged []CVSSChange    `json:"cvss_changed"`

	ScoreFrom  *int   `json:"score_from,omitempty"`
	ScoreTo    *int   `json:"score_to,omitempty"`
	ScoreDelta int    `json:"score_delta"`
	GradeFrom  string `json:"grade_from,omitempty"`
	GradeTo    string `json:"grade_to,omitempty"`

	WasOnline   bool `json:"was_online"`
	Online      bool `json:"online"`
	WentOffline bool `json:"went_offline"`
	CameOnline  bool `json:"came_online"`
}
