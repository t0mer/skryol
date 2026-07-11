package models

import "time"

// AssetSummary is an asset joined with its latest scan metrics for the dashboard.
type AssetSummary struct {
	AssetID        string     `json:"asset_id"`
	Type           string     `json:"type"`
	Value          string     `json:"value"`
	Label          string     `json:"label"`
	Enabled        bool       `json:"enabled"`
	LastScanID     string     `json:"last_scan_id,omitempty"`
	Status         string     `json:"status,omitempty"`
	Score          *int       `json:"score,omitempty"`
	Grade          string     `json:"grade,omitempty"`
	HighestCVSS    float64    `json:"highest_cvss"`
	CVECount       int        `json:"cve_count"`
	CriticalCount  int        `json:"critical_count"`
	OpenPortsCount int        `json:"open_ports_count"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
}

// TrendPoint is one day's fleet-average score.
type TrendPoint struct {
	Date     string  `json:"date"`
	AvgScore float64 `json:"avg_score"`
}

// Dashboard is the fleet-wide dashboard payload.
type Dashboard struct {
	TotalAssets       int            `json:"total_assets"`
	EnabledAssets     int            `json:"enabled_assets"`
	ScannedAssets     int            `json:"scanned_assets"`
	AverageScore      float64        `json:"average_score"`
	CriticalIssues    int            `json:"critical_issues"`
	TotalCVEs         int            `json:"total_cves"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	Assets            []AssetSummary `json:"assets"`
	Trend             []TrendPoint   `json:"trend"`
}
