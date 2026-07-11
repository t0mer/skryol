package models

import "time"

// ShodanKey is a stored Shodan API key. The secret itself is never serialized;
// only its live health/credit state is exposed via the API.
type ShodanKey struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	Enabled       bool       `json:"enabled"`
	RatePerSecond float64    `json:"rate_per_second"`
	QueryCredits  int        `json:"query_credits"`
	ScanCredits   int        `json:"scan_credits"`
	Plan          string     `json:"plan"`
	Health        string     `json:"health"`
	LastError     string     `json:"last_error,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	// Ciphertext holds the encrypted secret; populated only inside the store.
	Ciphertext string `json:"-"`
}
