package api

import (
	"net/http"

	"github.com/t0mer/skryol/internal/scoring"
	"github.com/t0mer/skryol/internal/version"
)

// settingsResponse exposes tunable and read-only runtime settings.
type settingsResponse struct {
	ScoringWeights       scoring.Weights `json:"scoring_weights"`
	Schedule             string          `json:"schedule"`
	MaxHostsPerAsset     int             `json:"max_hosts_per_asset"`
	MaxConcurrency       int             `json:"max_concurrency"`
	RetentionDays        int             `json:"retention_days"`
	AuthEnabled          bool            `json:"auth_enabled"`
	EncryptionConfigured bool            `json:"encryption_configured"`
	Version              string          `json:"version"`
}

// settingsUpdate is the mutable settings payload.
type settingsUpdate struct {
	ScoringWeights *scoring.Weights `json:"scoring_weights"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, settingsResponse{
		ScoringWeights:       s.DB.GetScoringWeights(r.Context()),
		Schedule:             s.Config.Scanner.Schedule,
		MaxHostsPerAsset:     s.Config.Scanner.MaxHostsPerAsset,
		MaxConcurrency:       s.Config.Scanner.MaxConcurrency,
		RetentionDays:        s.Config.Scanner.RetentionDays,
		AuthEnabled:          s.Config.Auth.Enabled,
		EncryptionConfigured: s.Cipher.Enabled(),
		Version:              version.Version,
	})
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.ScoringWeights != nil {
		if err := s.DB.SaveScoringWeights(r.Context(), *req.ScoringWeights); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save weights")
			return
		}
	}
	s.handleGetSettings(w, r)
}
