package api

import (
	"net/http"

	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/scoring"
	"github.com/t0mer/skryol/internal/settings"
	"github.com/t0mer/skryol/internal/version"
)

// settingsResponse is the full settings view: editable values (keyed by
// canonical dotted key), precedence locks, pending-restart changes, scoring
// weights, and read-only instance metadata.
type settingsResponse struct {
	Values          map[string]any                    `json:"values"`
	Locked          map[string]string                 `json:"locked"`
	PendingRestart  map[string]settings.PendingChange `json:"pending_restart"`
	ScoringWeights  scoring.Weights                   `json:"scoring_weights"`
	Version         string                            `json:"version"`
	EncryptionSet   bool                              `json:"encryption_configured"`
	AuthPasswordSet bool                              `json:"auth_password_set"`
	ConfigFile      string                            `json:"config_file"`
	RestartPending  bool                              `json:"restart_required"`
	Editable        []editableMeta                    `json:"editable"`
}

// editableMeta tells the UI how each key behaves (hot vs restart) so it can
// render the right badges without hard-coding the classification.
type editableMeta struct {
	Key   string `json:"key"`
	Apply string `json:"apply"` // "hot" | "restart"
}

// settingsUpdate is the mutable settings payload. Any subset may be present.
type settingsUpdate struct {
	Values         map[string]any   `json:"values"`
	Password       *string          `json:"password"`
	ScoringWeights *scoring.Weights `json:"scoring_weights"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.writeSettings(w, r)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ScoringWeights != nil {
		if err := s.DB.SaveScoringWeights(r.Context(), *req.ScoringWeights); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save scoring weights")
			return
		}
	}

	if (len(req.Values) > 0 || (req.Password != nil && *req.Password != "")) && s.Settings != nil {
		if err := s.Settings.Update(r.Context(), req.Values, req.Password); err != nil {
			// Validation and precedence-lock errors are the caller's fault.
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	s.writeSettings(w, r)
}

// writeSettings assembles and returns the full settings view.
func (s *Server) writeSettings(w http.ResponseWriter, r *http.Request) {
	resp := settingsResponse{
		Values:         map[string]any{},
		Locked:         map[string]string{},
		PendingRestart: map[string]settings.PendingChange{},
		ScoringWeights: s.DB.GetScoringWeights(r.Context()),
		Version:        version.Version,
		EncryptionSet:  s.Cipher.Enabled(),
		ConfigFile:     "",
	}

	if s.Settings != nil {
		resp.Values = s.Settings.Values()
		resp.Locked = s.Settings.Locked()
		resp.PendingRestart = s.Settings.Pending()
		resp.ConfigFile = s.Settings.FilePath()
		resp.RestartPending = len(resp.PendingRestart) > 0
	}

	if s.Auth != nil {
		if has, err := s.Auth.HasUser(r.Context()); err == nil {
			resp.AuthPasswordSet = has
		}
	}

	resp.Editable = make([]editableMeta, 0, len(config.EditableKeys))
	for _, ek := range config.EditableKeys {
		apply := "hot"
		if ek.Apply == config.ApplyRestart {
			apply = "restart"
		}
		resp.Editable = append(resp.Editable, editableMeta{Key: ek.Key, Apply: apply})
	}

	writeJSON(w, http.StatusOK, resp)
}
