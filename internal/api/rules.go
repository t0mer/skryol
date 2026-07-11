package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
)

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.DB.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list rules")
		return
	}
	if rules == nil {
		rules = []models.AlertRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

type ruleRequest struct {
	Scope           models.AlertScope `json:"scope"`
	AssetID         string            `json:"asset_id"`
	Condition       string            `json:"condition"`
	Params          json.RawMessage   `json:"params"`
	Enabled         *bool             `json:"enabled"`
	CooldownSeconds int               `json:"cooldown_seconds"`
	Severity        string            `json:"severity"`
	Label           string            `json:"label"`
	ChannelIDs      []string          `json:"channel_ids"`
}

func (req ruleRequest) toModel() models.AlertRule {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return models.AlertRule{
		Scope:           req.Scope,
		AssetID:         req.AssetID,
		Condition:       req.Condition,
		Params:          req.Params,
		Enabled:         enabled,
		CooldownSeconds: req.CooldownSeconds,
		Severity:        req.Severity,
		Label:           req.Label,
		ChannelIDs:      req.ChannelIDs,
	}
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	rule := req.toModel()
	if err := validateRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.CreateRule(r.Context(), &rule); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create rule")
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleGetRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := s.DB.GetRule(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch rule")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req ruleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	rule := req.toModel()
	rule.ID = id
	if err := validateRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.UpdateRule(r.Context(), &rule); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update rule")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.DB.DeleteRule(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete rule")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAlertEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.DB.ListAlertEvents(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list alert events")
		return
	}
	if events == nil {
		events = []models.AlertEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func validateRule(rule *models.AlertRule) error {
	if rule.Scope == "" {
		rule.Scope = models.ScopeGlobal
	}
	if rule.Scope != models.ScopeGlobal && rule.Scope != models.ScopeAsset {
		return errors.New("scope must be 'global' or 'asset'")
	}
	if rule.Scope == models.ScopeAsset && rule.AssetID == "" {
		return errors.New("asset-scoped rule requires asset_id")
	}
	if rule.Condition == "" {
		return errors.New("condition is required")
	}
	if rule.CooldownSeconds < 0 {
		return errors.New("cooldown_seconds must not be negative")
	}
	if rule.Severity == "" {
		rule.Severity = "info"
	}
	return nil
}
