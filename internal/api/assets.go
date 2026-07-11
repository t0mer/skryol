package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
)

// assetRequest is the create/update payload for an asset.
type assetRequest struct {
	Type    models.AssetType `json:"type"`
	Value   string           `json:"value"`
	Label   string           `json:"label"`
	Notes   string           `json:"notes"`
	Enabled *bool            `json:"enabled"`
	Rescan  *bool            `json:"rescan"`
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.DB.ListAssets(r.Context())
	if err != nil {
		s.Log.Error("list assets", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list assets")
		return
	}
	if assets == nil {
		assets = []models.Asset{}
	}
	writeJSON(w, http.StatusOK, assets)
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var req assetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	a := &models.Asset{
		Type:    req.Type,
		Value:   req.Value,
		Label:   req.Label,
		Notes:   req.Notes,
		Enabled: true,
	}
	if req.Enabled != nil {
		a.Enabled = *req.Enabled
	}
	if req.Rescan != nil {
		a.Rescan = *req.Rescan
	}
	if err := a.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.CreateAsset(r.Context(), a); err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "an asset with this type and value already exists")
			return
		}
		s.Log.Error("create asset", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create asset")
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, err := s.DB.GetAsset(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch asset")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DB.GetAsset(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch asset")
		return
	}

	var req assetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Type != "" {
		existing.Type = req.Type
	}
	if req.Value != "" {
		existing.Value = req.Value
	}
	existing.Label = req.Label
	existing.Notes = req.Notes
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Rescan != nil {
		existing.Rescan = *req.Rescan
	}
	if err := existing.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.UpdateAsset(r.Context(), existing); err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "an asset with this type and value already exists")
			return
		}
		s.Log.Error("update asset", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.DB.DeleteAsset(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "asset not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete asset")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
