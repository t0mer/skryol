package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/diff"
	"github.com/t0mer/skryol/internal/models"
)

// handleAssetDiff compares two scans of an asset. Query params `from` and `to`
// are scan IDs; if omitted, the two most recent successful scans are used.
func (s *Server) handleAssetDiff(w http.ResponseWriter, r *http.Request) {
	assetID := chi.URLParam(r, "id")
	if _, err := s.DB.GetAsset(r.Context(), assetID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "asset not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch asset")
		return
	}

	fromID := r.URL.Query().Get("from")
	toID := r.URL.Query().Get("to")

	// Default to the two most recent scans when unspecified.
	if toID == "" || fromID == "" {
		recent, err := s.DB.ListScansByAsset(r.Context(), assetID, 2)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list scans")
			return
		}
		if len(recent) == 0 {
			writeError(w, http.StatusNotFound, "no scans to compare")
			return
		}
		if toID == "" {
			toID = recent[0].ID
		}
		if fromID == "" && len(recent) > 1 {
			fromID = recent[1].ID
		}
	}

	to, err := s.DB.GetScan(r.Context(), toID)
	if err != nil {
		writeError(w, http.StatusNotFound, "target scan not found")
		return
	}
	toFindings, _ := s.DB.ListFindingsByScan(r.Context(), toID)

	var from *models.Scan
	var fromFindings []models.Finding
	if fromID != "" {
		from, err = s.DB.GetScan(r.Context(), fromID)
		if err != nil {
			writeError(w, http.StatusNotFound, "source scan not found")
			return
		}
		fromFindings, _ = s.DB.ListFindingsByScan(r.Context(), fromID)
	}

	summary := diff.Compute(from, to, fromFindings, toFindings)
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleScoreHistory(w http.ResponseWriter, r *http.Request) {
	assetID := chi.URLParam(r, "id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	history, err := s.DB.ScoreHistory(r.Context(), assetID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch score history")
		return
	}
	if history == nil {
		history = []models.ScorePoint{}
	}
	writeJSON(w, http.StatusOK, history)
}
