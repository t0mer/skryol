package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
)

func (s *Server) handleScanAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	asset, err := s.DB.GetAsset(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch asset")
		return
	}
	scan, err := s.Scanner.ScanAsset(r.Context(), *asset)
	if err != nil {
		s.Log.Error("scan asset", "asset", asset.Value, "err", err)
		writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (s *Server) handleScanAll(w http.ResponseWriter, r *http.Request) {
	res, err := s.Scanner.ScanAll(r.Context())
	if err != nil {
		s.Log.Error("fleet scan", "err", err)
		writeError(w, http.StatusInternalServerError, "fleet scan failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListAssetScans(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	scans, err := s.DB.ListScansByAsset(r.Context(), id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list scans")
		return
	}
	if scans == nil {
		scans = []models.Scan{}
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	scan, err := s.DB.GetScan(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch scan")
		return
	}
	findings, err := s.DB.ListFindingsByScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch findings")
		return
	}
	if findings == nil {
		findings = []models.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scan":     scan,
		"findings": findings,
	})
}
