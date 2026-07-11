package api

import (
	"net/http"

	"github.com/t0mer/skryol/internal/backup"
)

type exportRequest struct {
	Mode       backup.SecretMode `json:"mode"`
	Passphrase string            `json:"passphrase"`
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var req exportRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	bundle, err := s.Backup.Export(r.Context(), backup.ExportOptions{Mode: req.Mode, Passphrase: req.Passphrase})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="skryol-export.json"`)
	writeJSON(w, http.StatusOK, bundle)
}

type importRequest struct {
	Bundle     backup.Bundle `json:"bundle"`
	Passphrase string        `json:"passphrase"`
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	res, err := s.Backup.Import(r.Context(), &req.Bundle, backup.ImportOptions{Passphrase: req.Passphrase})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
