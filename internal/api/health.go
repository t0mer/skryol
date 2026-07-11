package api

import (
	"net/http"

	"github.com/t0mer/skryol/internal/version"
)

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if err := s.db.PingContext(r.Context()); err != nil {
		status = "degraded"
		writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: status, Version: version.Version})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{Status: status, Version: version.Version})
}
