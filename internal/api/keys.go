package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
)

// keyCreateRequest adds a new Shodan key. The secret is write-only.
type keyCreateRequest struct {
	Label         string  `json:"label"`
	Secret        string  `json:"secret"`
	Enabled       *bool   `json:"enabled"`
	RatePerSecond float64 `json:"rate_per_second"`
}

// keyUpdateRequest updates metadata and optionally rotates the secret.
type keyUpdateRequest struct {
	Label         string  `json:"label"`
	Secret        string  `json:"secret"`
	Enabled       *bool   `json:"enabled"`
	RatePerSecond float64 `json:"rate_per_second"`
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	list, err := s.Keys.List(r.Context())
	if err != nil {
		s.Log.Error("list keys", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}
	if list == nil {
		list = []models.ShodanKey{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req keyCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Secret) == "" {
		writeError(w, http.StatusBadRequest, "secret is required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	k, err := s.Keys.Create(r.Context(), req.Label, req.Secret, enabled, req.RatePerSecond)
	if err != nil {
		if errors.Is(err, crypto.ErrNoKey) {
			writeError(w, http.StatusPreconditionFailed, "encryption key not configured; set SKRYOL_CRYPTO_ENCRYPTION_KEY")
			return
		}
		s.Log.Error("create key", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create key")
		return
	}
	writeJSON(w, http.StatusCreated, k)
}

func (s *Server) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.DB.GetShodanKey(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch key")
		return
	}
	var req keyUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if err := s.Keys.UpdateMeta(r.Context(), id, req.Label, enabled, req.RatePerSecond); err != nil {
		s.Log.Error("update key meta", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to update key")
		return
	}
	if strings.TrimSpace(req.Secret) != "" {
		if err := s.Keys.UpdateSecret(r.Context(), id, req.Secret); err != nil {
			if errors.Is(err, crypto.ErrNoKey) {
				writeError(w, http.StatusPreconditionFailed, "encryption key not configured")
				return
			}
			s.Log.Error("update key secret", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to update key secret")
			return
		}
	}
	list, _ := s.Keys.List(r.Context())
	for _, k := range list {
		if k.ID == id {
			writeJSON(w, http.StatusOK, k)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Keys.Delete(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshKey(w http.ResponseWriter, r *http.Request) {
	// Refresh live credits for all keys via /api-info, then return current state.
	s.Shodan.RefreshCredits(r.Context())
	s.Keys.PersistPoolState(r.Context())
	list, err := s.Keys.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint failure.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
