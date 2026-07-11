package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
)

type channelRequest struct {
	Type    models.ChannelType   `json:"type"`
	Label   string               `json:"label"`
	Enabled *bool                `json:"enabled"`
	Config  models.ChannelConfig `json:"config"`
}

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request) {
	list, err := s.Channels.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list channels")
		return
	}
	if list == nil {
		list = []models.Channel{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	var req channelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	c, err := s.Channels.Create(r.Context(), req.Type, req.Label, enabled, req.Config)
	if err != nil {
		if errors.Is(err, crypto.ErrNoKey) {
			writeError(w, http.StatusPreconditionFailed, "encryption key not configured; set SKRYOL_CRYPTO_ENCRYPTION_KEY")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req channelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	// Only replace config when provided (non-empty struct).
	var cfgPtr *models.ChannelConfig
	if req.Config != (models.ChannelConfig{}) {
		cfgPtr = &req.Config
	}
	c, err := s.Channels.Update(r.Context(), id, req.Label, enabled, cfgPtr)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Channels.Delete(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete channel")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleTestChannel sends a real test message. If an {id} is present it tests a
// stored channel; otherwise it tests ad-hoc config from the request body.
func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id != "" {
		if err := s.Channels.TestStored(r.Context(), id); err != nil {
			writeError(w, http.StatusBadGateway, "test failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
		return
	}
	var req channelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := s.Channels.TestConfig(r.Context(), req.Type, req.Config); err != nil {
		writeError(w, http.StatusBadGateway, "test failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}
