package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t0mer/skryol/internal/auth"
	"github.com/t0mer/skryol/internal/db"
)

// requireAuth rejects unauthenticated requests when auth is enabled.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil || !s.Auth.Enabled() || s.Auth.Authenticate(r) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "authentication required")
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token, err := s.Auth.Login(r.Context(), strings.TrimSpace(req.Username), req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   12 * 60 * 60,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "username": req.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: auth.SessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	required := s.Auth != nil && s.Auth.Enabled()
	authed := !required || s.Auth.Authenticate(r)
	writeJSON(w, http.StatusOK, map[string]any{"auth_required": required, "authenticated": authed})
}

type tokenRequest struct {
	Label string `json:"label"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.Auth.ListTokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	_ = decodeJSON(r, &req)
	token, rec, err := s.Auth.CreateToken(r.Context(), req.Label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	// The plaintext token is returned exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "id": rec.ID, "label": rec.Label})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Auth.DeleteToken(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
