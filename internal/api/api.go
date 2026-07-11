// Package api wires the chi HTTP router: middleware, the versioned JSON API,
// Prometheus metrics, health, and the embedded SPA fallback.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/metrics"
	"github.com/t0mer/skryol/internal/web"
)

// Server holds the dependencies shared by all HTTP handlers.
type Server struct {
	cfg     *config.Config
	db      *db.DB
	log     *slog.Logger
	metrics *metrics.Metrics
}

// NewServer constructs the HTTP server dependencies.
func NewServer(cfg *config.Config, database *db.DB, log *slog.Logger, m *metrics.Metrics) *Server {
	return &Server{cfg: cfg, db: database, log: log, metrics: m}
}

// Router builds the fully-wired chi router.
func (s *Server) Router() (http.Handler, error) {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(middleware.Compress(5))
	if s.cfg.Server.EnableCORS {
		r.Use(corsMiddleware)
	}

	// Operational endpoints (never behind auth except optionally metrics).
	r.Get("/healthz", s.handleHealth)
	r.Handle("/metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))

	// Versioned JSON API. Handlers are added phase by phase.
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
	})

	// Embedded SPA with client-routing fallback.
	spa, err := web.Handler()
	if err != nil {
		return nil, err
	}
	r.NotFound(spa.ServeHTTP)
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	return r, nil
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.log.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
		s.metrics.HTTPRequests.WithLabelValues(r.Method, http.StatusText(ww.Status())).Inc()
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
