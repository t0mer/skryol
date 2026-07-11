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

	"github.com/t0mer/skryol/internal/channels"
	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/keys"
	"github.com/t0mer/skryol/internal/metrics"
	"github.com/t0mer/skryol/internal/scanner"
	"github.com/t0mer/skryol/internal/shodan"
	"github.com/t0mer/skryol/internal/web"
)

// Deps bundles the dependencies shared by all HTTP handlers.
type Deps struct {
	Config   *config.Config
	DB       *db.DB
	Log      *slog.Logger
	Metrics  *metrics.Metrics
	Keys     *keys.Service
	Shodan   *shodan.Client
	Cipher   *crypto.Cipher
	Scanner  *scanner.Scanner
	Channels *channels.Service
}

// Server holds handler dependencies.
type Server struct {
	Deps
}

// NewServer constructs the HTTP server.
func NewServer(d Deps) *Server {
	return &Server{Deps: d}
}

// Router builds the fully-wired chi router.
func (s *Server) Router() (http.Handler, error) {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(120 * time.Second))
	r.Use(middleware.Compress(5))
	if s.Config.Server.EnableCORS {
		r.Use(corsMiddleware)
	}

	// Operational endpoints.
	r.Get("/healthz", s.handleHealth)
	r.Handle("/metrics", promhttp.HandlerFor(s.Metrics.Registry, promhttp.HandlerOpts{}))

	// Versioned JSON API.
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)

		r.Route("/assets", func(r chi.Router) {
			r.Get("/", s.handleListAssets)
			r.Post("/", s.handleCreateAsset)
			r.Get("/{id}", s.handleGetAsset)
			r.Put("/{id}", s.handleUpdateAsset)
			r.Delete("/{id}", s.handleDeleteAsset)
			r.Post("/{id}/scan", s.handleScanAsset)
			r.Get("/{id}/scans", s.handleListAssetScans)
			r.Get("/{id}/diff", s.handleAssetDiff)
			r.Get("/{id}/score-history", s.handleScoreHistory)
		})

		r.Post("/scan", s.handleScanAll)
		r.Get("/scans/{id}", s.handleGetScan)

		r.Route("/shodan/keys", func(r chi.Router) {
			r.Get("/", s.handleListKeys)
			r.Post("/", s.handleCreateKey)
			r.Put("/{id}", s.handleUpdateKey)
			r.Delete("/{id}", s.handleDeleteKey)
			r.Post("/{id}/refresh", s.handleRefreshKey)
		})

		r.Route("/channels", func(r chi.Router) {
			r.Get("/", s.handleListChannels)
			r.Post("/", s.handleCreateChannel)
			r.Post("/test", s.handleTestChannel)
			r.Put("/{id}", s.handleUpdateChannel)
			r.Delete("/{id}", s.handleDeleteChannel)
			r.Post("/{id}/test", s.handleTestChannel)
		})

		r.Route("/rules", func(r chi.Router) {
			r.Get("/", s.handleListRules)
			r.Post("/", s.handleCreateRule)
			r.Get("/{id}", s.handleGetRule)
			r.Put("/{id}", s.handleUpdateRule)
			r.Delete("/{id}", s.handleDeleteRule)
		})

		r.Get("/alerts/events", s.handleListAlertEvents)
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
		s.Log.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
		s.Metrics.HTTPRequests.WithLabelValues(r.Method, http.StatusText(ww.Status())).Inc()
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
