// Package web embeds the built frontend SPA and serves it with a catch-all
// fallback so client-side routing works. The dist directory is produced by the
// Vite build; a tracked placeholder keeps this embed compiling before any build.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded SPA. Requests that
// don't map to a real asset fall back to index.html for client-side routing.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if upath == "" {
			upath = "index.html"
		}
		if info, err := fs.Stat(sub, upath); err != nil || info.IsDir() {
			// Not a real file (or a directory): serve the SPA entrypoint so
			// client-side routing handles paths like /assets or /settings.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}
