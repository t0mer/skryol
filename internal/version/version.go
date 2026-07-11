// Package version exposes the build-time version string for Skryol.
package version

// Version is the build version, injected at link time via
// -ldflags "-X github.com/t0mer/skryol/internal/version.Version=<v>".
// It defaults to "dev" for local (non-release) builds.
var Version = "dev"
