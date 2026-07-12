// Package logging builds the application's structured logger.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Logger wraps an *slog.Logger whose level can be changed at runtime. The level
// is backed by a *slog.LevelVar so a live update takes effect immediately across
// every handler derived from this logger, without rebuilding it.
type Logger struct {
	*slog.Logger
	level *slog.LevelVar
}

// New builds a Logger for the given level and format ("json" or "text").
func New(level, format string) *Logger {
	lv := new(slog.LevelVar)
	lv.Set(parseLevel(level))

	opts := &slog.HandlerOptions{Level: lv}
	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return &Logger{Logger: slog.New(handler), level: lv}
}

// SetLevel changes the active log level at runtime. Unknown values map to info.
func (l *Logger) SetLevel(level string) {
	l.level.Set(parseLevel(level))
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warning", "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
