package logging

import (
	"log/slog"
	"testing"
)

func TestSetLevelChangesActiveLevel(t *testing.T) {
	l := New("info", "json")
	if l.Enabled(nil, slog.LevelDebug) {
		t.Fatal("debug should be disabled at info level")
	}
	l.SetLevel("debug")
	if !l.Enabled(nil, slog.LevelDebug) {
		t.Fatal("debug should be enabled after SetLevel(debug)")
	}
	l.SetLevel("error")
	if l.Enabled(nil, slog.LevelWarn) {
		t.Fatal("warn should be disabled at error level")
	}
}

func TestParseLevelUnknownDefaultsInfo(t *testing.T) {
	if parseLevel("nonsense") != slog.LevelInfo {
		t.Fatal("unknown level should map to info")
	}
	if parseLevel("WARN") != slog.LevelWarn {
		t.Fatal("WARN should map to warn")
	}
}
