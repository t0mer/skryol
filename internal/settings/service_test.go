package settings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/logging"
	"github.com/t0mer/skryol/internal/scanner"
)

func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	return &config.Config{
		Server:   config.ServerConfig{Port: 8080, Address: "0.0.0.0"},
		Log:      config.LogConfig{Level: "info", Format: "json"},
		Database: config.DatabaseConfig{Path: "/data/skryol.db"},
		Scanner: config.ScannerConfig{
			Schedule: "0 3 * * *", MaxHostsPerAsset: 256, MaxConcurrency: 4,
		},
		Shodan: config.ShodanConfig{RequestsPerSecond: 1, MaxRetries: 4, TimeoutSeconds: 30},
		Auth:   config.AuthConfig{Enabled: false, Username: "admin"},
		Source: &config.Source{FileUsed: path, Locked: map[string]string{}},
	}
}

func newSvc(t *testing.T, cfg *config.Config) *Service {
	t.Helper()
	sc := scanner.New(nil, nil, nil, nil, logging.New("info", "text").Logger, cfg.Scanner)
	if err := sc.Start(); err != nil {
		t.Fatalf("scanner start: %v", err)
	}
	t.Cleanup(sc.Stop)
	// auth is nil-safe for the paths these tests exercise (no auth changes).
	return New(cfg, logging.New("info", "text"), sc, nil)
}

func TestUpdateHotScannerMutatesLiveAndPersists(t *testing.T) {
	cfg := baseConfig(t)
	svc := newSvc(t, cfg)

	err := svc.Update(context.Background(), map[string]any{
		"scanner.max_concurrency": float64(8), // JSON number
		"log.level":               "debug",
	}, nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if cfg.Scanner.MaxConcurrency != 8 {
		t.Fatalf("live max_concurrency = %d, want 8", cfg.Scanner.MaxConcurrency)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("live log.level = %q, want debug", cfg.Log.Level)
	}
	if len(svc.Pending()) != 0 {
		t.Fatalf("hot changes should not be pending: %#v", svc.Pending())
	}
	// Persisted to YAML.
	data, _ := os.ReadFile(cfg.Source.FileUsed)
	if !strings.Contains(string(data), "max_concurrency") {
		t.Fatalf("YAML not written:\n%s", data)
	}
}

func TestUpdateRestartKeyGoesPendingNotLive(t *testing.T) {
	cfg := baseConfig(t)
	svc := newSvc(t, cfg)

	if err := svc.Update(context.Background(), map[string]any{"server.port": float64(9090)}, nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("restart key must not mutate live: port = %d", cfg.Server.Port)
	}
	p, ok := svc.Pending()["server.port"]
	if !ok {
		t.Fatal("server.port should be pending")
	}
	if p.Desired != 9090 || p.Running != 8080 {
		t.Fatalf("pending = %+v, want desired 9090 running 8080", p)
	}
	// Values() surfaces the pending desired value for the form.
	if svc.Values()["server.port"] != 9090 {
		t.Fatalf("Values port = %v, want pending 9090", svc.Values()["server.port"])
	}
}

func TestUpdateRejectsLockedKey(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Source.Locked["server.port"] = "env"
	svc := newSvc(t, cfg)

	err := svc.Update(context.Background(), map[string]any{"server.port": float64(9090)}, nil)
	if err == nil {
		t.Fatal("expected rejection of env-locked key")
	}
	if _, statErr := os.Stat(cfg.Source.FileUsed); statErr == nil {
		t.Fatal("nothing should be persisted when a locked key is rejected")
	}
}

func TestUpdateRejectsBadSchedule(t *testing.T) {
	cfg := baseConfig(t)
	svc := newSvc(t, cfg)

	err := svc.Update(context.Background(), map[string]any{"scanner.schedule": "nope"}, nil)
	if err == nil {
		t.Fatal("expected invalid schedule rejection")
	}
	if cfg.Scanner.Schedule != "0 3 * * *" {
		t.Fatalf("schedule changed despite invalid cron: %q", cfg.Scanner.Schedule)
	}
}

func TestUpdateRejectsPortOutOfRange(t *testing.T) {
	cfg := baseConfig(t)
	svc := newSvc(t, cfg)
	if err := svc.Update(context.Background(), map[string]any{"server.port": float64(70000)}, nil); err == nil {
		t.Fatal("expected out-of-range port rejection")
	}
}
