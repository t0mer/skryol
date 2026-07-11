// Command skryol is the Skryol external attack-surface monitor daemon.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/t0mer/skryol/internal/alerts"
	"github.com/t0mer/skryol/internal/api"
	"github.com/t0mer/skryol/internal/auth"
	"github.com/t0mer/skryol/internal/channels"
	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/keys"
	"github.com/t0mer/skryol/internal/logging"
	"github.com/t0mer/skryol/internal/metrics"
	"github.com/t0mer/skryol/internal/processor"
	"github.com/t0mer/skryol/internal/scanner"
	"github.com/t0mer/skryol/internal/scoring"
	"github.com/t0mer/skryol/internal/shodan"
	"github.com/t0mer/skryol/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "skryol:", err)
		os.Exit(1)
	}
}

// resetAdminPassword prompts for a new admin password (twice) and stores it.
func resetAdminPassword(ctx context.Context, a *auth.Service) error {
	fmt.Print("New admin password: ")
	pw1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	fmt.Print("Confirm password: ")
	pw2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	if len(pw1) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if string(pw1) != string(pw2) {
		return fmt.Errorf("passwords do not match")
	}
	if err := a.SetPassword(ctx, string(pw1)); err != nil {
		return fmt.Errorf("setting password: %w", err)
	}
	fmt.Println("Admin password updated.")
	return nil
}

func run() error {
	fs := pflag.NewFlagSet("skryol", pflag.ContinueOnError)
	showVersion := fs.Bool("version", false, "Print version and exit")
	resetPassword := fs.Bool("reset-password", false, "Interactively reset the admin password and exit")
	config.DefineFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("skryol", version.Version)
		return nil
	}

	cfg, err := config.Load(fs)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	log := logging.New(cfg.Log.Level, cfg.Log.Format)
	log.Info("starting skryol", "version", version.Version, "port", cfg.Server.Port)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, cfg.Database.Path, log)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer database.Close()

	authService := auth.NewService(database, auth.Config{
		Enabled:       cfg.Auth.Enabled,
		Username:      cfg.Auth.Username,
		Password:      cfg.Auth.Password,
		SessionSecret: cfg.Auth.SessionSecret,
		GuardMetrics:  cfg.Auth.GuardMetrics,
	}, log)

	if *resetPassword {
		return resetAdminPassword(ctx, authService)
	}
	if err := authService.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrapping auth: %w", err)
	}

	m := metrics.New()

	cipher, err := crypto.New(cfg.Crypto.EncryptionKey)
	if err != nil {
		return fmt.Errorf("initializing crypto: %w", err)
	}
	if !cipher.Enabled() {
		log.Warn("no encryption key configured; Shodan keys and channel secrets cannot be stored (set SKRYOL_CRYPTO_ENCRYPTION_KEY)")
	}

	pool := shodan.NewKeyPool(cfg.Shodan.RequestsPerSecond)
	shodanClient := shodan.New(pool, shodan.Options{
		BaseURL:    cfg.Shodan.BaseURL,
		MaxRetries: cfg.Shodan.MaxRetries,
		Timeout:    time.Duration(cfg.Shodan.TimeoutSeconds) * time.Second,
		Logger:     log,
		OnRequest: func(endpoint, outcome string) {
			m.ShodanRequests.WithLabelValues(endpoint, outcome).Inc()
		},
	})

	keyService := keys.NewService(database, cipher, pool, log)
	if err := keyService.Reload(ctx); err != nil {
		return fmt.Errorf("loading shodan keys: %w", err)
	}

	channelService := channels.NewService(database, cipher)
	alertEngine := alerts.New(database, channelService, m, log, cfg.Server.BaseURL)

	scanEngine := scanner.New(database, shodanClient, keyService, m, log, cfg.Scanner)
	proc := processor.New(database, m, log, func(ctx context.Context) scoring.Weights {
		return database.GetScoringWeights(ctx)
	})
	proc.SetAlertEvaluator(alertEngine)
	scanEngine.SetProcessor(proc)
	if err := scanEngine.Start(); err != nil {
		return fmt.Errorf("starting scan scheduler: %w", err)
	}
	defer scanEngine.Stop()

	server := api.NewServer(api.Deps{
		Config:   cfg,
		DB:       database,
		Log:      log,
		Metrics:  m,
		Keys:     keyService,
		Shodan:   shodanClient,
		Cipher:   cipher,
		Scanner:  scanEngine,
		Channels: channelService,
		Auth:     authService,
	})
	router, err := server.Router()
	if err != nil {
		return fmt.Errorf("building router: %w", err)
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("skryol stopped")
	return nil
}
