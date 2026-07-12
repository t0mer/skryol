// Package settings persists runtime-editable configuration back to the YAML
// bootstrap file and applies it to the running process: hot where safe, or
// recorded as pending-restart otherwise. The YAML file remains the source of
// truth; every restart re-reads it as the live config, which clears any pending
// state naturally.
package settings

import (
	"context"
	"fmt"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/t0mer/skryol/internal/auth"
	"github.com/t0mer/skryol/internal/config"
	"github.com/t0mer/skryol/internal/logging"
	"github.com/t0mer/skryol/internal/scanner"
)

// PendingChange is a restart-required value that has been saved to YAML but is
// not yet live.
type PendingChange struct {
	Desired any `json:"desired"`
	Running any `json:"running"`
}

// minPasswordLen mirrors the CLI reset-password minimum.
const minPasswordLen = 8

// Service owns the write-back + apply logic for editable settings.
type Service struct {
	mu      sync.Mutex
	live    *config.Config
	pending map[string]PendingChange

	log     *logging.Logger
	scanner *scanner.Scanner
	auth    *auth.Service
}

// New builds a settings service around the live config and the services that can
// be reconfigured at runtime. live is the same *config.Config the rest of the
// process reads, so hot changes are visible everywhere immediately.
func New(live *config.Config, log *logging.Logger, sc *scanner.Scanner, a *auth.Service) *Service {
	return &Service{
		live:    live,
		pending: map[string]PendingChange{},
		log:     log,
		scanner: sc,
		auth:    a,
	}
}

// FilePath is the YAML file edits are written to.
func (s *Service) FilePath() string {
	if s.live.Source != nil {
		return s.live.Source.FileUsed
	}
	return ""
}

// Locked returns a copy of the precedence-lock map (key -> "env"|"flag").
func (s *Service) Locked() map[string]string {
	out := map[string]string{}
	if s.live.Source != nil {
		for k, v := range s.live.Source.Locked {
			out[k] = v
		}
	}
	return out
}

// Pending returns a copy of the restart-required changes awaiting a restart.
func (s *Service) Pending() map[string]PendingChange {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]PendingChange, len(s.pending))
	for k, v := range s.pending {
		out[k] = v
	}
	return out
}

// Values returns the current displayed value of each editable key: the pending
// desired value when one is queued, otherwise the live value.
func (s *Service) Values() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]any, len(config.EditableKeys))
	for _, ek := range config.EditableKeys {
		if p, ok := s.pending[ek.Key]; ok {
			out[ek.Key] = p.Desired
			continue
		}
		if v, ok := s.live.GetEditable(ek.Key); ok {
			out[ek.Key] = v
		}
	}
	return out
}

// Update coerces, validates, persists, and applies a set of changes keyed by
// canonical dotted key, plus an optional admin password. It returns an error
// without persisting anything if validation fails.
func (s *Service) Update(ctx context.Context, changes map[string]any, password *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	locked := s.Locked()

	// Coerce and reject unknown/locked keys before touching anything.
	coerced := make(map[string]any, len(changes))
	for key, raw := range changes {
		if _, ok := config.EditableKeyFor(key); !ok {
			return fmt.Errorf("unknown setting %q", key)
		}
		if reason, isLocked := locked[key]; isLocked {
			return fmt.Errorf("%q is managed by %s and cannot be edited here", key, reason)
		}
		v, err := config.Coerce(key, raw)
		if err != nil {
			return err
		}
		coerced[key] = v
	}

	// Build the effective config (a copy) and validate it as a whole.
	eff := *s.live
	for k, v := range coerced {
		if err := eff.SetEditable(k, v); err != nil {
			return err
		}
	}
	if err := eff.Validate(); err != nil {
		return err
	}
	if err := validateRanges(coerced); err != nil {
		return err
	}

	// Guard: enabling auth requires a usable admin account.
	if v, ok := coerced["auth.enabled"]; ok && v.(bool) && !s.live.Auth.Enabled {
		if password == nil || *password == "" {
			has, err := s.auth.HasUser(ctx)
			if err != nil {
				return fmt.Errorf("checking admin account: %w", err)
			}
			if !has {
				return fmt.Errorf("set an admin password before enabling authentication")
			}
		}
	}
	if password != nil && *password != "" && len(*password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}

	// Persist to YAML first; if this fails nothing is applied.
	if len(coerced) > 0 {
		if err := config.WriteEditable(s.FilePath(), coerced); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
	}

	// Apply. Values were validated above, so hot applies cannot fail here.
	var scannerChanged, authChanged, logLevelChanged bool
	for key, val := range coerced {
		ek, _ := config.EditableKeyFor(key)
		if ek.Apply == config.ApplyRestart {
			running, _ := s.live.GetEditable(key)
			if running == val {
				delete(s.pending, key)
			} else {
				s.pending[key] = PendingChange{Desired: val, Running: running}
			}
			continue
		}
		// Hot: mutate live config and flag the owning subsystem.
		_ = s.live.SetEditable(key, val)
		switch {
		case key == "log.level":
			logLevelChanged = true
		case len(key) >= 8 && key[:8] == "scanner.":
			scannerChanged = true
		case len(key) >= 5 && key[:5] == "auth.":
			authChanged = true
		}
	}

	if logLevelChanged {
		s.log.SetLevel(s.live.Log.Level)
	}
	if scannerChanged {
		if err := s.scanner.Reconfigure(s.live.Scanner); err != nil {
			// Pre-validated, but surface anything unexpected.
			return fmt.Errorf("applying scanner settings: %w", err)
		}
	}
	if authChanged {
		if err := s.auth.SetRuntimeConfig(ctx, s.live.Auth.Enabled, s.live.Auth.Username, s.live.Auth.GuardMetrics); err != nil {
			return fmt.Errorf("applying auth settings: %w", err)
		}
	}
	if password != nil && *password != "" {
		if err := s.auth.SetPassword(ctx, *password); err != nil {
			return fmt.Errorf("setting password: %w", err)
		}
	}
	return nil
}

// validateRanges enforces per-key bounds beyond Config.Validate.
func validateRanges(changes map[string]any) error {
	for key, val := range changes {
		switch key {
		case "server.address":
			if val.(string) == "" {
				return fmt.Errorf("server.address must not be empty")
			}
		case "scanner.schedule":
			if _, err := cron.ParseStandard(val.(string)); err != nil {
				return fmt.Errorf("invalid schedule %q: %w", val.(string), err)
			}
		case "scanner.max_hosts_per_asset", "scanner.max_concurrency", "scanner.rescan_timeout_seconds", "shodan.timeout_seconds":
			if val.(int) < 1 {
				return fmt.Errorf("%s must be at least 1", key)
			}
		case "scanner.retention_days", "shodan.max_retries":
			if val.(int) < 0 {
				return fmt.Errorf("%s must not be negative", key)
			}
		case "shodan.requests_per_second":
			if val.(float64) <= 0 {
				return fmt.Errorf("shodan.requests_per_second must be greater than 0")
			}
		}
	}
	return nil
}
