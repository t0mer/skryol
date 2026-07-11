// Package keys ties together Shodan key persistence (encrypted at rest),
// decryption, and the in-memory rotating key pool.
package keys

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/shodan"
)

// Service manages Shodan API keys and keeps the shared pool in sync.
type Service struct {
	db     *db.DB
	cipher *crypto.Cipher
	pool   *shodan.KeyPool
	log    *slog.Logger
	mu     sync.Mutex
}

// NewService constructs the key service.
func NewService(database *db.DB, cipher *crypto.Cipher, pool *shodan.KeyPool, log *slog.Logger) *Service {
	return &Service{db: database, cipher: cipher, pool: pool, log: log}
}

// Reload loads all keys from the database, decrypts them, and replaces the
// pool's contents. Keys that fail to decrypt are skipped and logged.
func (s *Service) Reload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.ListShodanKeys(ctx)
	if err != nil {
		return err
	}
	configs := make([]shodan.KeyConfig, 0, len(rows))
	for _, k := range rows {
		secret, derr := s.cipher.DecryptString(k.Ciphertext)
		if derr != nil {
			s.log.Error("failed to decrypt shodan key; skipping", "key", k.ID, "label", k.Label, "err", derr)
			continue
		}
		configs = append(configs, shodan.KeyConfig{
			ID:            k.ID,
			Label:         k.Label,
			Secret:        secret,
			Enabled:       k.Enabled,
			RatePerSecond: k.RatePerSecond,
			QueryCredits:  k.QueryCredits,
			ScanCredits:   k.ScanCredits,
			Plan:          k.Plan,
			Health:        shodan.Health(k.Health),
		})
	}
	s.pool.SetKeys(configs)
	return nil
}

// Create encrypts and stores a new key, then reloads the pool.
func (s *Service) Create(ctx context.Context, label, secret string, enabled bool, rate float64) (*models.ShodanKey, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, fmt.Errorf("shodan key secret must not be empty")
	}
	if !s.cipher.Enabled() {
		return nil, crypto.ErrNoKey
	}
	ct, err := s.cipher.EncryptString(secret)
	if err != nil {
		return nil, err
	}
	k := &models.ShodanKey{
		Label:         label,
		Ciphertext:    ct,
		Enabled:       enabled,
		RatePerSecond: rate,
		Health:        "unknown",
	}
	if err := s.db.CreateShodanKey(ctx, k); err != nil {
		return nil, err
	}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	k.Ciphertext = ""
	return k, nil
}

// UpdateMeta changes label/enabled/rate and reloads the pool.
func (s *Service) UpdateMeta(ctx context.Context, id, label string, enabled bool, rate float64) error {
	if rate <= 0 {
		rate = 1.0
	}
	if err := s.db.UpdateShodanKeyMeta(ctx, id, label, enabled, rate); err != nil {
		return err
	}
	return s.Reload(ctx)
}

// UpdateSecret re-encrypts and replaces a key's secret, then reloads the pool.
func (s *Service) UpdateSecret(ctx context.Context, id, secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return fmt.Errorf("shodan key secret must not be empty")
	}
	ct, err := s.cipher.EncryptString(secret)
	if err != nil {
		return err
	}
	if err := s.db.UpdateShodanKeySecret(ctx, id, ct); err != nil {
		return err
	}
	return s.Reload(ctx)
}

// Delete removes a key and reloads the pool.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.db.DeleteShodanKey(ctx, id); err != nil {
		return err
	}
	return s.Reload(ctx)
}

// List returns key metadata merged with live pool state (credits/health), so
// the UI shows current values even before they are persisted.
func (s *Service) List(ctx context.Context) ([]models.ShodanKey, error) {
	rows, err := s.db.ListShodanKeys(ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]shodan.KeyState{}
	for _, st := range s.pool.States() {
		live[st.ID] = st
	}
	out := make([]models.ShodanKey, 0, len(rows))
	for _, k := range rows {
		k.Ciphertext = "" // never expose
		if st, ok := live[k.ID]; ok {
			k.QueryCredits = st.QueryCredits
			k.ScanCredits = st.ScanCredits
			k.Plan = st.Plan
			k.Health = string(st.Health)
			k.LastError = st.LastError
			if !st.LastUsedAt.IsZero() {
				t := st.LastUsedAt
				k.LastUsedAt = &t
			}
			if !st.LastCheckedAt.IsZero() {
				t := st.LastCheckedAt
				k.LastCheckedAt = &t
			}
		}
		out = append(out, k)
	}
	return out, nil
}

// PersistPoolState writes the pool's live credit/health snapshots back to the
// database. Best-effort: individual failures are logged, not fatal.
func (s *Service) PersistPoolState(ctx context.Context) {
	for _, st := range s.pool.States() {
		if err := s.db.UpdateShodanKeyState(ctx, st.ID, st.QueryCredits, st.ScanCredits,
			st.Plan, string(st.Health), st.LastError, timeOrNil(st.LastUsedAt), timeOrNil(st.LastCheckedAt)); err != nil {
			s.log.Warn("persist key state failed", "key", st.ID, "err", err)
		}
	}
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
