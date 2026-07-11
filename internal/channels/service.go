// Package channels manages notification channels: their encrypted-at-rest
// configuration, credential masking for the API, and construction of concrete
// senders for delivery and test messages.
package channels

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/notify"
)

// Service manages channel persistence and delivery.
type Service struct {
	db     *db.DB
	cipher *crypto.Cipher
}

// NewService builds the channel service.
func NewService(database *db.DB, cipher *crypto.Cipher) *Service {
	return &Service{db: database, cipher: cipher}
}

// Create encrypts and stores a new channel.
func (s *Service) Create(ctx context.Context, typ models.ChannelType, label string, enabled bool, cfg models.ChannelConfig) (*models.Channel, error) {
	if !s.cipher.Enabled() {
		return nil, crypto.ErrNoKey
	}
	if _, err := notify.NewSender(typ, cfg); err != nil {
		return nil, err
	}
	ct, err := s.encrypt(cfg)
	if err != nil {
		return nil, err
	}
	c := &models.Channel{Type: typ, Label: label, Enabled: enabled, Ciphertext: ct}
	if err := s.db.CreateChannel(ctx, c); err != nil {
		return nil, err
	}
	c.Config = mask(cfg)
	c.Ciphertext = ""
	return c, nil
}

// Update replaces label/enabled and, when cfg is non-nil, the encrypted config.
func (s *Service) Update(ctx context.Context, id string, label string, enabled bool, cfg *models.ChannelConfig) (*models.Channel, error) {
	existing, err := s.db.GetChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	existing.Label = label
	existing.Enabled = enabled
	if cfg != nil {
		if _, err := notify.NewSender(existing.Type, *cfg); err != nil {
			return nil, err
		}
		ct, err := s.encrypt(*cfg)
		if err != nil {
			return nil, err
		}
		existing.Ciphertext = ct
		existing.NeedsCredentials = false
	}
	if err := s.db.UpdateChannel(ctx, existing); err != nil {
		return nil, err
	}
	return s.get(ctx, id, true)
}

// Delete removes a channel.
func (s *Service) Delete(ctx context.Context, id string) error {
	return s.db.DeleteChannel(ctx, id)
}

// List returns all channels with masked credentials.
func (s *Service) List(ctx context.Context) ([]models.Channel, error) {
	rows, err := s.db.ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]models.Channel, 0, len(rows))
	for _, c := range rows {
		cfg, _ := s.decrypt(c.Ciphertext)
		c.Config = mask(cfg)
		c.Ciphertext = ""
		out = append(out, c)
	}
	return out, nil
}

// get returns one channel, optionally masked.
func (s *Service) get(ctx context.Context, id string, masked bool) (*models.Channel, error) {
	c, err := s.db.GetChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	cfg, _ := s.decrypt(c.Ciphertext)
	if masked {
		c.Config = mask(cfg)
	} else {
		c.Config = cfg
	}
	c.Ciphertext = ""
	return c, nil
}

// SendTo delivers a message to a stored channel by ID (best-effort).
func (s *Service) SendTo(ctx context.Context, id string, msg notify.Message) error {
	c, err := s.get(ctx, id, false)
	if err != nil {
		return err
	}
	sender, err := notify.NewSender(c.Type, c.Config)
	if err != nil {
		return err
	}
	return sender.Send(ctx, msg)
}

// TestStored sends a test message to a stored channel.
func (s *Service) TestStored(ctx context.Context, id string) error {
	c, err := s.get(ctx, id, false)
	if err != nil {
		return err
	}
	sender, err := notify.NewSender(c.Type, c.Config)
	if err != nil {
		return err
	}
	return sender.Test(ctx)
}

// TestConfig sends a test message using ad-hoc config (before saving).
func (s *Service) TestConfig(ctx context.Context, typ models.ChannelType, cfg models.ChannelConfig) error {
	sender, err := notify.NewSender(typ, cfg)
	if err != nil {
		return err
	}
	return sender.Test(ctx)
}

func (s *Service) encrypt(cfg models.ChannelConfig) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return s.cipher.Encrypt(b)
}

func (s *Service) decrypt(ct string) (models.ChannelConfig, error) {
	var cfg models.ChannelConfig
	if ct == "" {
		return cfg, nil
	}
	b, err := s.cipher.Decrypt(ct)
	if err != nil {
		return cfg, fmt.Errorf("decrypting channel config: %w", err)
	}
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}

const maskToken = "••••••"

// mask redacts secret fields for API responses while keeping non-secret context.
func mask(cfg models.ChannelConfig) models.ChannelConfig {
	if cfg.URL != "" {
		cfg.URL = maskToken
	}
	if cfg.Token != "" {
		cfg.Token = maskToken
	}
	if cfg.Password != "" {
		cfg.Password = maskToken
	}
	return cfg
}
