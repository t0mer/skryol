package models

import (
	"encoding/json"
	"time"
)

// ChannelType enumerates notification backends.
type ChannelType string

const (
	ChannelShoutrrr    ChannelType = "shoutrrr"
	ChannelGreenAPI    ChannelType = "greenapi"
	ChannelWhatsAppWeb ChannelType = "whatsapp_web"
)

// ChannelConfig is the union of provider-specific settings. Fields not relevant
// to a provider are empty. Secrets are encrypted at rest as this JSON blob.
type ChannelConfig struct {
	// Shoutrrr
	URL string `json:"url,omitempty"`
	// GreenAPI
	InstanceID string `json:"instance_id,omitempty"`
	Token      string `json:"token,omitempty"`
	APIURL     string `json:"api_url,omitempty"`
	// WhatsApp Web (self-hosted)
	BaseURL  string `json:"base_url,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Shared
	Phone string `json:"phone,omitempty"`
}

// Channel is a configured notification destination.
type Channel struct {
	ID               string        `json:"id"`
	Type             ChannelType   `json:"type"`
	Label            string        `json:"label"`
	Enabled          bool          `json:"enabled"`
	NeedsCredentials bool          `json:"needs_credentials"`
	Config           ChannelConfig `json:"config"`
	Ciphertext       string        `json:"-"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

// AlertScope is the breadth a rule applies to.
type AlertScope string

const (
	ScopeGlobal AlertScope = "global"
	ScopeAsset  AlertScope = "asset"
)

// AlertRule defines a condition and its notification routing.
type AlertRule struct {
	ID              string          `json:"id"`
	Scope           AlertScope      `json:"scope"`
	AssetID         string          `json:"asset_id,omitempty"`
	Condition       string          `json:"condition"`
	Params          json.RawMessage `json:"params,omitempty"`
	Enabled         bool            `json:"enabled"`
	CooldownSeconds int             `json:"cooldown_seconds"`
	Severity        string          `json:"severity"`
	Label           string          `json:"label"`
	ChannelIDs      []string        `json:"channel_ids"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// AlertEvent is a recorded rule firing (audit log).
type AlertEvent struct {
	ID        string          `json:"id"`
	RuleID    string          `json:"rule_id"`
	AssetID   string          `json:"asset_id"`
	Condition string          `json:"condition"`
	Severity  string          `json:"severity"`
	FiredAt   time.Time       `json:"fired_at"`
	DedupKey  string          `json:"dedup_key"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Delivered json.RawMessage `json:"delivered,omitempty"`
}
