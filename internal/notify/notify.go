// Package notify provides a provider-agnostic notification channel abstraction
// with three backends: Shoutrrr (broad coverage), GreenAPI WhatsApp, and a
// self-hosted WhatsApp Web bridge. Sending is best-effort and must never block
// or fail the primary operation.
package notify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/t0mer/skryol/internal/models"
)

// Message is a notification payload.
type Message struct {
	Title string
	Body  string
}

// Text renders the message as a single string (title + body).
func (m Message) Text() string {
	if m.Title == "" {
		return m.Body
	}
	return m.Title + "\n\n" + m.Body
}

// Sender delivers messages for one configured channel.
type Sender interface {
	Send(ctx context.Context, msg Message) error
	Test(ctx context.Context) error
}

// httpClient is the shared client for provider HTTP calls.
var httpClient = &http.Client{Timeout: 20 * time.Second}

// NewSender builds a Sender for a channel type + config. It validates that the
// config carries the fields the provider requires.
func NewSender(typ models.ChannelType, cfg models.ChannelConfig) (Sender, error) {
	switch typ {
	case models.ChannelShoutrrr:
		if strings.TrimSpace(cfg.URL) == "" {
			return nil, fmt.Errorf("shoutrrr channel requires a URL")
		}
		return &shoutrrrSender{url: strings.TrimSpace(cfg.URL)}, nil

	case models.ChannelGreenAPI:
		s := &greenAPISender{
			instanceID: strings.TrimSpace(cfg.InstanceID),
			token:      strings.TrimSpace(cfg.Token),
			phone:      strings.TrimSpace(cfg.Phone),
			apiURL:     strings.TrimSpace(cfg.APIURL),
		}
		if s.instanceID == "" || s.token == "" || s.phone == "" {
			return nil, fmt.Errorf("greenapi channel requires instance_id, token, and phone")
		}
		return s, nil

	case models.ChannelWhatsAppWeb:
		s := &whatsappWebSender{
			baseURL:  strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
			phone:    strings.TrimSpace(cfg.Phone),
			username: strings.TrimSpace(cfg.Username),
			password: cfg.Password,
		}
		if s.baseURL == "" || s.phone == "" {
			return nil, fmt.Errorf("whatsapp_web channel requires base_url and phone")
		}
		return s, nil

	default:
		return nil, fmt.Errorf("unknown channel type %q", typ)
	}
}
