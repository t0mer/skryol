package notify

import (
	"context"
	"fmt"

	"github.com/containrrr/shoutrrr"
)

// shoutrrrSender delivers via a Shoutrrr service URL (Slack, Telegram, Discord,
// SMTP, ntfy, generic webhook, and many more).
type shoutrrrSender struct {
	url string
}

func (s *shoutrrrSender) Send(_ context.Context, msg Message) error {
	if err := shoutrrr.Send(s.url, msg.Text()); err != nil {
		return fmt.Errorf("shoutrrr send: %w", err)
	}
	return nil
}

func (s *shoutrrrSender) Test(ctx context.Context) error {
	return s.Send(ctx, Message{Title: "Skryol test", Body: "This is a test notification from Skryol."})
}
