package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultGreenAPIURL = "https://api.green-api.com"

// greenAPISender delivers via the GreenAPI WhatsApp cloud service.
type greenAPISender struct {
	instanceID string
	token      string
	phone      string
	apiURL     string
}

func (g *greenAPISender) chatID() string {
	// The phone is digits-only, international format. Append @c.us if absent.
	p := strings.TrimSpace(g.phone)
	if strings.Contains(p, "@") {
		return p
	}
	return p + "@c.us"
}

func (g *greenAPISender) endpoint() string {
	base := g.apiURL
	if base == "" {
		base = defaultGreenAPIURL
	}
	base = strings.TrimRight(base, "/")
	return fmt.Sprintf("%s/waInstance%s/sendMessage/%s", base, g.instanceID, g.token)
}

func (g *greenAPISender) Send(ctx context.Context, msg Message) error {
	body, _ := json.Marshal(map[string]string{
		"chatId":  g.chatID(),
		"message": msg.Text(),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("greenapi send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("greenapi send: status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func (g *greenAPISender) Test(ctx context.Context) error {
	return g.Send(ctx, Message{Title: "Skryol test", Body: "This is a test notification from Skryol."})
}
