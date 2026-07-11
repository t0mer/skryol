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

// whatsappWebSender delivers via a self-hosted go-whatsapp-web-multidevice
// bridge (POST {base}/send/message with optional basic auth).
type whatsappWebSender struct {
	baseURL  string
	phone    string
	username string
	password string
}

func (s *whatsappWebSender) Send(ctx context.Context, msg Message) error {
	body, _ := json.Marshal(map[string]string{
		"phone":   s.phone,
		"message": msg.Text(),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/send/message", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.username != "" || s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("whatsapp_web send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("whatsapp_web send: status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func (s *whatsappWebSender) Test(ctx context.Context) error {
	return s.Send(ctx, Message{Title: "Skryol test", Body: "This is a test notification from Skryol."})
}
