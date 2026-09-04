// sentinel-core: internal/services/dispatcher.go
package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TeamsMessage struct {
	Text string `json:"text"`
}

// DispatchAlert sendet Alarme an vorkonfigurierte Systemhaus-Webhooks mit striktem Timeout
func DispatchAlert(tenantID string, message string, webhookURL string) error {
	payload := TeamsMessage{
		Text: "🚨 **SentinelCore Alert (Mandant: " + tenantID + ")**\n\n" + message,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal teams message: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to dispatch alert webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned error status code: %d", resp.StatusCode)
	}

	return nil
}
