// sentinel-core: internal/services/dispatcher.go
package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type TeamsMessage struct {
	Text string `json:"text"`
}

// DispatchAlert sendet Alarme an vorkonfigurierte Systemhaus-Webhooks
func DispatchAlert(tenantID string, message string, webhookURL string) error {
	payload := TeamsMessage{
		Text: "🚨 **SentinelCore Alert**\n\n" + message,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, _ := http.NewRequest(http.MethodPost, webhookURL, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
