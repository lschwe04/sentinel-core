package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type IntegrationConfig struct {
	Type       string
	WebhookURL string
	APIToken   string
}

type TicketConnector interface {
	Dispatch(ctx context.Context, alert AlertPayload, config IntegrationConfig) error
}

type ZammadConnector struct {
	client *http.Client
}

func (z *ZammadConnector) Dispatch(ctx context.Context, alert AlertPayload, config IntegrationConfig) error {
	payload := map[string]interface{}{
		"title":       fmt.Sprintf("[Sentinel] %s auf Node %s", alert.Severity, alert.NodeID),
		"group":       "Users",
		"customer_id": fmt.Sprintf("%d", alert.CustomerID),
		"article": map[string]string{
			"subject":  "Automatischer Sentinel Alert",
			"body":     fmt.Sprintf("Metrik: %s\nWert: %.2f\nNachricht: %s", alert.Metric, alert.Value, alert.Message),
			"type":     "note",
			"internal": "false",
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("zammad payload marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.WebhookURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if config.APIToken != "" {
		req.Header.Set("Authorization", "Token token="+config.APIToken)
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return fmt.Errorf("zammad request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("zammad API returned status: %d", resp.StatusCode)
	}
	return nil
}

type TeamsConnector struct {
	client *http.Client
}

func (t *TeamsConnector) Dispatch(ctx context.Context, alert AlertPayload, config IntegrationConfig) error {
	payload := map[string]string{
		"text": fmt.Sprintf("🚨 **%s**\nNode: %s\nMessage: %s", alert.Severity, alert.NodeID, alert.Message),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.WebhookURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("teams webhook failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams API returned status: %d", resp.StatusCode)
	}
	return nil
}
