// sentinel-core: internal/services/dispatcher.go
package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type TeamsMessage struct {
	Text string `json:"text"`
}

// WebhookDispatcher definiert das Interface für saubere Dependency Injection und Unit-Tests
type WebhookDispatcher interface {
	DispatchAlert(ctx context.Context, tenantID string, message string, webhookURL string) error
}

type HTTPDispatcher struct {
	Client     *http.Client
	MaxRetries int
}

func NewHTTPDispatcher() *HTTPDispatcher {
	return &HTTPDispatcher{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		MaxRetries: 3,
	}
}

// DispatchAlert sendet Alarme mit Exponential Backoff, Retry-Logik und strukturiertem Logging
func (d *HTTPDispatcher) DispatchAlert(ctx context.Context, tenantID string, message string, webhookURL string) error {
	if webhookURL == "" {
		slog.Error("webhook URL is missing for tenant", "tenant_id", tenantID)
		return fmt.Errorf("webhook URL is empty for tenant: %s", tenantID)
	}

	payload := TeamsMessage{
		Text: fmt.Sprintf("🚨 **SentinelCore Alert (Mandant: %s)**\n\n%s", tenantID, message),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal teams message", "tenant_id", tenantID, "error", err)
		return fmt.Errorf("failed to marshal teams message: %w", err)
	}

	var lastErr error
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= d.MaxRetries; attempt++ {
		// Kontext-Abbruch vor jedem Versuch prüfen (Security/Resilience)
		if err := ctx.Err(); err != nil {
			slog.Warn("context cancelled before dispatch attempt", "tenant_id", tenantID, "attempt", attempt, "error", err)
			return fmt.Errorf("context cancelled before dispatch attempt %d: %w", attempt, err)
		}

		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewBuffer(data))
		if err != nil {
			cancel()
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := d.Client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			slog.Warn("webhook dispatch attempt failed, initiating retry",
				"tenant_id", tenantID,
				"attempt", attempt,
				"max_retries", d.MaxRetries,
				"error", err,
			)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		// Body sicher schließen
		resp.Body.Close()
		cancel()

		if resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("webhook returned error status code: %d", resp.StatusCode)
			slog.Warn("webhook returned non-success status code",
				"tenant_id", tenantID,
				"status_code", resp.StatusCode,
				"attempt", attempt,
			)
			// Nur bei Serverfehlern (5xx) oder Rate Limits (429) wiederholen
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		slog.Info("alert successfully dispatched", "tenant_id", tenantID, "attempt", attempt)
		return nil
	}

	slog.Error("all webhook dispatch retry attempts failed", "tenant_id", tenantID, "error", lastErr)
	return fmt.Errorf("all %d retry attempts failed: %w", d.MaxRetries, lastErr)
}
