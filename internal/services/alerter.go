package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type AlertPayload struct {
	NodeID     string    `json:"node_id"`
	CustomerID int       `json:"customer_id"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	Timestamp  time.Time `json:"timestamp"`
}

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
}

func StartAlertEngine() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			checkThresholds()
			checkDeadAgents()
		}
	}()
}

func checkThresholds() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT n.node_id, COALESCE(n.customer_id, 0), n.cpu_usage_pct, n.ram_usage_pct
		FROM node_metrics n
		WHERE n.recorded_at >= NOW() - INTERVAL '2 minutes'
		  AND (n.cpu_usage_pct > 90.0 OR n.ram_usage_pct > 95.0)
	`
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		slog.Error("Threshold query failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var tenantID int
		var cpu, ram float64
		if err := rows.Scan(&nodeID, &tenantID, &cpu, &ram); err != nil {
			slog.Error("Failed to scan threshold row", "error", err)
			continue
		}

		slog.Warn("ALERT: Critical system load detected!", "node_id", nodeID, "cpu", cpu, "ram", ram)

		dispatchAlertToIntegrations(tenantID, AlertPayload{
			NodeID:     nodeID,
			CustomerID: tenantID,
			Metric:     "CPU/RAM",
			Value:      cpu,
			Severity:   "CRITICAL",
			Message:    fmt.Sprintf("Critical load: CPU %.1f%%, RAM %.1f%%", cpu, ram),
			Timestamp:  time.Now().UTC(),
		})
	}
}

func checkDeadAgents() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT node_id, COALESCE(customer_id, 0), MAX(recorded_at) as last_seen
		FROM node_metrics
		GROUP BY node_id, customer_id
		HAVING MAX(recorded_at) < NOW() - INTERVAL '10 minutes'
	`
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		slog.Error("Dead agents query failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var tenantID int
		var lastSeen time.Time
		if err := rows.Scan(&nodeID, &tenantID, &lastSeen); err != nil {
			slog.Error("Failed to scan dead agent row", "error", err)
			continue
		}

		slog.Error("ALERT: Agent is offline!", "node_id", nodeID, "last_seen", lastSeen)

		dispatchAlertToIntegrations(tenantID, AlertPayload{
			NodeID:     nodeID,
			CustomerID: tenantID,
			Metric:     "HEARTBEAT",
			Value:      0,
			Severity:   "ERROR",
			Message:    fmt.Sprintf("Agent offline (last seen: %s)", lastSeen.Format(time.RFC3339)),
			Timestamp:  time.Now().UTC(),
		})
	}
}

func dispatchAlertToIntegrations(tenantID int, alert AlertPayload) {
	if tenantID == 0 {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		query := `
			SELECT integration_type, webhook_url, COALESCE(api_token, '') 
			FROM tenant_integrations 
			WHERE tenant_id = $1 AND is_active = TRUE
		`
		rows, err := db.Pool.Query(ctx, query, tenantID)
		if err != nil {
			slog.Error("Failed to load tenant integrations", "tenant_id", tenantID, "error", err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var cfg IntegrationConfig
			if err := rows.Scan(&cfg.Type, &cfg.WebhookURL, &cfg.APIToken); err != nil {
				slog.Error("Failed to scan integration config", "error", err)
				continue
			}

			if err := executeConnector(ctx, cfg, alert); err != nil {
				slog.Warn("Integration dispatch failed",
					"tenant_id", tenantID,
					"type", cfg.Type,
					"error", err,
				)
			}
		}
	}()
}

func executeConnector(ctx context.Context, cfg IntegrationConfig, alert AlertPayload) error {
	switch cfg.Type {
	case "zammad":
		connector := &ZammadConnector{client: httpClient}
		return connector.Dispatch(ctx, alert, cfg)
	case "teams":
		connector := &TeamsConnector{client: httpClient}
		return connector.Dispatch(ctx, alert, cfg)
	default:
		return sendGenericWebhook(ctx, cfg.WebhookURL, alert)
	}
}

func sendGenericWebhook(ctx context.Context, url string, alert AlertPayload) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("generic webhook returned status: %d", resp.StatusCode)
	}
	return nil
}
