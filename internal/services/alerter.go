package services

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sentinel-core/internal/db"
	"time"
)

type AlertPayload struct {
	NodeID     string  `json:"node_id"`
	CustomerID int     `json:"customer_id"`
	Metric     string  `json:"metric"`
	Value      float64 `json:"value"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
}

// StartAlertEngine prüft periodisch Schwellwerte und tote Agenten
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

	// Prüfe auf kritische CPU (> 90%) oder RAM (> 95%) in den letzten 2 Minuten
	query := `
		SELECT n.node_id, n.customer_id, n.cpu_usage_pct, n.ram_usage_pct
		FROM node_metrics n
		WHERE n.recorded_at >= NOW() - INTERVAL '2 minutes'
		  AND (n.cpu_usage_pct > 90.0 OR n.ram_usage_pct > 95.0)
	`
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var customerID int
		var cpu, ram float64
		if err := rows.Scan(&nodeID, &customerID, &cpu, &ram); err == nil {
			slog.Warn("ALERT: Hohe Systemlast erkannt!", "node_id", nodeID, "cpu", cpu, "ram", ram)
			triggerWebhook(customerID, AlertPayload{
				NodeID:     nodeID,
				CustomerID: customerID,
				Metric:     "SYSTEM_LOAD",
				Value:      cpu,
				Severity:   "HIGH",
				Message:    "CPU oder RAM Auslastung kritisch überschritten.",
			})
		}
	}
}

func checkDeadAgents() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Prüfe, ob ein Node seit mehr als 10 Minuten keine Metriken mehr gesendet hat
	query := `
		SELECT node_id, customer_id, MAX(recorded_at) as last_seen
		FROM node_metrics
		GROUP BY node_id, customer_id
		HAVING MAX(recorded_at) < NOW() - INTERVAL '10 minutes'
	`
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var customerID int
		var lastSeen time.Time
		if err := rows.Scan(&nodeID, &customerID, &lastSeen); err == nil {
			slog.Error("ALERT: Agent ist offline / unresponsive!", "node_id", nodeID, "last_seen", lastSeen)
			triggerWebhook(customerID, AlertPayload{
				NodeID:     nodeID,
				CustomerID: customerID,
				Metric:     "AGENT_OFFLINE",
				Value:      0,
				Severity:   "CRITICAL",
				Message:    "Keine Telemetriedaten seit über 10 Minuten empfangen.",
			})
		}
	}
}

func triggerWebhook(customerID int, payload AlertPayload) {
	// In Produktion: Hole die Webhook-URL des Kunden/Tenants aus der Datenbank
	webhookURL := "https://webhook.site/dein-test-endpoint"

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(data))
	if err == nil {
		resp.Body.Close()
	}
}
