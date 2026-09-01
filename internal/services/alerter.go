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
}

// StartAlertEngine prüft periodisch, ob Nodes kritische Werte überschreiten
func StartAlertEngine() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			checkThresholds()
		}
	}()
}

func checkThresholds() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Beispiel: Finde Nodes, deren CPU in den letzten 2 Minuten über 90% lag
	query := `
		SELECT n.node_id, n.customer_id, n.cpu_usage_pct
		FROM node_metrics n
		WHERE n.recorded_at >= NOW() - INTERVAL '2 minutes'
		  AND n.cpu_usage_pct > 90.0
	`
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var customerID int
		var cpu float64
		if err := rows.Scan(&nodeID, &customerID, &cpu); err == nil {
			slog.Warn("ALERT: Hohe CPU-Auslastung erkannt!", "node_id", nodeID, "cpu_pct", cpu)

			// Hier könntest du einen Webhook an das Systemhaus triggern
			triggerSystemHouseWebhook(customerID, AlertPayload{
				NodeID:     nodeID,
				CustomerID: customerID,
				Metric:     "CPU_USAGE",
				Value:      cpu,
				Severity:   "HIGH",
			})
		}
	}
}

func triggerSystemHouseWebhook(_ int, payload AlertPayload) {
	// In Produktion: Hole die Webhook-URL des Tenants/Systemhauses aus der DB
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
