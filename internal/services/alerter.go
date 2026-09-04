package services

import (
	"context"
	"log/slog"
	"time"

	"sentinel-core/internal/db"
)

type AlertPayload struct {
	NodeID     string  `json:"node_id"`
	CustomerID int     `json:"customer_id"`
	Metric     string  `json:"metric"`
	Value      float64 `json:"value"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
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
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var customerID int
		var cpu, ram float64
		if err := rows.Scan(&nodeID, &customerID, &cpu, &ram); err == nil {
			slog.Warn("ALERT: Critical system load detected!", "node_id", nodeID, "cpu", cpu, "ram", ram)
		}
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
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID string
		var customerID int
		var lastSeen time.Time
		if err := rows.Scan(&nodeID, &customerID, &lastSeen); err == nil {
			slog.Error("ALERT: Agent is offline!", "node_id", nodeID, "last_seen", lastSeen)
		}
	}
}
