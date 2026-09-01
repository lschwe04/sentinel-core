package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type NodeMetrics struct {
	NodeID       string    `json:"node_id"`
	CPUUsagePct  float64   `json:"cpu_usage_pct"`
	RAMUsagePct  float64   `json:"ram_usage_pct"`
	DiskUsagePct float64   `json:"disk_usage_pct"`
	UptimeHours  int       `json:"uptime_hours"`
	Timestamp    time.Time `json:"timestamp"`
}

// IngestMetrics nimmt die Telemetriedaten des Agenten entgegen und speichert sie in PostgreSQL
func IngestMetrics(w http.ResponseWriter, r *http.Request) {
	var metrics NodeMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	query := `
		INSERT INTO node_metrics (node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := db.Pool.Exec(ctx, query, metrics.NodeID, metrics.CPUUsagePct, metrics.RAMUsagePct, metrics.DiskUsagePct, metrics.UptimeHours, time.Now())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status": "metric_stored"}`))
}

// GetMetrics liest die neuesten Metriken für einen Node aus der Datenbank aus
func GetMetrics(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var m NodeMetrics
	query := `SELECT node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at FROM node_metrics WHERE node_id = $1 ORDER BY recorded_at DESC LIMIT 1`
	err := db.Pool.QueryRow(ctx, query, nodeID).Scan(&m.NodeID, &m.CPUUsagePct, &m.RAMUsagePct, &m.DiskUsagePct, &m.UptimeHours, &m.Timestamp)
	if err != nil {
		// Fallback mit deinen Standard-Mockwerten, falls noch keine Daten da sind
		m = NodeMetrics{
			NodeID:       nodeID,
			CPUUsagePct:  8.2,
			RAMUsagePct:  34.5,
			DiskUsagePct: 52.1,
			UptimeHours:  720,
			Timestamp:    time.Now(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}
