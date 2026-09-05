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

func IngestMetrics(w http.ResponseWriter, r *http.Request) {
	var metrics NodeMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, `{"error": "Invalid payload format"}`, http.StatusBadRequest)
		return
	}

	// Usability: Plausibilitätsprüfung der eingehenden Telemetrie
	if metrics.CPUUsagePct < 0 || metrics.CPUUsagePct > 100 || metrics.RAMUsagePct < 0 || metrics.RAMUsagePct > 100 {
		http.Error(w, `{"error": "Metrics out of logical bounds"}`, http.StatusUnprocessableEntity)
		return
	}

	// Scalability: Reduzierter Timeout für schnelles Failover bei DB-Locking
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	query := `
		INSERT INTO node_metrics (node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := db.Pool.Exec(ctx, query, metrics.NodeID, metrics.CPUUsagePct, metrics.RAMUsagePct, metrics.DiskUsagePct, metrics.UptimeHours, time.Now().UTC())
	if err != nil {
		http.Error(w, `{"error": "Database storage error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status": "metric_stored"}`))
}

func GetMetrics(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, `{"error": "node_id is required"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var m NodeMetrics
	query := `SELECT node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at FROM node_metrics WHERE node_id = $1 ORDER BY recorded_at DESC LIMIT 1`
	err := db.Pool.QueryRow(ctx, query, nodeID).Scan(&m.NodeID, &m.CPUUsagePct, &m.RAMUsagePct, &m.DiskUsagePct, &m.UptimeHours, &m.Timestamp)

	if err != nil {
		http.Error(w, `{"error": "No metrics found for node"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}
