package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/auth"
	"sentinel-core/internal/db"
	"sentinel-core/internal/observability"
)

type NodeMetrics struct {
	NodeID       string    `json:"node_id"`
	CPUUsagePct  float64   `json:"cpu_usage_pct"`
	RAMUsagePct  float64   `json:"ram_usage_pct"`
	DiskUsagePct float64   `json:"disk_usage_pct"`
	UptimeHours  int       `json:"uptime_hours"`
	Timestamp    time.Time `json:"timestamp"`
}

var metricsRepository db.MetricsRepository

func IngestMetrics(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
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
	tenantID, ok := r.Context().Value(auth.AuthenticatedTenantKey).(string)
	if !ok || tenantID == "" {
		http.Error(w, `{"error":"authenticated tenant context is required"}`, http.StatusForbidden)
		return
	}

	// Scalability: Reduzierter Timeout für schnelles Failover bei DB-Locking
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	err := metricsRepository.Insert(ctx, tenantID, metrics.NodeID, metrics.CPUUsagePct, metrics.RAMUsagePct, metrics.DiskUsagePct, metrics.UptimeHours, time.Now().UTC())
	if err != nil {
		http.Error(w, `{"error": "Database storage error"}`, http.StatusInternalServerError)
		return
	}
	observability.MetricIngested(time.Since(started))

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
	tenantID, ok := r.Context().Value(auth.AuthenticatedTenantKey).(string)
	if !ok || tenantID == "" {
		http.Error(w, `{"error":"authenticated tenant context is required"}`, http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	metric, err := metricsRepository.Latest(ctx, tenantID, nodeID)

	if err != nil {
		http.Error(w, `{"error": "No metrics found for node"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(NodeMetrics{NodeID: metric.NodeID, CPUUsagePct: metric.CPUUsagePct, RAMUsagePct: metric.RAMUsagePct, DiskUsagePct: metric.DiskUsagePct, UptimeHours: metric.UptimeHours, Timestamp: metric.Timestamp})
}
