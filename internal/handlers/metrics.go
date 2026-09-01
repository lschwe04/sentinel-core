package handlers

import (
	"encoding/json"
	"net/http"
)

type NodeMetrics struct {
	NodeID       string  `json:"node_id"`
	CPUUsagePct  float64 `json:"cpu_usage_pct"`
	RAMUsagePct  float64 `json:"ram_usage_pct"`
	DiskUsagePct float64 `json:"disk_usage_pct"`
	UptimeHours  int     `json:"uptime_hours"`
}

func GetMetrics(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	metrics := NodeMetrics{
		NodeID:       nodeID,
		CPUUsagePct:  8.2,
		RAMUsagePct:  34.5,
		DiskUsagePct: 52.1,
		UptimeHours:  720,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}
