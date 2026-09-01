package handlers

import (
	"encoding/json"
	"net/http"
)

type SystemMetrics struct {
	NodeID      string  `json:"node_id"`
	CPULoad     float64 `json:"cpu_load_percent"`
	RAMUsage    float64 `json:"ram_usage_percent"`
	DiskUsage   float64 `json:"disk_usage_percent"`
	NetworkTxMb float64 `json:"network_tx_mb"`
}

func GetMetrics(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")

	// Mock: In Produktion Weiterleitung der Anfrage an die lokale Prometheus-Instanz via API
	metrics := SystemMetrics{
		NodeID:      nodeID,
		CPULoad:     12.4,
		RAMUsage:    45.2,
		DiskUsage:   68.9,
		NetworkTxMb: 1024.5,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}
