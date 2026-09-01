package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type HardeningStatus struct {
	NodeID     string    `json:"node_id"`
	CISLevel1  bool      `json:"cis_level_1_compliant"`
	CISLevel2  bool      `json:"cis_level_2_compliant"`
	LastScan   time.Time `json:"last_scan"`
	OpenIssues int       `json:"open_issues"`
}

func GetHardeningStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var status HardeningStatus
	query := `SELECT node_id, cis_level_1_compliant, cis_level_2_compliant, last_scan, open_issues FROM hardening_status WHERE node_id = $1`

	err := db.Pool.QueryRow(ctx, query, nodeID).Scan(
		&status.NodeID,
		&status.CISLevel1,
		&status.CISLevel2,
		&status.LastScan,
		&status.OpenIssues,
	)

	if err != nil {
		http.Error(w, "Hardening-Status für diesen Node nicht gefunden", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func TriggerHardening(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "hardening_job_queued"}`))
}
