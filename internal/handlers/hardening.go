package handlers

import (
	"encoding/json"
	"net/http"
)

type HardeningStatus struct {
	NodeID      string `json:"node_id"`
	CISLevel1   bool   `json:"cis_level_1_compliant"`
	CISLevel2   bool   `json:"cis_level_2_compliant"`
	LastScan    string `json:"last_scan"`
	OpenIssues  int    `json:"open_issues"`
}

func GetHardeningStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	// Mock-Daten für Datenbankabfrage (PostgreSQL)
	status := HardeningStatus{
		NodeID:     nodeID,
		CISLevel1:  true,
		CISLevel2:  false, // Level 2 oft strenger
		LastScan:   "2026-09-01T14:00:00Z",
		OpenIssues: 3,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func TriggerHardening(w http.ResponseWriter, r *http.Request) {
	// Hier würde der Hub den Agenten via gRPC/HTTP auf dem Wireguard Interface kontaktieren
	// um das lokale Ansible-Playbook zur Härtung zu triggern.
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "hardening_job_queued"}`))
}
