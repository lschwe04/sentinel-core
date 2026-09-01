package handlers

import (
	"encoding/json"
	"net/http"
)

type SecurityAlert struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Source    string `json:"source"` // z.B. "falco", "auditd"
	Message   string `json:"message"`
}

func GetSecurityLogs(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")

	// Mock: Normalerweise ein sicherer SELECT auf die Datenbank (z.B. pgxpool)
	alerts := []SecurityAlert{
		{
			Timestamp: "2026-09-01T19:10:00Z",
			Severity:  "CRITICAL",
			Source:    "falco",
			Message:   "Unauthorized bash execution detected in container",
		},
		{
			Timestamp: "2026-09-01T18:45:00Z",
			Severity:  "WARNING",
			Source:    "auditd",
			Message:   "Failed SSH login attempt",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"node_id": nodeID,
		"alerts":  alerts,
	})
}
