package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type SecurityAlert struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
}

func GetSecurityLogs(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	query := `SELECT created_at, severity, source, message FROM security_logs WHERE node_id = $1 ORDER BY created_at DESC LIMIT 50`
	rows, err := db.Pool.Query(ctx, query, nodeID)
	if err != nil {
		http.Error(w, "Fehler beim Laden der Logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []SecurityAlert
	for rows.Next() {
		var alert SecurityAlert
		if err := rows.Scan(&alert.Timestamp, &alert.Severity, &alert.Source, &alert.Message); err == nil {
			alerts = append(alerts, alert)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"node_id": nodeID,
		"alerts":  alerts,
	})
}
