package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sentinel-core/internal/db"
	"time"
)

type SecurityLogPayload struct {
	NodeID     string `json:"node_id"`
	CustomerID int    `json:"customer_id"`
	Severity   string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Source     string `json:"source"`   // e.g., "ssh", "kernel", "packages"
	Message    string `json:"message"`
}

func HandleSecurityLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload SecurityLogPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	query := `
		INSERT INTO security_logs (node_id, customer_id, severity, source, message, created_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
	`
	_, err := db.Pool.Exec(ctx, query, payload.NodeID, payload.CustomerID, payload.Severity, payload.Source, payload.Message)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged"})
}
