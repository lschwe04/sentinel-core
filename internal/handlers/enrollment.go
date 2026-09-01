package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sentinel-core/internal/db"
	"time"
)

type EnrollRequest struct {
	EnrollToken string `json:"enroll_token"`
	NodeID      string `json:"node_id"`
	CustomerID  int    `json:"customer_id"`
}

func HandleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// In Produktion: Validierung des EnrollTokens gegen eine Tenant-/Setup-Tabelle
	if req.EnrollToken != "systemhaus-master-secret-token" {
		http.Error(w, "Invalid enrollment token", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Initialen Hardening-Status für den neuen Node anlegen
	query := `
		INSERT INTO hardening_status (node_id, customer_id, cis_level_1_compliant, last_scan, open_issues)
		VALUES ($1, $2, false, CURRENT_TIMESTAMP, 0)
		ON CONFLICT (node_id) DO NOTHING
	`
	_, err := db.Pool.Exec(ctx, query, req.NodeID, req.CustomerID)
	if err != nil {
		http.Error(w, "Database error during enrollment", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "enrolled_successfully",
		"node_id": req.NodeID,
	})
}
