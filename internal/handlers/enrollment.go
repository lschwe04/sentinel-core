package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"sentinel-core/internal/db"
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

	expectedMasterToken := os.Getenv("SYSTEMHAUS_ENROLL_SECRET")
	if expectedMasterToken == "" {
		expectedMasterToken = "default-secure-enroll-key"
	}

	if req.EnrollToken != expectedMasterToken {
		http.Error(w, `{"error": "Invalid or expired enrollment token"}`, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO hardening_status (node_id, customer_id, cis_level_1_compliant, last_scan, open_issues)
		VALUES ($1, $2, false, CURRENT_TIMESTAMP, 0)
		ON CONFLICT (node_id) DO UPDATE SET last_scan = CURRENT_TIMESTAMP
	`
	_, err := db.Pool.Exec(ctx, query, req.NodeID, req.CustomerID)
	if err != nil {
		http.Error(w, `{"error": "Database error during enrollment"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "enrolled_successfully",
		"node_id": req.NodeID,
	})
}
