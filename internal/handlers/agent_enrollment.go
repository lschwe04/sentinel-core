package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type EnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	HardwareUUID    string `json:"hardware_uuid"`
	OSVersion       string `json:"os_version"`
}

type EnrollmentResponse struct {
	AgentID      string `json:"agent_id"`
	SharedSecret string `json:"mTLS_shared_secret"`
	Status       string `json:"status"`
}

// HandleAgentEnrollment verarbeitet die Erstregistrierung eines neuen Endpunkt-Agenten
func HandleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req EnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request payload"}`, http.StatusBadRequest)
		return
	}

	// 1. Prüfen ob das Enrollment-Token des Systemhauses gültig ist
	var customerID string
	var isValid bool
	err := db.Pool.QueryRow(ctx, `
		SELECT customer_id, is_active FROM enrollment_tokens WHERE token = $1
	`, req.EnrollmentToken).Scan(&customerID, &isValid)

	if err != nil || !isValid {
		http.Error(w, `{"error": "Invalid or expired system house enrollment token"}`, http.StatusUnauthorized)
		return
	}

	// 2. Eindeutigen Agenten-Hash generieren (Hardware-Fingerprint)
	hasher := sha256.New()
	hasher.Write([]byte(req.HardwareUUID + req.Hostname))
	agentID := hex.EncodeToString(hasher.Sum(nil))[:16]

	// Einmaliges mTLS-Secret für zukünftige Heartbeats erzeugen
	randBytes := make([]byte, 32)
	// (In Realimplementation crypto/rand nutzen)
	sharedSecret := hex.EncodeToString(randBytes)

	// 3. Agent in Datenbank persistieren
	_, err = db.Pool.Exec(ctx, `
		INSERT INTO registered_agents (agent_id, customer_id, hostname, os_version, hardware_uuid, secret_hash, status, registered_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', NOW())
		ON CONFLICT (agent_id) DO UPDATE 
		SET last_seen = NOW(), status = 'ACTIVE'
	`, agentID, customerID, req.Hostname, req.OSVersion, req.HardwareUUID, sharedSecret)

	if err != nil {
		http.Error(w, `{"error": "Database error registering agent"}`, http.StatusInternalServerError)
		return
	}

	// Audit Log für das Systemhaus
	go func() {
		_, _ = db.Pool.Exec(context.Background(),
			`INSERT INTO security_logs (node_id, severity, source, message) VALUES ($1, $2, $3, $4)`,
			agentID, "INFO", "AGENT_ENROLL", "Neuer Endpunkt-Agent erfolgreich via Zero-Trust Hardware-Fingerprint registriert.",
		)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(EnrollmentResponse{
		AgentID:      agentID,
		SharedSecret: sharedSecret,
		Status:       "ENROLLED",
	})
}
