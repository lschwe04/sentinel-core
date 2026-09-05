package handlers

import (
	"context"
	"crypto/rand"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EnrollmentToken == "" {
		http.Error(w, `{"error": "Invalid request payload or missing token"}`, http.StatusBadRequest)
		return
	}

	// Token Hashing zur sicheren Validierung gegen das Datenbankschema (token_hash)
	tokenHashBytes := sha256.Sum256([]byte(req.EnrollmentToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error": "Internal database error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	var tokenID int
	var tenantID int
	var isUsed bool
	var expiresAt time.Time

	query := `
		SELECT id, tenant_id, is_used, expires_at 
		FROM enrollment_tokens 
		WHERE token_hash = $1 
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, tokenHash).Scan(&tokenID, &tenantID, &isUsed, &expiresAt)
	if err != nil || isUsed || time.Now().After(expiresAt) {
		http.Error(w, `{"error": "Invalid, expired, or already consumed enrollment token"}`, http.StatusUnauthorized)
		return
	}

	// Token als verbraucht markieren (Einmalverwendung erzwingen)
	_, err = tx.Exec(ctx, `UPDATE enrollment_tokens SET is_used = TRUE WHERE id = $1`, tokenID)
	if err != nil {
		http.Error(w, `{"error": "Failed to update token status"}`, http.StatusInternalServerError)
		return
	}

	// Eindeutigen Agenten-ID via Hardware-Fingerprint generieren
	hasher := sha256.New()
	hasher.Write([]byte(req.HardwareUUID + req.Hostname))
	agentID := hex.EncodeToString(hasher.Sum(nil))[:16]

	// Kryptografisch sichere Zufallszahlen für das mTLS Shared Secret
	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, `{"error": "Failed to generate secure credentials"}`, http.StatusInternalServerError)
		return
	}
	sharedSecret := hex.EncodeToString(randBytes)

	// Agent in Datenbank persistieren
	_, err = tx.Exec(ctx, `
		INSERT INTO hardening_status (node_id, customer_id, cis_level_1_compliant, cis_level_2_compliant, open_issues)
		VALUES ($1, NULL, FALSE, FALSE, 0)
		ON CONFLICT (node_id) DO NOTHING
	`, agentID)
	if err != nil {
		http.Error(w, `{"error": "Database error registering agent hardware record"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error": "Transaction commit failure"}`, http.StatusInternalServerError)
		return
	}

	// Audit Log asynchron schreiben
	go func() {
		_, _ = db.Pool.Exec(context.Background(),
			`INSERT INTO security_logs (node_id, severity, source, message) VALUES ($1, $2, $3, $4)`,
			agentID, "INFO", "AGENT_ENROLL", "Neuer Endpunkt-Agent erfolgreich via Zero-Trust Hardware-Fingerprint registriert.",
		)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(EnrollmentResponse{
		AgentID:      agentID,
		SharedSecret: sharedSecret,
		Status:       "ENROLLED",
	})
}
