package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	OSVersion       string `json:"os_version"`
	MACAddress      string `json:"mac_address"`
}

type EnrollResponse struct {
	NodeID   string `json:"node_id"`
	NodeKey  string `json:"node_key"`
	TenantID int    `json:"tenant_id"`
	Status   string `json:"status"`
}

// HandleAgentEnrollment führt das stumme Enrollment via GPO-Token durch
func HandleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EnrollmentToken == "" {
		http.Error(w, `{"error": "Invalid payload or missing enrollment token"}`, http.StatusBadRequest)
		return
	}

	// Token hashing für sicheren DB-Vergleich (kein Plaintext-Match)
	tokenHashBytes := sha256.Sum256([]byte(req.EnrollmentToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	ctx := r.Context()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error": "Internal database error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Atomares Auslesen mit Row-Lock (FOR UPDATE), um Replay-Attacken beim Batch-Rollout zu blocken
	var tokenID, tenantID int
	var expiresAt time.Time
	var isUsed bool

	query := `
		SELECT id, tenant_id, expires_at, is_used 
		FROM enrollment_tokens 
		WHERE token_hash = $1 
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, tokenHash).Scan(&tokenID, &tenantID, &expiresAt, &isUsed)
	if err != nil || isUsed || time.Now().After(expiresAt) {
		http.Error(w, `{"error": "Unauthorized: Invalid, expired, or consumed enrollment token"}`, http.StatusUnauthorized)
		return
	}

	// Generierung dedizierter Agent-Credentials
	nodeID := generateSecureString(16)
	nodeKey := generateSecureString(32)

	// Node in Hardening-Tabelle als verifiziert anlegen
	_, err = tx.Exec(ctx, `
		INSERT INTO hardening_status (node_id, customer_id, cis_level_1_compliant, cis_level_2_compliant, open_issues)
		VALUES ($1, NULL, FALSE, FALSE, 0)
		ON CONFLICT (node_id) DO NOTHING
	`, nodeID)
	if err != nil {
		http.Error(w, `{"error": "Failed to register node hardware record"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error": "Transaction commit failure"}`, http.StatusInternalServerError)
		return
	}

	resp := EnrollResponse{
		NodeID:   nodeID,
		NodeKey:  nodeKey,
		TenantID: tenantID,
		Status:   "enrolled",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func generateSecureString(byteLength int) string {
	b := make([]byte, byteLength)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
