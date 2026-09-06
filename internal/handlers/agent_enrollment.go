package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strconv"
	"time"

	"sentinel-core/internal/auth"
	"sentinel-core/internal/db"
)

type EnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	CSR             string `json:"csr"`
	Hostname        string `json:"hostname"`
	HardwareUUID    string `json:"hardware_uuid"`
	OSVersion       string `json:"os_version"`
}

type EnrollmentResponse struct {
	AgentID           string `json:"agent_id"`
	SharedSecret      string `json:"mTLS_shared_secret"`
	ClientCertificate string `json:"client_certificate,omitempty"`
	CACertificate     string `json:"ca_certificate,omitempty"`
	Status            string `json:"status"`
}

var agentSecurityManager *auth.SecurityManager

func ConfigureAgentSecurityManager(manager *auth.SecurityManager) {
	agentSecurityManager = manager
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
	if req.Hostname == "" || req.HardwareUUID == "" || req.CSR == "" {
		http.Error(w, `{"error": "hostname, hardware_uuid and csr are required"}`, http.StatusBadRequest)
		return
	}
	if len(req.Hostname) > 255 || len(req.HardwareUUID) > 255 || len(req.OSVersion) > 255 {
		http.Error(w, `{"error": "device metadata is too long"}`, http.StatusBadRequest)
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
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, strconv.Itoa(tenantID)); err != nil {
		http.Error(w, `{"error":"failed to establish tenant database context"}`, http.StatusInternalServerError)
		return
	}

	// Token als verbraucht markieren (Einmalverwendung erzwingen)
	_, err = tx.Exec(ctx, `UPDATE enrollment_tokens SET is_used = TRUE WHERE id = $1`, tokenID)
	if err != nil {
		http.Error(w, `{"error": "Failed to update token status"}`, http.StatusInternalServerError)
		return
	}

	// Die Node-ID ist zufällig und unveränderlich; Hardwaredaten dienen nur der Nachvollziehbarkeit.
	nodeIDBytes := make([]byte, 16)
	if _, err := rand.Read(nodeIDBytes); err != nil {
		http.Error(w, `{"error": "Failed to generate agent identity"}`, http.StatusInternalServerError)
		return
	}
	agentID := hex.EncodeToString(nodeIDBytes)

	// Kryptografisch sichere Zufallszahlen für das mTLS Shared Secret
	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, `{"error": "Failed to generate secure credentials"}`, http.StatusInternalServerError)
		return
	}
	sharedSecret := hex.EncodeToString(randBytes)
	sharedSecretHashBytes := sha256.Sum256([]byte(sharedSecret))
	sharedSecretHash := hex.EncodeToString(sharedSecretHashBytes[:])
	var certificateFingerprint string
	var clientCertificate, caCertificate string
	if agentSecurityManager != nil {
		certPEM, issueErr := agentSecurityManager.IssueAgentCertificateFromCSR(agentID, strconv.Itoa(tenantID), []byte(req.CSR), 30)
		if issueErr != nil {
			http.Error(w, `{"error": "Failed to issue client certificate"}`, http.StatusInternalServerError)
			return
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			http.Error(w, `{"error": "Failed to encode client certificate"}`, http.StatusInternalServerError)
			return
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			http.Error(w, `{"error": "Failed to parse client certificate"}`, http.StatusInternalServerError)
			return
		}
		fingerprint := sha256.Sum256(cert.Raw)
		certificateFingerprint = hex.EncodeToString(fingerprint[:])
		clientCertificate = base64.StdEncoding.EncodeToString(certPEM)
		caCertificate = base64.StdEncoding.EncodeToString([]byte(os.Getenv("CA_CERT_PEM")))
	}

	// Agent in Datenbank persistieren
	_, err = tx.Exec(ctx, `
		INSERT INTO hardening_status (node_id, tenant_id, customer_id, cis_level_1_compliant, cis_level_2_compliant, open_issues)
		VALUES ($1, $2, NULL, FALSE, FALSE, 0)
		ON CONFLICT (node_id) DO NOTHING
	`, agentID, tenantID)
	if err != nil {
		http.Error(w, `{"error": "Database error registering agent hardware record"}`, http.StatusInternalServerError)
		return
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_credentials (node_id, tenant_id, shared_secret_hash, hostname, hardware_uuid, os_version, certificate_fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
	`, agentID, tenantID, sharedSecretHash, req.Hostname, req.HardwareUUID, req.OSVersion, certificateFingerprint)
	if err != nil {
		http.Error(w, `{"error": "Database error storing agent credentials"}`, http.StatusInternalServerError)
		return
	}
	auditPayload, err := json.Marshal(map[string]any{
		"action": "AGENT_ENROLL", "actor": "agent-enrollment", "node_id": agentID,
		"payload": map[string]any{"hostname": req.Hostname, "hardware_uuid": req.HardwareUUID},
	})
	if err != nil {
		http.Error(w, `{"error":"audit event failed"}`, http.StatusInternalServerError)
		return
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO event_outbox (tenant_id, event_type, deduplication_key, payload)
		VALUES ($1, 'audit.event', $2, $3) ON CONFLICT (event_type, deduplication_key) DO NOTHING
	`, tenantID, "agent-enroll:"+agentID, auditPayload); err != nil {
		http.Error(w, `{"error":"audit event storage failed"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error": "Transaction commit failure"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(EnrollmentResponse{
		AgentID:           agentID,
		SharedSecret:      sharedSecret,
		ClientCertificate: clientCertificate,
		CACertificate:     caCertificate,
		Status:            "ENROLLED",
	})
}
