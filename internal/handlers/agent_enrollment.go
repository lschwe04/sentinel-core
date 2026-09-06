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
	"log/slog"
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

func logEnrollmentError(r *http.Request, operation string, err error) {
	slog.Error("agent enrollment failed", "operation", operation, "path", r.URL.Path, "error", err)
}

func ConfigureAgentSecurityManager(manager *auth.SecurityManager) {
	agentSecurityManager = manager
}

// HandleAgentEnrollment verarbeitet die Erstregistrierung eines neuen Endpunkt-Agenten
func HandleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAgentError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req EnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EnrollmentToken == "" {
		writeAgentError(w, http.StatusBadRequest, "invalid request payload or missing token")
		return
	}
	if req.Hostname == "" || req.HardwareUUID == "" || req.CSR == "" {
		writeAgentError(w, http.StatusBadRequest, "hostname, hardware_uuid and csr are required")
		return
	}
	if len(req.Hostname) > 255 || len(req.HardwareUUID) > 255 || len(req.OSVersion) > 255 {
		writeAgentError(w, http.StatusBadRequest, "device metadata is too long")
		return
	}

	// Token Hashing zur sicheren Validierung gegen das Datenbankschema (token_hash)
	tokenHashBytes := sha256.Sum256([]byte(req.EnrollmentToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		logEnrollmentError(r, "begin transaction", err)
		writeAgentError(w, http.StatusInternalServerError, "internal database error")
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
		writeAgentError(w, http.StatusUnauthorized, "invalid, expired, or already consumed enrollment token")
		return
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, strconv.Itoa(tenantID)); err != nil {
		logEnrollmentError(r, "set tenant context", err)
		writeAgentError(w, http.StatusInternalServerError, "failed to establish tenant database context")
		return
	}

	// Token als verbraucht markieren (Einmalverwendung erzwingen)
	_, err = tx.Exec(ctx, `UPDATE enrollment_tokens SET is_used = TRUE WHERE id = $1`, tokenID)
	if err != nil {
		logEnrollmentError(r, "consume enrollment token", err)
		writeAgentError(w, http.StatusInternalServerError, "failed to update token status")
		return
	}

	// Die Node-ID ist zufällig und unveränderlich; Hardwaredaten dienen nur der Nachvollziehbarkeit.
	nodeIDBytes := make([]byte, 16)
	if _, err := rand.Read(nodeIDBytes); err != nil {
		logEnrollmentError(r, "generate agent identity", err)
		writeAgentError(w, http.StatusInternalServerError, "failed to generate agent identity")
		return
	}
	agentID := hex.EncodeToString(nodeIDBytes)

	// Kryptografisch sichere Zufallszahlen für das mTLS Shared Secret
	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		logEnrollmentError(r, "generate shared secret", err)
		writeAgentError(w, http.StatusInternalServerError, "failed to generate secure credentials")
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
			logEnrollmentError(r, "issue client certificate", issueErr)
			writeAgentError(w, http.StatusInternalServerError, "failed to issue client certificate")
			return
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			writeAgentError(w, http.StatusInternalServerError, "failed to encode client certificate")
			return
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			logEnrollmentError(r, "parse client certificate", parseErr)
			writeAgentError(w, http.StatusInternalServerError, "failed to parse client certificate")
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
		logEnrollmentError(r, "register hardening record", err)
		writeAgentError(w, http.StatusInternalServerError, "database error registering agent hardware record")
		return
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_credentials (node_id, tenant_id, shared_secret_hash, hostname, hardware_uuid, os_version, certificate_fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
	`, agentID, tenantID, sharedSecretHash, req.Hostname, req.HardwareUUID, req.OSVersion, certificateFingerprint)
	if err != nil {
		logEnrollmentError(r, "store agent credentials", err)
		writeAgentError(w, http.StatusInternalServerError, "database error storing agent credentials")
		return
	}
	auditPayload, err := json.Marshal(map[string]any{
		"action": "AGENT_ENROLL", "actor": "agent-enrollment", "node_id": agentID,
		"payload": map[string]any{"hostname": req.Hostname, "hardware_uuid": req.HardwareUUID},
	})
	if err != nil {
		logEnrollmentError(r, "marshal audit event", err)
		writeAgentError(w, http.StatusInternalServerError, "audit event failed")
		return
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO event_outbox (tenant_id, event_type, deduplication_key, payload)
		VALUES ($1, 'audit.event', $2, $3) ON CONFLICT (event_type, deduplication_key) DO NOTHING
	`, tenantID, "agent-enroll:"+agentID, auditPayload); err != nil {
		logEnrollmentError(r, "store audit event", err)
		writeAgentError(w, http.StatusInternalServerError, "audit event storage failed")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logEnrollmentError(r, "commit enrollment", err)
		writeAgentError(w, http.StatusInternalServerError, "transaction commit failure")
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
