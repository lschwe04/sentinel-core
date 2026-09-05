package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentinel-core/internal/db"
)

type agentContext struct {
	nodeID   string
	tenantID int
}

type heartbeatRequest struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type telemetryRequest struct {
	CPUUsagePct  float64 `json:"cpu_usage_pct"`
	RAMUsagePct  float64 `json:"ram_usage_pct"`
	DiskUsagePct float64 `json:"disk_usage_pct"`
	UptimeHours  int     `json:"uptime_hours"`
}

type agentHardeningReport struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	OpenIssues int    `json:"open_issues"`
}

type agentCommand struct {
	ID          string          `json:"id"`
	CommandType string          `json:"command_type"`
	Payload     json.RawMessage `json:"payload"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

type commandAck struct {
	Status string                 `json:"status"`
	Result map[string]interface{} `json:"result,omitempty"`
}

func authenticateAgent(r *http.Request) (agentContext, error) {
	if r.TLS == nil && os.Getenv("ALLOW_INSECURE_AGENT_TRANSPORT") != "true" {
		return agentContext{}, errors.New("agent transport must use TLS")
	}
	nodeID := strings.TrimSpace(r.Header.Get("X-Agent-ID"))
	authHeader := r.Header.Get("Authorization")
	if nodeID == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return agentContext{}, errors.New("missing agent credentials")
	}
	secret := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if secret == "" {
		return agentContext{}, errors.New("missing agent secret")
	}
	secretHashBytes := sha256.Sum256([]byte(secret))
	secretHash := hex.EncodeToString(secretHashBytes[:])

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var tenantID int
	var storedFingerprint *string
	err := db.Pool.QueryRow(ctx, `
		SELECT tenant_id, certificate_fingerprint
		FROM agent_credentials
		WHERE node_id = $1 AND shared_secret_hash = $2 AND status = 'active'
	`, nodeID, secretHash).Scan(&tenantID, &storedFingerprint)
	if err != nil {
		return agentContext{}, errors.New("invalid agent credentials")
	}

	if storedFingerprint != nil && *storedFingerprint != "" {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return agentContext{}, errors.New("client certificate required")
		}
		fingerprint := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		actual := hex.EncodeToString(fingerprint[:])
		if subtle.ConstantTimeCompare([]byte(actual), []byte(*storedFingerprint)) != 1 {
			return agentContext{}, errors.New("client certificate mismatch")
		}
	}
	return agentContext{nodeID: nodeID, tenantID: tenantID}, nil
}

func RequireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := authenticateAgent(r)
		if err != nil {
			http.Error(w, `{"error":"unauthorized agent"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), agentContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type agentContextKey struct{}

func agentIdentity(r *http.Request) agentContext {
	return r.Context().Value(agentContextKey{}).(agentContext)
}

func HandleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity := agentIdentity(r)
	var request heartbeatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
		http.Error(w, `{"error":"invalid heartbeat"}`, http.StatusBadRequest)
		return
	}
	if request.Status == "" {
		request.Status = "healthy"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.Pool.Exec(ctx, `UPDATE agent_credentials SET last_seen = CURRENT_TIMESTAMP WHERE node_id = $1 AND tenant_id = $2`, identity.nodeID, identity.tenantID)
	if err != nil {
		http.Error(w, `{"error":"heartbeat storage failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "agent_status": request.Status})
}

func HandleAgentTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity := agentIdentity(r)
	var telemetry telemetryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&telemetry); err != nil {
		http.Error(w, `{"error":"invalid telemetry"}`, http.StatusBadRequest)
		return
	}
	if telemetry.CPUUsagePct < 0 || telemetry.CPUUsagePct > 100 || telemetry.RAMUsagePct < 0 || telemetry.RAMUsagePct > 100 || telemetry.DiskUsagePct < 0 || telemetry.DiskUsagePct > 100 || telemetry.UptimeHours < 0 {
		http.Error(w, `{"error":"telemetry values out of bounds"}`, http.StatusUnprocessableEntity)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO node_metrics (node_id, customer_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at)
		VALUES ($1, NULL, $2, $3, $4, $5, CURRENT_TIMESTAMP)
	`, identity.nodeID, telemetry.CPUUsagePct, telemetry.RAMUsagePct, telemetry.DiskUsagePct, telemetry.UptimeHours)
	if err != nil {
		http.Error(w, `{"error":"telemetry storage failed"}`, http.StatusInternalServerError)
		return
	}
	_, _ = db.Pool.Exec(ctx, `UPDATE agent_credentials SET last_seen = CURRENT_TIMESTAMP WHERE node_id = $1 AND tenant_id = $2`, identity.nodeID, identity.tenantID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func HandleAgentHardeningReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity := agentIdentity(r)
	var report agentHardeningReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&report); err != nil || report.OpenIssues < 0 {
		http.Error(w, `{"error":"invalid hardening report"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO hardening_status (node_id, cis_level_2_compliant, last_scan, open_issues)
		VALUES ($1, $2, CURRENT_TIMESTAMP, $3)
		ON CONFLICT (node_id) DO UPDATE SET cis_level_2_compliant = EXCLUDED.cis_level_2_compliant,
		last_scan = CURRENT_TIMESTAMP, open_issues = EXCLUDED.open_issues
	`, identity.nodeID, report.Success, report.OpenIssues)
	if err != nil {
		http.Error(w, `{"error":"hardening report storage failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func HandleAgentCommands(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity := agentIdentity(r)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"command storage failed"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)
	var command agentCommand
	err = tx.QueryRow(ctx, `
		SELECT id::text, command_type, payload, expires_at
		FROM agent_commands
		WHERE node_id = $1 AND tenant_id = $2 AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED LIMIT 1
	`, identity.nodeID, identity.tenantID).Scan(&command.ID, &command.CommandType, &command.Payload, &command.ExpiresAt)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_commands SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP WHERE id = $1`, command.ID); err != nil {
		http.Error(w, `{"error":"command delivery failed"}`, http.StatusInternalServerError)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"command delivery commit failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(command)
}

func HandleAgentCommandAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity := agentIdentity(r)
	commandID := strings.TrimPrefix(r.URL.Path, "/agent/v1/commands/")
	commandID = strings.TrimSuffix(commandID, "/ack")
	if commandID == "" || strings.Contains(commandID, "/") {
		http.Error(w, `{"error":"invalid command id"}`, http.StatusBadRequest)
		return
	}
	var ack commandAck
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&ack); err != nil || (ack.Status != "acknowledged" && ack.Status != "failed") {
		http.Error(w, `{"error":"invalid command acknowledgement"}`, http.StatusBadRequest)
		return
	}
	result, err := json.Marshal(ack.Result)
	if err != nil {
		http.Error(w, `{"error":"invalid command result"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	commandStatus := ack.Status
	var updated int
	err = db.Pool.QueryRow(ctx, `
		UPDATE agent_commands SET status = $1, result = $2, acknowledged_at = CURRENT_TIMESTAMP
		WHERE id = $3::uuid AND node_id = $4 AND tenant_id = $5 AND status = 'delivered'
		RETURNING 1
	`, commandStatus, result, commandID, identity.nodeID, identity.tenantID).Scan(&updated)
	if err != nil || updated != 1 {
		http.Error(w, `{"error":"command not found or already acknowledged"}`, http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func ServeAgentArtifact(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var envName string
		var filename string
		switch kind {
		case "linux":
			envName, filename = "AGENT_LINUX_BINARY", "sentinel-agent"
		case "windows":
			envName, filename = "AGENT_WINDOWS_BINARY", "sentinel-agent.exe"
		default:
			http.NotFound(w, r)
			return
		}
		path := os.Getenv(envName)
		if path == "" {
			path = filepath.Join("artifacts", filename)
		}
		path, err := filepath.Abs(path)
		if err != nil {
			http.Error(w, "artifact unavailable", http.StatusNotFound)
			return
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			http.Error(w, "artifact unavailable", http.StatusNotFound)
			return
		}
		file, err := os.Open(path)
		if err != nil {
			http.Error(w, "artifact unavailable", http.StatusNotFound)
			return
		}
		hash := sha256.New()
		_, hashErr := io.Copy(hash, file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			http.Error(w, "artifact unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("X-Checksum-SHA256", hex.EncodeToString(hash.Sum(nil)))
		http.ServeFile(w, r, path)
	}
}

func ServeInstaller(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		filename := map[string]string{"linux": "install-agent.sh", "windows": "install-agent.ps1"}[kind]
		if filename == "" {
			http.NotFound(w, r)
			return
		}
		baseDir := os.Getenv("AGENT_INSTALLER_DIR")
		if baseDir == "" {
			baseDir = "deployments"
		}
		path, err := filepath.Abs(filepath.Join(baseDir, kind, filename))
		if err != nil {
			http.Error(w, "installer unavailable", http.StatusNotFound)
			return
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			http.Error(w, "installer unavailable", http.StatusNotFound)
			return
		}
		if kind == "linux" {
			w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		http.ServeFile(w, r, path)
	}
}
