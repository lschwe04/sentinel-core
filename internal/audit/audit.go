package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditEntry struct {
	ID          int64     `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Action      string    `json:"action"` // z. B. "ANSIBLE_HARDENING_TRIGGER"
	Actor       string    `json:"actor"`  // User-Email oder Service-ID
	NodeID      string    `json:"node_id"`
	PayloadJSON string    `json:"payload"`
	PrevHash    string    `json:"prev_hash"`
	CurrentHash string    `json:"current_hash"`
	Timestamp   time.Time `json:"timestamp"`
}

type Logger struct {
	pool *pgxpool.Pool
}

func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{pool: pool}
}

// LogEvent schreibt einen fälschungssicheren, kryptografisch verketteten Audit-Log-Eintrag
func (l *Logger) LogEvent(ctx context.Context, tenantID, action, actor, nodeID string, payload map[string]any) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("audit payload marshal failed: %w", err)
	}

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Holen des vorherigen Hashes für genau diesen Mandanten (Locking erzwingen für Sequentialität)
	var lastHash string
	lastHashQuery := `
		SELECT current_hash 
		FROM audit_logs 
		WHERE tenant_id = $1 
		ORDER BY id DESC LIMIT 1 
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, lastHashQuery, tenantID).Scan(&lastHash)
	if err != nil {
		// Genesis Hash für den ersten Eintrag des Mandanten
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC()

	// Hasherstellung: SHA256(prev_hash + tenant_id + action + actor + node_id + payload + timestamp)
	dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		lastHash, tenantID, action, actor, nodeID, string(payloadBytes), now.Format(time.RFC3339Nano),
	)
	hashBytes := sha256.Sum256([]byte(dataToHash))
	currentHash := hex.EncodeToString(hashBytes[:])

	insertQuery := `
		INSERT INTO audit_logs (tenant_id, action, actor, node_id, payload, prev_hash, current_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err = tx.Exec(ctx, insertQuery, tenantID, action, actor, nodeID, string(payloadBytes), lastHash, currentHash, now)
	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return tx.Commit(ctx)
}

// VerifyTenantChain validiert die Integrität der gesamten Log-Kette eines Mandanten auf Fälschungen
func (l *Logger) VerifyTenantChain(ctx context.Context, tenantID string) (bool, error) {
	query := `
		SELECT id, tenant_id, action, actor, node_id, payload, prev_hash, current_hash, created_at 
		FROM audit_logs 
		WHERE tenant_id = $1 
		ORDER BY id ASC
	`
	rows, err := l.pool.Query(ctx, query, tenantID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	expectedPrevHash := "0000000000000000000000000000000000000000000000000000000000000000"

	for rows.Next() {
		var entry AuditEntry
		err := rows.Scan(
			&entry.ID, &entry.TenantID, &entry.Action, &entry.Actor,
			&entry.NodeID, &entry.PayloadJSON, &entry.PrevHash, &entry.CurrentHash, &entry.Timestamp,
		)
		if err != nil {
			return false, err
		}

		if entry.PrevHash != expectedPrevHash {
			return false, fmt.Errorf("tampering detected at record ID %d: prev_hash mismatch", entry.ID)
		}

		dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			entry.PrevHash, entry.TenantID, entry.Action, entry.Actor, entry.NodeID, entry.PayloadJSON, entry.Timestamp.UTC().Format(time.RFC3339Nano),
		)
		calculatedHashBytes := sha256.Sum256([]byte(dataToHash))
		calculatedHash := hex.EncodeToString(calculatedHashBytes[:])

		if calculatedHash != entry.CurrentHash {
			return false, fmt.Errorf("tampering detected at record ID %d: current_hash corrupted", entry.ID)
		}

		expectedPrevHash = entry.CurrentHash
	}

	return true, nil
}
