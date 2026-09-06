package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"sentinel-core/internal/audit"
	"sentinel-core/internal/db"

	"github.com/jackc/pgx/v5"
)

const alertCooldown = 5 * time.Minute

func enqueueAlert(ctx context.Context, alert AlertPayload) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	dedup := fmt.Sprintf("%d:%s:%s:%s:%d", alert.TenantID, alert.NodeID, alert.Metric, alert.Severity, alert.Timestamp.Unix()/int64(alertCooldown/time.Second))
	return db.WithTenantTx(ctx, alert.TenantID, func(txCtx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(txCtx, `
			INSERT INTO alert_state (deduplication_key, tenant_id, status, last_seen, payload)
			VALUES ($1, $2, 'open', CURRENT_TIMESTAMP, $3)
			ON CONFLICT (deduplication_key) DO UPDATE SET status = 'open', last_seen = CURRENT_TIMESTAMP, payload = EXCLUDED.payload`,
			dedup, alert.TenantID, payload)
		if err != nil {
			return err
		}
		_, err = tx.Exec(txCtx, `
			INSERT INTO event_outbox (tenant_id, event_type, deduplication_key, payload)
			VALUES ($1, 'security.alert', $2, $3)
			ON CONFLICT (event_type, deduplication_key) DO NOTHING`, alert.TenantID, dedup, payload)
		return err
	})
}

func StartOutboxWorker() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			processOutbox(context.Background())
		}
	}()
}

func processOutbox(ctx context.Context) {
	workCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := db.Pool.Begin(workCtx)
	if err != nil {
		return
	}
	defer tx.Rollback(workCtx)
	var id, tenantID, attempts int
	var eventType string
	var payload []byte
	err = tx.QueryRow(workCtx, `
		WITH claimed AS (
			SELECT id FROM event_outbox
			WHERE status = 'pending' AND available_at <= CURRENT_TIMESTAMP
			ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE event_outbox e SET status = 'processing', locked_at = CURRENT_TIMESTAMP, attempts = attempts + 1
		FROM claimed WHERE e.id = claimed.id
		RETURNING e.id, e.tenant_id, e.event_type, e.attempts, e.payload`).Scan(&id, &tenantID, &eventType, &attempts, &payload)
	if err != nil {
		return
	}
	if err = tx.Commit(workCtx); err != nil {
		return
	}

	var deliveryErr error
	if eventType == "security.alert" {
		deliveryErr = deliverAlert(workCtx, tenantID, payload)
	} else if eventType == "audit.event" {
		deliveryErr = deliverAudit(workCtx, tenantID, payload)
	} else {
		deliveryErr = fmt.Errorf("unsupported outbox event type: %s", eventType)
	}
	if deliveryErr == nil {
		_, _ = db.Pool.Exec(workCtx, `UPDATE event_outbox SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP WHERE id = $1`, id)
		return
	}
	if attempts >= 5 {
		_, _ = db.Pool.Exec(workCtx, `
			WITH moved AS (UPDATE event_outbox SET status = 'dead', last_error = $2 WHERE id = $1 RETURNING id, tenant_id, payload)
			INSERT INTO event_dead_letters (outbox_id, tenant_id, payload, error) SELECT id, tenant_id, payload, $2 FROM moved`, id, deliveryErr.Error())
		return
	}
	backoff := time.Duration(1<<uint(attempts-1)) * time.Second
	_, _ = db.Pool.Exec(workCtx, `UPDATE event_outbox SET status = 'pending', available_at = CURRENT_TIMESTAMP + $2::interval, last_error = $3 WHERE id = $1`, id, fmt.Sprintf("%f seconds", backoff.Seconds()), deliveryErr.Error())
}

type auditEvent struct {
	Action  string         `json:"action"`
	Actor   string         `json:"actor"`
	NodeID  string         `json:"node_id"`
	Payload map[string]any `json:"payload"`
}

func deliverAudit(ctx context.Context, tenantID int, payload []byte) error {
	var event auditEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	return audit.NewLogger(db.Pool).LogEvent(ctx, fmt.Sprintf("%d", tenantID), event.Action, event.Actor, event.NodeID, event.Payload)
}

func deliverAlert(ctx context.Context, tenantID int, payload []byte) error {
	var alert AlertPayload
	if err := json.Unmarshal(payload, &alert); err != nil {
		return err
	}
	rows, err := db.Pool.Query(ctx, `SELECT integration_type, webhook_url, COALESCE(api_token, '') FROM tenant_integrations WHERE tenant_id = $1 AND is_active = TRUE`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var firstErr error
	for rows.Next() {
		var cfg IntegrationConfig
		if err := rows.Scan(&cfg.Type, &cfg.WebhookURL, &cfg.APIToken); err != nil {
			firstErr = err
			continue
		}
		if err := validateWebhookURL(cfg.WebhookURL); err != nil {
			firstErr = err
			continue
		}
		if err := executeConnector(ctx, cfg, alert); err != nil {
			firstErr = err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return firstErr
}

func validateWebhookURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return fmt.Errorf("webhook URL is not allowed")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return fmt.Errorf("webhook target is private")
	}
	resolved, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("webhook host cannot be resolved: %w", err)
	}
	for _, ip := range resolved {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("webhook resolves to private address")
		}
	}
	return nil
}
