package db

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type MetricsRepository struct{}

func (MetricsRepository) Insert(ctx context.Context, tenantID, nodeID string, cpu, ram, disk float64, uptime int, recordedAt time.Time) error {
	if tenantID == "" || nodeID == "" {
		return fmt.Errorf("tenant ID and node ID are required")
	}
	return withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO node_metrics (tenant_id, node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, tenantID, nodeID, cpu, ram, disk, uptime, recordedAt.UTC())
		return err
	})
}

type Metric struct {
	NodeID       string
	CPUUsagePct  float64
	RAMUsagePct  float64
	DiskUsagePct float64
	UptimeHours  int
	Timestamp    time.Time
}

func (MetricsRepository) Latest(ctx context.Context, tenantID, nodeID string) (Metric, error) {
	var metric Metric
	err := withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
		SELECT node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at
		FROM node_metrics WHERE tenant_id = $1 AND node_id = $2
		ORDER BY recorded_at DESC LIMIT 1
		`, tenantID, nodeID).Scan(&metric.NodeID, &metric.CPUUsagePct, &metric.RAMUsagePct, &metric.DiskUsagePct, &metric.UptimeHours, &metric.Timestamp)
	})
	return metric, err
}

type AgentRepository struct{}

func (AgentRepository) Touch(ctx context.Context, tenantID, nodeID string) error {
	_, err := Pool.Exec(ctx, `UPDATE agent_credentials SET last_seen = CURRENT_TIMESTAMP WHERE tenant_id = $1 AND node_id = $2`, tenantID, nodeID)
	return err
}

func withTenant(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	id, err := strconv.Atoi(tenantID)
	if err != nil || id < 1 {
		return fmt.Errorf("invalid tenant ID")
	}
	return WithTenantTx(ctx, id, func(_ context.Context, tx pgx.Tx) error { return fn(tx) })
}
