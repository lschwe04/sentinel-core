package db

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type MetricsRepository struct {
	pool *pgxpool.Pool
}

func NewMetricsRepository(pool *pgxpool.Pool) MetricsRepository {
	return MetricsRepository{pool: pool}
}

type MetricRecord struct {
	NodeID       string
	CPUUsagePct  float64
	RAMUsagePct  float64
	DiskUsagePct float64
	UptimeHours  int
	Timestamp    time.Time
}

func (r *MetricsRepository) Insert(ctx context.Context, tenantID string, nodeID string, cpu float64, ram float64, disk float64, uptime int, recordedAt time.Time) error {
	tID, err := strconv.Atoi(tenantID)
	if err != nil {
		return err
	}

	query := `INSERT INTO node_metrics (tenant_id, node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = r.pool.Exec(ctx, query, tID, nodeID, cpu, ram, disk, uptime, recordedAt)
	return err
}

func (r *MetricsRepository) Latest(ctx context.Context, tenantID string, nodeID string) (*MetricRecord, error) {
	tID, err := strconv.Atoi(tenantID)
	if err != nil {
		return nil, err
	}

	query := `SELECT node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, uptime_hours, recorded_at 
	          FROM node_metrics 
	          WHERE tenant_id = $1 AND node_id = $2 
	          ORDER BY recorded_at DESC LIMIT 1`

	row := r.pool.QueryRow(ctx, query, tID, nodeID)
	var m MetricRecord
	err = row.Scan(&m.NodeID, &m.CPUUsagePct, &m.RAMUsagePct, &m.DiskUsagePct, &m.UptimeHours, &m.Timestamp)
	if err != nil {
		return nil, err
	}
	return &m, nil
}
