package db

import (
	"context"
	"log/slog"
	"time"
)

func RunMigrations() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	query := `
	CREATE TABLE IF NOT EXISTS tenants (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		slug VARCHAR(64) UNIQUE NOT NULL,
		logo_url TEXT,
		primary_color VARCHAR(7) DEFAULT '#2563eb',
		subscription_status VARCHAR(32) DEFAULT 'inactive',
		stripe_customer_id VARCHAR(255),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS customers (
		id SERIAL PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		name VARCHAR(255) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		id SERIAL PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		token_hash VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		is_used BOOLEAN DEFAULT FALSE
	);

	CREATE TABLE IF NOT EXISTS node_metrics (
		id BIGSERIAL PRIMARY KEY,
		node_id VARCHAR(64) NOT NULL,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		cpu_usage_pct FLOAT NOT NULL,
		ram_usage_pct FLOAT NOT NULL,
		disk_usage_pct FLOAT NOT NULL,
		uptime_hours INT DEFAULT 0,
		recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS hardening_status (
		node_id VARCHAR(64) PRIMARY KEY,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		cis_level_1_compliant BOOLEAN DEFAULT FALSE,
		cis_level_2_compliant BOOLEAN DEFAULT FALSE,
		last_scan TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		open_issues INT DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS security_logs (
		id BIGSERIAL PRIMARY KEY,
		node_id VARCHAR(64) NOT NULL,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		severity VARCHAR(16),
		source VARCHAR(32),
		message TEXT
	);

	-- Performance-Indizes für schnelle Dashboard-Queries unter Vollast
	CREATE INDEX IF NOT EXISTS idx_node_metrics_node_recorded ON node_metrics (node_id, recorded_at DESC);
	CREATE INDEX IF NOT EXISTS idx_security_logs_node ON security_logs (node_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_customers_tenant ON customers (tenant_id);
	`

	_, err := Pool.Exec(ctx, query)
	if err != nil {
		slog.Error("Fehler beim Ausführen der Datenbank-Migrationen", "error", err)
		return err
	}

	slog.Info("Datenbank-Migrationen & Indizes erfolgreich angewendet")
	return nil
}
