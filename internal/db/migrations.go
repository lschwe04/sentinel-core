package db

import (
	"context"
	"log/slog"
	"time"
)

func RunMigrations() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	CREATE TABLE IF NOT EXISTS node_metrics (
		id SERIAL PRIMARY KEY,
		node_id VARCHAR(64) NOT NULL,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		cpu_usage_pct FLOAT NOT NULL,
		ram_usage_pct FLOAT NOT NULL,
		disk_usage_pct FLOAT NOT NULL,
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
		id SERIAL PRIMARY KEY,
		node_id VARCHAR(64) NOT NULL,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		severity VARCHAR(16),
		source VARCHAR(32),
		message TEXT
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id SERIAL PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		actor VARCHAR(255) NOT NULL,
		action VARCHAR(128) NOT NULL,
		details TEXT,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := Pool.Exec(ctx, query)
	if err != nil {
		slog.Error("Fehler beim Ausführen der Mandanten-Migrationen", "error", err)
		return err
	}

	slog.Info("Mandanten-Datenbank-Migrationen erfolgreich abgeschlossen")
	return nil
}
