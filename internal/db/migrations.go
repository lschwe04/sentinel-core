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
	-- Erweiterungen für UUID-Generierung
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

	-- Basis-Mandantenstruktur
	CREATE TABLE IF NOT EXISTS tenants (
		id SERIAL PRIMARY KEY,
		parent_tenant_id INT REFERENCES tenants(id) ON DELETE RESTRICT,
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

	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	-- RBAC (Rollensystem)
	CREATE TABLE IF NOT EXISTS roles (
		id SERIAL PRIMARY KEY,
		name VARCHAR(32) UNIQUE NOT NULL,
		description TEXT
	);

	CREATE TABLE IF NOT EXISTS user_roles (
		user_id UUID NOT NULL,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		role_id INT REFERENCES roles(id) ON DELETE RESTRICT,
		PRIMARY KEY (user_id, tenant_id)
	);

	-- Agenten & Security
	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		id SERIAL PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		token_hash VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		is_used BOOLEAN DEFAULT FALSE
	);

	CREATE TABLE IF NOT EXISTS agent_credentials (
		node_id VARCHAR(64) PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		shared_secret_hash VARCHAR(64) NOT NULL,
		hostname VARCHAR(255) NOT NULL DEFAULT '',
		hardware_uuid VARCHAR(255) NOT NULL DEFAULT '',
		os_version VARCHAR(255) NOT NULL DEFAULT '',
		certificate_fingerprint VARCHAR(128),
		last_seen TIMESTAMP WITH TIME ZONE,
		status VARCHAR(32) NOT NULL DEFAULT 'active',
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS hostname VARCHAR(255) NOT NULL DEFAULT '';
	ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS hardware_uuid VARCHAR(255) NOT NULL DEFAULT '';
	ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS os_version VARCHAR(255) NOT NULL DEFAULT '';
	ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS certificate_fingerprint VARCHAR(128);
	ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE;
	ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'active';

	CREATE TABLE IF NOT EXISTS agent_commands (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		node_id VARCHAR(64) NOT NULL REFERENCES agent_credentials(node_id) ON DELETE CASCADE,
		tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		command_type VARCHAR(64) NOT NULL,
		payload JSONB NOT NULL DEFAULT '{}'::jsonb,
		status VARCHAR(16) NOT NULL DEFAULT 'pending',
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		delivered_at TIMESTAMP WITH TIME ZONE,
		acknowledged_at TIMESTAMP WITH TIME ZONE,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		result JSONB,
		CHECK (status IN ('pending', 'delivered', 'acknowledged', 'failed', 'expired'))
	);

	CREATE TABLE IF NOT EXISTS node_metrics (
		id BIGSERIAL PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		node_id VARCHAR(64) NOT NULL,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		cpu_usage_pct FLOAT NOT NULL,
		ram_usage_pct FLOAT NOT NULL,
		disk_usage_pct FLOAT NOT NULL,
		uptime_hours INT DEFAULT 0,
		recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	ALTER TABLE node_metrics ADD COLUMN IF NOT EXISTS tenant_id INT;

	CREATE TABLE IF NOT EXISTS event_outbox (
		id BIGSERIAL PRIMARY KEY,
		tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		event_type VARCHAR(64) NOT NULL,
		deduplication_key VARCHAR(255) NOT NULL,
		payload JSONB NOT NULL,
		status VARCHAR(16) NOT NULL DEFAULT 'pending',
		available_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		attempts INT NOT NULL DEFAULT 0,
		locked_at TIMESTAMP WITH TIME ZONE,
		delivered_at TIMESTAMP WITH TIME ZONE,
		last_error TEXT,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(event_type, deduplication_key)
	);
	ALTER TABLE event_outbox ADD COLUMN IF NOT EXISTS locked_at TIMESTAMP WITH TIME ZONE;
	ALTER TABLE event_outbox ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP WITH TIME ZONE;

	CREATE TABLE IF NOT EXISTS alert_state (
		deduplication_key VARCHAR(255) PRIMARY KEY,
		tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		status VARCHAR(16) NOT NULL DEFAULT 'open',
		first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_delivered_at TIMESTAMP WITH TIME ZONE,
		recovery_at TIMESTAMP WITH TIME ZONE,
		payload JSONB NOT NULL DEFAULT '{}'::jsonb
	);

	CREATE TABLE IF NOT EXISTS event_dead_letters (
		id BIGSERIAL PRIMARY KEY,
		outbox_id BIGINT NOT NULL REFERENCES event_outbox(id) ON DELETE CASCADE,
		tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		payload JSONB NOT NULL,
		error TEXT NOT NULL,
		failed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id BIGSERIAL PRIMARY KEY,
		tenant_id VARCHAR(64) NOT NULL,
		action VARCHAR(128) NOT NULL,
		actor VARCHAR(255) NOT NULL,
		node_id VARCHAR(128) NOT NULL DEFAULT '',
		payload JSONB NOT NULL DEFAULT '{}'::jsonb,
		prev_hash CHAR(64) NOT NULL,
		current_hash CHAR(64) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_tenant_hash ON audit_logs(tenant_id, current_hash);
	CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger AS $$
	BEGIN
		RAISE EXCEPTION 'audit logs are append-only';
	END;
	$$ LANGUAGE plpgsql;
	DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;
	CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
	ALTER TABLE node_metrics ENABLE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS node_metrics_tenant_isolation ON node_metrics;
	CREATE POLICY node_metrics_tenant_isolation ON node_metrics
		USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INTEGER)
		WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INTEGER);

	CREATE TABLE IF NOT EXISTS hardening_status (
		node_id VARCHAR(64) PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		cis_level_1_compliant BOOLEAN DEFAULT FALSE,
		cis_level_2_compliant BOOLEAN DEFAULT FALSE,
		last_scan TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		open_issues INT DEFAULT 0
	);
	ALTER TABLE hardening_status ADD COLUMN IF NOT EXISTS tenant_id INT;
	ALTER TABLE hardening_status DROP CONSTRAINT IF EXISTS hardening_status_tenant_fk;
	ALTER TABLE hardening_status ADD CONSTRAINT hardening_status_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

	CREATE TABLE IF NOT EXISTS security_logs (
		id BIGSERIAL PRIMARY KEY,
		node_id VARCHAR(64) NOT NULL,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		customer_id INT REFERENCES customers(id) ON DELETE CASCADE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		severity VARCHAR(16),
		source VARCHAR(32),
		message TEXT
	);
	ALTER TABLE security_logs ADD COLUMN IF NOT EXISTS tenant_id INT;
	ALTER TABLE security_logs DROP CONSTRAINT IF EXISTS security_logs_tenant_fk;
	ALTER TABLE security_logs ADD CONSTRAINT security_logs_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

	CREATE TABLE IF NOT EXISTS backups (
		node_id VARCHAR(64) PRIMARY KEY,
		last_snapshot TIMESTAMP WITH TIME ZONE NOT NULL,
		status VARCHAR(32) NOT NULL,
		s3_object_lock BOOLEAN NOT NULL DEFAULT FALSE,
		size_mb DOUBLE PRECISION NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS tenant_audit_logs (
		id BIGSERIAL PRIMARY KEY,
		tenant_id VARCHAR(64) NOT NULL,
		technician_email VARCHAR(255) NOT NULL,
		action VARCHAR(64) NOT NULL,
		target_node VARCHAR(64),
		ip_address INET NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS permissions (
		id SERIAL PRIMARY KEY,
		code VARCHAR(64) UNIQUE NOT NULL
	);

	CREATE TABLE IF NOT EXISTS role_permissions (
		role_id INT REFERENCES roles(id) ON DELETE CASCADE,
		permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
		PRIMARY KEY (role_id, permission_id)
	);

	CREATE TABLE IF NOT EXISTS tenant_integrations (
		id SERIAL PRIMARY KEY,
		tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
		integration_type VARCHAR(32) NOT NULL,
		webhook_url TEXT NOT NULL,
		api_token TEXT,
		is_active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(tenant_id, integration_type)
	);

	-- Tenantkritische Tabellen muessen auch bei versehentlichen Pool-Zugriffen isoliert bleiben.
	ALTER TABLE hardening_status ENABLE ROW LEVEL SECURITY;
	ALTER TABLE hardening_status FORCE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS hardening_status_tenant_isolation ON hardening_status;
	CREATE POLICY hardening_status_tenant_isolation ON hardening_status
		USING (tenant_id::text = current_setting('app.tenant_id', true))
		WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
	ALTER TABLE security_logs ENABLE ROW LEVEL SECURITY;
	ALTER TABLE security_logs FORCE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS security_logs_tenant_isolation ON security_logs;
	CREATE POLICY security_logs_tenant_isolation ON security_logs
		USING (tenant_id::text = current_setting('app.tenant_id', true))
		WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
	ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;
	ALTER TABLE agent_commands FORCE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS agent_commands_tenant_isolation ON agent_commands;
	CREATE POLICY agent_commands_tenant_isolation ON agent_commands
		USING (tenant_id::text = current_setting('app.tenant_id', true))
		WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
	ALTER TABLE event_outbox ENABLE ROW LEVEL SECURITY;
	ALTER TABLE event_outbox FORCE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS event_outbox_tenant_isolation ON event_outbox;
	CREATE POLICY event_outbox_tenant_isolation ON event_outbox
		USING (tenant_id::text = current_setting('app.tenant_id', true))
		WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
	ALTER TABLE alert_state ENABLE ROW LEVEL SECURITY;
	ALTER TABLE alert_state FORCE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS alert_state_tenant_isolation ON alert_state;
	CREATE POLICY alert_state_tenant_isolation ON alert_state
		USING (tenant_id::text = current_setting('app.tenant_id', true))
		WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
	ALTER TABLE event_dead_letters ENABLE ROW LEVEL SECURITY;
	ALTER TABLE event_dead_letters FORCE ROW LEVEL SECURITY;
	DROP POLICY IF EXISTS event_dead_letters_tenant_isolation ON event_dead_letters;
	CREATE POLICY event_dead_letters_tenant_isolation ON event_dead_letters
		USING (tenant_id::text = current_setting('app.tenant_id', true))
		WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

	-- Seed: Systemhaus-Standardrollen
	INSERT INTO roles (name, description) VALUES
		('syshaus_admin', 'Vollzugriff auf Systemhaus- und Mandanten-Ebene'),
		('syshaus_tech', 'Techniker mit Lese- und Schreibrechten für Kundensysteme'),
		('customer_view', 'Lesezugriff beschränkt auf spezifische Endkunden')
	ON CONFLICT (name) DO NOTHING;

	-- Performance- & Relations-Indizes
	CREATE INDEX IF NOT EXISTS idx_customers_tenant ON customers (tenant_id);
	CREATE INDEX IF NOT EXISTS idx_user_roles_lookup ON user_roles (user_id, tenant_id);
	CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant ON enrollment_tokens (tenant_id);
	CREATE INDEX IF NOT EXISTS idx_node_metrics_node_recorded ON node_metrics (node_id, recorded_at DESC);
	CREATE INDEX IF NOT EXISTS idx_node_metrics_customer ON node_metrics (customer_id);
	CREATE INDEX IF NOT EXISTS idx_security_logs_node ON security_logs (node_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_security_logs_customer ON security_logs (customer_id);
	CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON tenant_audit_logs (tenant_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_tenant_integrations_active ON tenant_integrations (tenant_id) WHERE is_active = TRUE;
	CREATE INDEX IF NOT EXISTS idx_agent_commands_poll ON agent_commands (node_id, status, expires_at);
	`

	_, err := Pool.Exec(ctx, query)
	if err != nil {
		slog.Error("Fehler beim Ausführen der Datenbank-Migrationen", "error", err)
		return err
	}

	slog.Info("Datenbank-Migrationen, RBAC-Initialisierung & Indizes erfolgreich angewendet")
	return nil
}
