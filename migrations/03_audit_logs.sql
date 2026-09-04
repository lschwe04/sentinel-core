-- sentinel-core: migrations/03_audit_logs.sql (Neu)
CREATE TABLE IF NOT EXISTS tenant_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    technician_email VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_node VARCHAR(64),
    ip_address INET NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_tenant_time ON tenant_audit_logs (tenant_id, created_at DESC);
