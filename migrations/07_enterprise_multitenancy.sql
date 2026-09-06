-- Tenant ownership is explicit on all agent telemetry and supports MSP sub-customers.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS parent_tenant_id INTEGER REFERENCES tenants(id) ON DELETE RESTRICT;
ALTER TABLE node_metrics ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_tenants_parent ON tenants(parent_tenant_id);
CREATE INDEX IF NOT EXISTS idx_node_metrics_tenant_node ON node_metrics(tenant_id, node_id, recorded_at DESC);
ALTER TABLE node_metrics ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS node_metrics_tenant_isolation ON node_metrics;
CREATE POLICY node_metrics_tenant_isolation ON node_metrics
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INTEGER)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INTEGER);

-- Prevent destructive changes to the immutable audit chain.
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    node_id VARCHAR(128) NOT NULL DEFAULT '',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_tenant_hash ON audit_logs(tenant_id, current_hash);
CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit logs are append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;
CREATE TRIGGER audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();