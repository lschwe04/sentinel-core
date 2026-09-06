-- Enterprise tenant isolation, outbox delivery and durable alert state.
BEGIN;

ALTER TABLE node_metrics ADD COLUMN IF NOT EXISTS tenant_id INT;
ALTER TABLE security_logs ADD COLUMN IF NOT EXISTS tenant_id INT;
ALTER TABLE hardening_status ADD COLUMN IF NOT EXISTS tenant_id INT;

UPDATE node_metrics n
SET tenant_id = a.tenant_id
FROM agent_credentials a
WHERE n.tenant_id IS NULL AND n.node_id = a.node_id;

UPDATE security_logs s
SET tenant_id = a.tenant_id
FROM agent_credentials a
WHERE s.tenant_id IS NULL AND s.node_id = a.node_id;

UPDATE hardening_status h
SET tenant_id = a.tenant_id
FROM agent_credentials a
WHERE h.tenant_id IS NULL AND h.node_id = a.node_id;

CREATE INDEX IF NOT EXISTS idx_node_metrics_tenant_time ON node_metrics (tenant_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_logs_tenant_time ON security_logs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hardening_tenant_node ON hardening_status (tenant_id, node_id);

ALTER TABLE node_metrics DROP CONSTRAINT IF EXISTS node_metrics_tenant_fk;
ALTER TABLE node_metrics ADD CONSTRAINT node_metrics_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE security_logs DROP CONSTRAINT IF EXISTS security_logs_tenant_fk;
ALTER TABLE security_logs ADD CONSTRAINT security_logs_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE hardening_status DROP CONSTRAINT IF EXISTS hardening_status_tenant_fk;
ALTER TABLE hardening_status ADD CONSTRAINT hardening_status_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE node_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE node_metrics FORCE ROW LEVEL SECURITY;
ALTER TABLE security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE hardening_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardening_status FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS node_metrics_tenant_isolation ON node_metrics;
CREATE POLICY node_metrics_tenant_isolation ON node_metrics
USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INT)
WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INT);
DROP POLICY IF EXISTS security_logs_tenant_isolation ON security_logs;
CREATE POLICY security_logs_tenant_isolation ON security_logs
USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INT)
WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INT);
DROP POLICY IF EXISTS hardening_status_tenant_isolation ON hardening_status;
CREATE POLICY hardening_status_tenant_isolation ON hardening_status
USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INT)
WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::INT);

CREATE TABLE IF NOT EXISTS event_outbox (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    deduplication_key VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (event_type, deduplication_key)
);
ALTER TABLE event_outbox ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
ALTER TABLE event_outbox ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_event_outbox_delivery ON event_outbox (status, available_at, id);

CREATE TABLE IF NOT EXISTS alert_state (
    deduplication_key VARCHAR(255) PRIMARY KEY,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_delivered_at TIMESTAMPTZ,
    recovery_at TIMESTAMPTZ,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS event_dead_letters (
    id BIGSERIAL PRIMARY KEY,
    outbox_id BIGINT NOT NULL REFERENCES event_outbox(id) ON DELETE CASCADE,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    error TEXT NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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

COMMIT;