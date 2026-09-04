-- migrations/05_tenant_integrations.sql
CREATE TABLE IF NOT EXISTS tenant_integrations (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    integration_type VARCHAR(32) NOT NULL, -- z. B. 'zammad', 'teams', 'jira'
    webhook_url TEXT NOT NULL,
    api_token VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, integration_type)
);

CREATE INDEX idx_tenant_integrations_active ON tenant_integrations(tenant_id) WHERE is_active = TRUE;
