-- migrations/04_rbac_hardening.sql
BEGIN;

-- Granulare Berechtigungstabelle für spätere Detail-Rechte
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    code VARCHAR(64) UNIQUE NOT NULL, -- z.B. 'metrics:read', 'hardening:execute', 'tenant:write'
    description TEXT
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Indizes für Sub-Millisekunden RBAC Lookups
CREATE INDEX IF NOT EXISTS idx_user_roles_composite 
ON user_roles (user_id, tenant_id, role_id);

CREATE INDEX IF NOT EXISTS idx_user_roles_customer_isolation 
ON user_roles (tenant_id, customer_id) WHERE customer_id IS NOT NULL;

COMMIT;
