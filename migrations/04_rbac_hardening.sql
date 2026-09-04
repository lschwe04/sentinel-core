-- migrations/04_rbac_hardening.sql

-- 1. Rollen definieren
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(32) UNIQUE NOT NULL, -- z. B. 'msp_admin', 'client_admin', 'technician', 'viewer'
    description TEXT
);

-- 2. Feingranulare Berechtigungen
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    code VARCHAR(64) UNIQUE NOT NULL -- z. B. 'alerts:resolve', 'nodes:delete', 'integrations:write'
);

-- 3. M:N Verknüpfung Rolle <-> Berechtigung
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 4. User-Tabelle um Mandanten- und Rollenbezug erweitern
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS role_id INT REFERENCES roles(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, role_id);
