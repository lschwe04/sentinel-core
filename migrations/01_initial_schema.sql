-- Base schema for the Docker demo database.
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

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS node_metrics (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    node_id VARCHAR(64) NOT NULL,
    customer_id INT,
    cpu_usage_pct FLOAT NOT NULL,
    ram_usage_pct FLOAT NOT NULL,
    disk_usage_pct FLOAT NOT NULL,
    uptime_hours INT DEFAULT 0,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backups (
    node_id VARCHAR(64) PRIMARY KEY,
    last_snapshot TIMESTAMP WITH TIME ZONE,
    status VARCHAR(32),
    s3_object_lock BOOLEAN,
    size_mb FLOAT
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

CREATE TABLE IF NOT EXISTS security_logs (
    id BIGSERIAL PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    customer_id INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(16),
    source VARCHAR(32),
    message TEXT
);

CREATE TABLE IF NOT EXISTS hardening_status (
    node_id VARCHAR(64) PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    customer_id INT,
    cis_level_1_compliant BOOLEAN DEFAULT FALSE,
    cis_level_2_compliant BOOLEAN DEFAULT FALSE,
    last_scan TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    open_issues INT DEFAULT 0
);