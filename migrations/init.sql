CREATE TABLE IF NOT EXISTS node_metrics (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    cpu_usage_pct FLOAT NOT NULL,
    ram_usage_pct FLOAT NOT NULL,
    disk_usage_pct FLOAT NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backups (
    node_id VARCHAR(64) PRIMARY KEY,
    last_snapshot TIMESTAMP WITH TIME ZONE,
    status VARCHAR(32),
    s3_object_lock BOOLEAN,
    size_mb FLOAT
);
