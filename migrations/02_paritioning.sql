-- sentinel-core: migrations/02_partitioning.sql (Neu)
-- Konvertierung der node_metrics in eine partitionierte Tabelle
CREATE TABLE node_metrics_partitioned (
    node_id VARCHAR(64) NOT NULL,
    customer_id INT NOT NULL,
    cpu_usage_pct FLOAT NOT NULL,
    ram_usage_pct FLOAT NOT NULL,
    disk_usage_pct FLOAT NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (node_id, recorded_at)
) PARTITION BY RANGE (recorded_at);

-- Erstellung der initialen Partition
CREATE TABLE node_metrics_y2026m09 PARTITION OF node_metrics_partitioned
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
