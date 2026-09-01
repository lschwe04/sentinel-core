package db

import (
	"context"
	"log/slog"
	"time"
)

func RunMigrations() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
	CREATE TABLE IF NOT EXISTS hardening_status (
		node_id VARCHAR(64) PRIMARY KEY,
		cis_level_1_compliant BOOLEAN DEFAULT FALSE,
		cis_level_2_compliant BOOLEAN DEFAULT FALSE,
		last_scan TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		open_issues INT DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS security_logs (
		id SERIAL PRIMARY KEY,
		node_id VARCHAR(64) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		severity VARCHAR(16),
		source VARCHAR(32),
		message TEXT
	);
	`

	_, err := Pool.Exec(ctx, query)
	if err != nil {
		slog.Error("Fehler beim Ausführen der Datenbank-Migrationen", "error", err)
		return err
	}

	slog.Info("Datenbank-Migrationen erfolgreich abgeschlossen")
	return nil
}
