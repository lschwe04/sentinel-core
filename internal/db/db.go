package db

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InitDB gibt den Pool zurück, anstatt ihn global zu speichern.
func InitDB(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	if connStr == "" {
		return nil, fmt.Errorf("CRITICAL: DATABASE_URL fehlt")
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("konnte Datenbank-Konfiguration nicht parsen: %w", err)
	}

	config.MaxConns = 50
	config.MinConns = 10
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("verbindung zur Datenbank fehlgeschlagen: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("datenbank antwortet nicht: %w", err)
	}

	slog.Info("Erfolgreich mit PostgreSQL verbunden (Pool konfiguriert)", "max_conns", config.MaxConns)
	return pool, nil
}
