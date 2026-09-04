package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func InitDB() error {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		return fmt.Errorf("CRITICAL: DATABASE_URL Umgebungsvariable fehlt")
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("konnte Datenbank-Konfiguration nicht parsen: %w", err)
	}

	// Performance-Tunings für Hochlast (Skalierbarkeit NR2)
	config.MaxConns = 50
	config.MinConns = 10
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	Pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("verbindung zur Datenbank fehlgeschlagen: %w", err)
	}

	if err := Pool.Ping(ctx); err != nil {
		return fmt.Errorf("datenbank antwortet nicht: %w", err)
	}

	slog.Info("Erfolgreich mit PostgreSQL verbunden (Pool konfiguriert)", "max_conns", config.MaxConns)
	return nil
}

func CloseDB() {
	if Pool != nil {
		Pool.Close()
		slog.Info("Datenbank-Pool geschlossen.")
	}
}
