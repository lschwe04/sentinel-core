package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func InitDB() error {
	ctx := context.Background()
	connStr := os.Getenv("DATABASE_URL")

	if connStr == "" {
		slog.Error("CRITICAL: DATABASE_URL Umgebungsvariable fehlt. Abbruch aus Sicherheitsgründen.")
		os.Exit(1)
	}

	var err error
	Pool, err = pgxpool.New(ctx, connStr)
	if err != nil {
		return fmt.Errorf("verbindung zur Datenbank fehlgeschlagen: %w", err)
	}

	if err := Pool.Ping(ctx); err != nil {
		return fmt.Errorf("datenbank antwortet nicht: %w", err)
	}

	slog.Info("Erfolgreich mit PostgreSQL verbunden")
	return nil
}
