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
		// Fallback zu Standard-Werten aus deiner Config
		connStr = "postgres://sentinel:secret@postgres:5432/sentinel_db?sslmode=verify-full"
	}

	var err error
	Pool, err = pgxpool.New(ctx, connStr)
	if err != nil {
		return fmt.Errorf("konnte Verbindung zur Datenbank nicht herstellen: %w", err)
	}

	if err := Pool.Ping(ctx); err != nil {
		return fmt.Errorf("datenbank antwortet nicht: %w", err)
	}

	slog.Info("Erfolgreich mit PostgreSQL verbunden")
	return nil
}
