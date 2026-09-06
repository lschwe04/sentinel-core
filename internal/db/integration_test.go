//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgresMigrationsAndTenantRepository(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := postgres.Run(ctx, "postgres:16-alpine", postgres.WithDatabase("sentinel"), postgres.WithUsername("sentinel"), postgres.WithPassword("test-password"), testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	connectionString, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	Pool, err = pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Pool.Close() })
	if err := RunMigrations(); err != nil {
		t.Fatal(err)
	}
	if _, err := Pool.Exec(ctx, `INSERT INTO tenants (name, slug) VALUES ('Integration Tenant', 'integration')`); err != nil {
		t.Fatal(err)
	}
	if _, err := Pool.Exec(ctx, `INSERT INTO tenants (name, slug) VALUES ('Other Tenant', 'other')`); err != nil {
		t.Fatal(err)
	}
	if err := (MetricsRepository{}).Insert(ctx, "1", "node-1", 10, 20, 30, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := (MetricsRepository{}).Latest(ctx, "2", "node-1"); err == nil {
		t.Fatal("cross-tenant metric was visible")
	}
}
