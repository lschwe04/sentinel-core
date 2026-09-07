package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TenantRepository struct {
	pool *pgxpool.Pool
}

func NewTenantRepository(pool *pgxpool.Pool) *TenantRepository {
	return &TenantRepository{pool: pool}
}

// ExecWithRLS führt eine Funktion innerhalb einer RLS-gesicherten Transaktion aus.
func (r *TenantRepository) ExecWithRLS(ctx context.Context, tenantID string, fn func(tx pgxx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Setze die Session-Variable für Row-Level-Security VOR dem eigentlichen Query
	_, err = tx.Exec(ctx, "SET LOCAL app.tenant_id = $1", tenantID)
	if err != nil {
		return fmt.Errorf("RLS setup failed: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
