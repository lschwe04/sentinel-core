package db

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// WithTenantTx starts a short-lived transaction and sets the tenant GUC locally.
// The caller must perform all RLS-protected reads and writes through tx.
func WithTenantTx(ctx context.Context, tenantID int, fn func(context.Context, pgx.Tx) error) error {
	txCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := Pool.BeginTx(txCtx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer tx.Rollback(txCtx)

	if _, err := tx.Exec(txCtx, "SELECT set_config('app.tenant_id', $1, true)", strconv.Itoa(tenantID)); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(txCtx, tx); err != nil {
		return err
	}
	if err := tx.Commit(txCtx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}
