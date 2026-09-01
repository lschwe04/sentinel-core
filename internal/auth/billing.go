package auth

import (
	"context"
	"net/http"
	"sentinel-core/internal/db"
	"time"
)

// RequireActiveSubscription erzwingt, dass das Systemhaus ein aktives Abo hat
func RequireActiveSubscription(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			http.Error(w, "Unauthorized: Missing Tenant Header", http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		var status string
		query := `SELECT subscription_status FROM tenants WHERE slug = $1 OR id::text = $1`
		err := db.Pool.QueryRow(ctx, query, tenantID).Scan(&status)

		if err != nil || status != "active" {
			http.Error(w, "Payment Required: Active subscription needed to ingest data", http.StatusPaymentRequired)
			return
		}

		next(w, r)
	}
}
