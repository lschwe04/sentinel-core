package auth

import (
	"context"
	"net/http"
	"sentinel-core/internal/db"
)

func RequireActiveSubscription(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			http.Error(w, "Unauthorized: Missing Tenant", http.StatusUnauthorized)
			return
		}

		ctx := context.Background()
		var status string
		query := `SELECT subscription_status FROM tenants WHERE slug = $1`
		err := db.Pool.QueryRow(ctx, query, tenantID).Scan(&status)

		if err != nil || status != "active" {
			http.Error(w, "Payment Required: Active subscription needed", http.StatusPaymentRequired)
			return
		}

		next.ServeHTTP(w, r)
	})
}
