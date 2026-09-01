package auth

import (
	"context"
	"net/http"
)

type contextKey string

const TenantKey contextKey = "tenant_id"

// TenantMiddleware extrahiert das Systemhaus anhand eines Headers (oder mTLS CN in Prod)
func TenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			http.Error(w, "Unauthorized: Missing Tenant Context", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), TenantKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
