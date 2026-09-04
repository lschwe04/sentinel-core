package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const TenantKey contextKey = "tenant_id"

func TenantAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		authHeader := r.Header.Get("Authorization")

		if tenantID == "" || authHeader == "" {
			http.Error(w, `{"error": "Unauthorized: Missing tenant parameters"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			http.Error(w, `{"error": "Unauthorized: Invalid token format"}`, http.StatusUnauthorized)
			return
		}

		// In Produktion: Token-Signatur (JWT) oder Datenbank-Lookup verifizieren
		ctx := context.WithValue(r.Context(), TenantKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
