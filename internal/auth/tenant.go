package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const TenantKey contextKey = "tenant_id"
const AuthenticatedTenantKey contextKey = "authenticated_tenant_id"

func TenantAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		authHeader := r.Header.Get("Authorization")

		if tenantID == "" || authHeader == "" {
			http.Error(w, `{"error": "Unauthorized: Missing tenant parameters"}`, http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error": "Unauthorized: Invalid token format"}`, http.StatusUnauthorized)
			return
		}

		claims, err := ParseUserJWT(strings.TrimPrefix(authHeader, "Bearer "))
		if err != nil {
			http.Error(w, `{"error": "Unauthorized: Invalid token"}`, http.StatusUnauthorized)
			return
		}
		claimTenant, ok := claims["tenant_id"].(string)
		if !ok || claimTenant == "" || claimTenant != tenantID {
			http.Error(w, `{"error": "Forbidden: Tenant mismatch"}`, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), TenantKey, claimTenant)
		ctx = context.WithValue(ctx, AuthenticatedTenantKey, claimTenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
