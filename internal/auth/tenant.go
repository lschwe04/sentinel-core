package auth

import (
	"context"
	"net/http"
	"sentinel-core/internal/observability"
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
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: missing tenant parameters")
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: invalid token format")
			return
		}

		claims, err := ParseUserJWT(strings.TrimPrefix(authHeader, "Bearer "))
		if err != nil {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: invalid token")
			return
		}
		claimTenant, ok := claims["tenant_id"].(string)
		if !ok || claimTenant == "" || claimTenant != tenantID {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusForbidden, "forbidden: tenant mismatch")
			return
		}
		ctx := context.WithValue(r.Context(), TenantKey, claimTenant)
		ctx = context.WithValue(ctx, AuthenticatedTenantKey, claimTenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
