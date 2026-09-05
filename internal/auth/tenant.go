package auth

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v4"
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

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error": "Unauthorized: Invalid token format"}`, http.StatusUnauthorized)
			return
		}

		secret := os.Getenv("JWT_SECRET")
		if len(secret) < 32 {
			http.Error(w, `{"error": "Authentication is not configured"}`, http.StatusInternalServerError)
			return
		}
		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(strings.TrimPrefix(authHeader, "Bearer "), claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, `{"error": "Unauthorized: Invalid token"}`, http.StatusUnauthorized)
			return
		}
		claimTenant, ok := (*claims)["tenant_id"].(string)
		if !ok || claimTenant == "" || claimTenant != tenantID {
			http.Error(w, `{"error": "Forbidden: Tenant mismatch"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), TenantKey, claimTenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
