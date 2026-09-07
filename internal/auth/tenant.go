package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"sentinel-core/internal/observability"
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

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		parts := strings.Split(tokenString, ".")
		if len(parts) != 3 {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: invalid token structure")
			return
		}

		// 1. JWT-Signatur mittels Standardbibliothek (HMAC-SHA256) verifizieren
		jwtSecret := os.Getenv("JWT_SECRET")
		mac := hmac.New(sha256.New, []byte(jwtSecret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		expectedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || !hmac.Equal(mac.Sum(nil), expectedSig) {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: invalid token signature")
			return
		}

		// 2. Payload-Claims decodieren
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: invalid token payload")
			return
		}

		var claims map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			observability.AuthFailure()
			writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: invalid token claims")
			return
		}

		// 3. Optional: Token-Ablaufzeit prüfen (exp)
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				observability.AuthFailure()
				writeRateLimitError(w, http.StatusUnauthorized, "unauthorized: token expired")
				return
			}
		}

		// 4. Tenant-Übereinstimmung prüfen
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
