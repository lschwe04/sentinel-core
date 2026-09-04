package api

import (
	"context"
	"net/http"
	"strings"

	"sentinel-core/internal/auth"
)

type contextKey string

const ClaimsContextKey contextKey = "agent_claims"

type AuthMiddleware struct {
	secManager *auth.SecurityManager
}

func NewAuthMiddleware(sm *auth.SecurityManager) *AuthMiddleware {
	return &AuthMiddleware{secManager: sm}
}

// RequireAgentAuth prüft den Bearer Token und blockiert unautorisierte Zugriffe
func (m *AuthMiddleware) RequireAgentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := m.secManager.ValidateJWT(tokenStr)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Claims in den Context schreiben für nachgelagerte Handler (z.B. Audit Logger)
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
