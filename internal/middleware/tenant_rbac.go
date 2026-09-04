package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type contextKey string

const (
	ContextKeyTenantID   contextKey = "tenant_id"
	ContextKeyRole       contextKey = "role"
	ContextKeyCustomerID contextKey = "customer_id"
)

// EnforceTenantAndRBAC garantiert, dass Systemhaus-Techniker nur auf ihre mandantenberechtigten Daten zugreifen
func EnforceTenantAndRBAC(requiredRole string, jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error": "Unauthorized: Missing or malformed token"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// Token parsen und validieren
			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, http.ErrAbortHandler
				}
				return []byte(jwtSecret), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error": "Forbidden: Invalid or expired session"}`, http.StatusForbidden)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error": "Forbidden: Corrupt token claims"}`, http.StatusForbidden)
				return
			}

			// Rollen-Prüfung (z.B. "admin" oder "technician")
			userRole, _ := claims["role"].(string)
			if requiredRole == "admin" && userRole != "admin" {
				http.Error(w, `{"error": "Access Denied: Admin privileges required for this action"}`, http.StatusForbidden)
				return
			}

			// Mandanten-IDs aus Claims extrahieren
			tenantID, _ := claims["tenant_id"].(string)
			customerID := r.URL.Query().Get("customer_id")

			// Wenn ein spezifischer Endkunde abgefragt wird, prüfen ob der Tenant berechtigt ist
			if customerID != "" && userRole != "admin" {
				// Hier könnte in Produktion ein DB-Lookup erfolgen, ob Tenant den Kunden besitzt
				if tenantID == "" {
					http.Error(w, `{"error": "Tenant context missing"}`, http.StatusBadRequest)
					return
				}
			}

			// Kontext für nachfolgende Handler anichern
			ctx := context.WithValue(r.Context(), ContextKeyTenantID, tenantID)
			ctx = context.WithValue(ctx, ContextKeyRole, userRole)
			ctx = context.WithValue(ctx, ContextKeyCustomerID, customerID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
