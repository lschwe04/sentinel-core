package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinel-core/internal/db"

	"github.com/golang-jwt/jwt/v4"
)

type contextKey string

const (
	ContextKeyUserID     contextKey = "user_id"
	ContextKeyTenantID   contextKey = "tenant_id"
	ContextKeyRole       contextKey = "role"
	ContextKeyCustomerID contextKey = "customer_id"
)

// Hierarchie-Map für den Abgleich von Mindestberechtigungen
var roleHierarchy = map[string]int{
	"customer_view": 1,
	"syshaus_tech":  2,
	"syshaus_admin": 3,
}

// Typed Claims für sicheres und performantes JWT-Parsing
type JWTClaims struct {
	UserID   string `json:"sub"`
	TenantID string `json:"tenant_id"`
	jwt.RegisteredClaims
}

// EnforceTenantAndRBAC validiert Tokens, prüft Live-Rechte in der DB und isoliert Mandanten
func EnforceTenantAndRBAC(requiredRole string, jwtSecret string) func(http.Handler) http.Handler {
	secretBytes := []byte(jwtSecret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				respondJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing or malformed token")
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// 1. JWT parsen & Signatur prüfen
			claims := &JWTClaims{}
			token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return secretBytes, nil
			})

			if err != nil || !token.Valid {
				respondJSONError(w, http.StatusForbidden, "Forbidden: Invalid or expired session")
				return
			}

			if claims.UserID == "" || claims.TenantID == "" {
				respondJSONError(w, http.StatusForbidden, "Forbidden: Incomplete identity context in token")
				return
			}

			// 2. Anti-Spoofing: Verhindert das Einschleusen fremder Tenant-Header
			headerTenantID := r.Header.Get("X-Tenant-ID")
			if headerTenantID != "" && headerTenantID != claims.TenantID {
				respondJSONError(w, http.StatusForbidden, "Forbidden: Tenant cross-contamination attempt detected")
				return
			}

			// 3. Live-RBAC DB-Check mit Query Timeout
			dbCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()

			var liveRole string
			var dbCustomerID *int

			query := `
				SELECT r.name, ur.customer_id 
				FROM user_roles ur
				JOIN roles r ON ur.role_id = r.id
				WHERE ur.user_id = $1 AND ur.tenant_id = $2
			`
			err = db.Pool.QueryRow(dbCtx, query, claims.UserID, claims.TenantID).Scan(&liveRole, &dbCustomerID)
			if err != nil {
				respondJSONError(w, http.StatusForbidden, "Forbidden: Access rights revoked or user assignment missing")
				return
			}

			// 4. Hierarchische Rollenprüfung
			if !hasPermission(liveRole, requiredRole) {
				respondJSONError(w, http.StatusForbidden, "Access Denied: Insufficient privilege level")
				return
			}

			// 5. Kundenebene-Einschränkung für "customer_view"
			requestedCustomerStr := r.URL.Query().Get("customer_id")
			if liveRole == "customer_view" {
				if dbCustomerID == nil {
					respondJSONError(w, http.StatusForbidden, "Forbidden: Scoped customer assignment missing")
					return
				}

				if requestedCustomerStr != "" {
					reqCustID, parseErr := strconv.Atoi(requestedCustomerStr)
					if parseErr != nil || reqCustID != *dbCustomerID {
						respondJSONError(w, http.StatusForbidden, "Forbidden: Access restricted to assigned customer entity")
						return
					}
				}
			}

			// 6. Sicheren Kontext für nachfolgende Handler aufbauen
			ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, ContextKeyTenantID, claims.TenantID)
			ctx = context.WithValue(ctx, ContextKeyRole, liveRole)

			// Kontext-Typisierung für CustomerID durchgehend als int beibehalten
			if dbCustomerID != nil {
				ctx = context.WithValue(ctx, ContextKeyCustomerID, *dbCustomerID)
			} else if requestedCustomerStr != "" {
				if reqCustID, parseErr := strconv.Atoi(requestedCustomerStr); parseErr == nil {
					ctx = context.WithValue(ctx, ContextKeyCustomerID, reqCustID)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper: Prüft, ob die Ist-Rolle die Rechte der Soll-Rolle abdeckt
func hasPermission(actualRole, requiredRole string) bool {
	actualLevel, existsActual := roleHierarchy[actualRole]
	requiredLevel, existsRequired := roleHierarchy[requiredRole]

	if !existsActual || !existsRequired {
		return false
	}
	return actualLevel >= requiredLevel
}

// Helper: Saubere JSON-Fehlerantworten mit korrektem Content-Type Header
func respondJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
