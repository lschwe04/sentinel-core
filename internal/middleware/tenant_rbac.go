package middleware

import (
	"context"
	"net/http"
	"strings"

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

// EnforceTenantAndRBAC validiert Tokens, prüft Live-Rechte in der DB und isoliert Mandanten
func EnforceTenantAndRBAC(requiredRole string, jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error": "Unauthorized: Missing or malformed token"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// 1. JWT parsen & signatur prüfen
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

			userID, _ := claims["sub"].(string)
			jwtTenantID, _ := claims["tenant_id"].(string)

			if userID == "" || jwtTenantID == "" {
				http.Error(w, `{"error": "Forbidden: Incomplete identity context in token"}`, http.StatusForbidden)
				return
			}

			// 2. Anti-Spoofing: Verhindert das Einschleusen fremder Tenant-Header
			headerTenantID := r.Header.Get("X-Tenant-ID")
			if headerTenantID != "" && headerTenantID != jwtTenantID {
				http.Error(w, `{"error": "Forbidden: Tenant cross-contamination attempt detected"}`, http.StatusForbidden)
				return
			}

			// 3. Live-RBAC DB-Check: Rollen- & Zuordnungsabfrage aus der Datenbank
			var liveRole string
			var dbCustomerID *int

			query := `
				SELECT r.name, ur.customer_id 
				FROM user_roles ur
				JOIN roles r ON ur.role_id = r.id
				WHERE ur.user_id = $1 AND ur.tenant_id = $2
			`
			err = db.Pool.QueryRow(r.Context(), query, userID, jwtTenantID).Scan(&liveRole, &dbCustomerID)
			if err != nil {
				http.Error(w, `{"error": "Forbidden: Access rights revoked or user assignment missing"}`, http.StatusForbidden)
				return
			}

			// 4. Hierarchische Rollenprüfung
			if !hasPermission(liveRole, requiredRole) {
				http.Error(w, `{"error": "Access Denied: Insufficient privilege level"}`, http.StatusForbidden)
				return
			}

			// 5. Kundenebene-Einschränkung für "customer_view"
			requestedCustomer := r.URL.Query().Get("customer_id")
			if liveRole == "customer_view" {
				if dbCustomerID == nil {
					http.Error(w, `{"error": "Forbidden: Scoped customer assignment missing"}`, http.StatusForbidden)
					return
				}
				// Falls ein spezifischer Kunde angefragt wird, muss dieser mit dem zugewiesenen übereinstimmen
				if requestedCustomer != "" && stringToInt(requestedCustomer) != *dbCustomerID {
					http.Error(w, `{"error": "Forbidden: Access restricted to assigned customer entity"}`, http.StatusForbidden)
					return
				}
			}

			// 6. Sicheren Kontext für nachfolgende Handler aufbauen
			ctx := context.WithValue(r.Context(), ContextKeyUserID, userID)
			ctx = context.WithValue(ctx, ContextKeyTenantID, jwtTenantID)
			ctx = context.WithValue(ctx, ContextKeyRole, liveRole)

			if dbCustomerID != nil {
				ctx = context.WithValue(ctx, ContextKeyCustomerID, *dbCustomerID)
			} else if requestedCustomer != "" {
				ctx = context.WithValue(ctx, ContextKeyCustomerID, requestedCustomer)
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

func stringToInt(s string) int {
	var id int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		id = id*10 + int(ch-'0')
	}
	return id
}
