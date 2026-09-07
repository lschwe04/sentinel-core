package auth

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogMiddleware nimmt nun den dbPool entgegen und gibt die eigentliche Middleware zurück
func AuditLogMiddleware(dbPool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Nur schreibende Aktionen loggen
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				tenantID, _ := r.Context().Value(AuthenticatedTenantKey).(string)
				if tenantID == "" {
					next.ServeHTTP(w, r)
					return
				}
				techEmail := "authenticated-user"
				ipAddress := r.RemoteAddr
				query := `INSERT INTO tenant_audit_logs (tenant_id, technician_email, action, target_node, ip_address) VALUES ($1, $2, $3, $4, $5)`
				if _, err := dbPool.Exec(r.Context(), query, tenantID, techEmail, r.URL.Path, "node-unknown", ipAddress); err != nil {
					slog.Error("Audit Log Fehler", "error", err)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
