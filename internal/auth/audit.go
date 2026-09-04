// sentinel-core: internal/auth/audit.go (Neu)
package auth

import (
	"context"
	"log/slog"
	"net/http"
	"sentinel-core/internal/db"
)

func AuditLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Nur schreibende Aktionen loggen
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			tenantID := r.Header.Get("X-Tenant-ID")
			techEmail := r.Header.Get("X-Technician-Email") // Aus JWT extrahiert
			ipAddress := r.RemoteAddr

			go func() {
				query := `INSERT INTO tenant_audit_logs (tenant_id, technician_email, action, target_node, ip_address) 
						  VALUES ($1, $2, $3, $4, $5)`
				// target_node müsste aus dem Body/URL-Param gelesen werden
				_, err := db.Pool.Exec(context.Background(), query, tenantID, techEmail, r.URL.Path, "node-xyz", ipAddress)
				if err != nil {
					slog.Error("Audit Log Fehler", "error", err)
				}
			}()
		}
		next.ServeHTTP(w, r)
	})
}
