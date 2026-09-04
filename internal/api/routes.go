// sentinel-core/internal/api/routes.go
package api

import (
	"encoding/json"
	"net/http"

	"sentinel-core/internal/middleware"
)

// SetupRoutes registriert die Endpunkte unter Verwendung Ihrer bestehenden RBAC-Middleware
func SetupRoutes(mux *http.ServeMux, jwtSecret string) {

	// Endpunkt für den FIM-Agenten (Nur Techniker oder Admin-Rolle erlaubt)
	fimHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Mandanten-Kontext auslesen, den Ihre Middleware sicher in den Request gelegt hat
		tenantID := r.Context().Value(middleware.ContextKeyTenantID).(string)
		userRole := r.Context().Value(middleware.ContextKeyRole).(string)

		// Beispiel: Verarbeite die eingehenden FIM-Alarme für diesen Mandanten
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(encodeWriter(w)).Encode(map[string]interface{}{
			"status":    "success",
			"message":   "FIM alert processed successfully",
			"tenant_id": tenantID,
			"role":      userRole,
		})
	})

	// Middleware davor schalten (Erfordert mindestens Techniker-Rechte)
	securedFIMHandler := middleware.EnforceTenantAndRBAC("technician", jwtSecret)(fimHandler)

	mux.Handle("/api/v1/sentinel/fim-alert", securedFIMHandler)
}

func encodeWriter(w http.ResponseWriter) http.ResponseWriter {
	return w
}
