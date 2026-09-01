package handlers

import (
	"context"
	"net/http"
	"sentinel-core/internal/db"
	"time"
)

func HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// Prüfe, ob die Datenbankverbindung steht
	if err := db.Pool.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("STATUS: UNHEALTHY (Database down)"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("STATUS: HEALTHY"))
}
