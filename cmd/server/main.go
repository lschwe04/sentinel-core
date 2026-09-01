package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-core/internal/handlers"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Routing Setup (Go 1.22+)
	mux := http.NewServeMux()
	
	// API Endpoints für die 5 Reiter
	mux.HandleFunc("GET /api/v1/hardening/status", handlers.GetHardeningStatus)
	mux.HandleFunc("POST /api/v1/hardening/trigger", handlers.TriggerHardening)
	mux.HandleFunc("GET /api/v1/backup/status", handlers.GetBackupStatus)
	// Weitere Routen für Metriken, Logs und Provisioning analog...

	// Middleware: Auth Token validieren (Zero-Trust)
	secureMux := enforceAuth(mux)

	// TLS Konfiguration (Strikt für mTLS)
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		// In Production: ClientCAs laden für mTLS Verifizierung der Agenten
	}

	server := &http.Server{
		Addr:         "10.0.0.1:8443", // Bindung an das WireGuard Interface
		Handler:      secureMux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful Shutdown Channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("SentinelCore Hub API startet auf 10.0.0.1:8443")
		if err := server.ListenAndServeTLS("certs/hub-cert.pem", "certs/hub-key.pem"); err != nil && err != http.ErrServerClosed {
			slog.Error("Server Fehler", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Fahre Server kontrolliert herunter...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Fehler beim Shutdown", "error", err)
	}
}

func enforceAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer SECRET_ENTERPRISE_TOKEN" { // In Prod: JWT/Vault Integration
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
