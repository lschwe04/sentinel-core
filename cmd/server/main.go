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

	// mTLS-Konfiguration aufrufen
	tlsConfig, err := getEnterpriseTLSConfig()
	if err != nil {
		slog.Error("Konnte mTLS-Zertifikate nicht laden", "error", err)
		os.Exit(1)
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
		slog.Info("SentinelCore Hub API startet auf 10.0.0.1:8443 (mTLS aktiv)")
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

// getEnterpriseTLSConfig lädt die CA und erzwingt mTLS für alle Agenten-Verbindungen
func getEnterpriseTLSConfig() (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequireAndVerifyClientCert, // Erzwingt mTLS für Agenten!
		ClientCAs:                caCertPool,
	}, nil
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
