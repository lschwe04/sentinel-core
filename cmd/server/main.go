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

	addr := os.Getenv("HUB_ADDR")
	if addr == "" {
		addr = "10.0.0.1:8443"
	}

	mux := http.NewServeMux()

	// API Endpoints für Nodes & UI
	mux.HandleFunc("GET /api/v1/hardening/status", handlers.GetHardeningStatus)
	mux.HandleFunc("POST /api/v1/hardening/trigger", handlers.TriggerHardening)
	mux.HandleFunc("GET /api/v1/backup/status", handlers.GetBackupStatus)
	mux.HandleFunc("POST /api/v1/metrics", handlers.IngestMetrics)
	mux.HandleFunc("GET /api/v1/metrics", handlers.GetMetrics)

	// UI Reiter Routen
	mux.HandleFunc("GET /api/v1/ui/hardening", handlers.RenderHardeningTab)
	mux.HandleFunc("GET /api/v1/ui/metrics", handlers.RenderMetricsTab)
	mux.HandleFunc("GET /api/v1/ui/backups", handlers.RenderBackupsTab)
	mux.HandleFunc("GET /api/v1/ui/logs", handlers.RenderLogsTab)
	mux.HandleFunc("GET /api/v1/ui/provisioning", handlers.RenderProvisioningTab)
	mux.HandleFunc("POST /api/v1/provisioning/trigger", handlers.TriggerProvisioning)

	secureMux := enforceAuth(mux)

	tlsConfig, err := getEnterpriseTLSConfig()
	if err != nil {
		slog.Error("Konnte mTLS-Zertifikate nicht laden", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      secureMux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("SentinelCore Hub API startet", "addr", server.Addr)
		if err := server.ListenAndServeTLS("certs/hub-cert.pem", "certs/hub-key.pem"); err != nil && err != http.ErrServerClosed {
			slog.Error("Server Fehler", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Fahre Server kontrolliert herunter...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

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
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                caCertPool,
	}, nil
}

func enforceAuth(next http.Handler) http.Handler {
	// Token über Umgebungsvariable beziehen statt hartkodiert
	secretToken := os.Getenv("ENTERPRISE_AUTH_TOKEN")
	if secretToken == "" {
		secretToken = "SECRET_ENTERPRISE_TOKEN" // Fallback für lokale Entwicklung
	}
	expectedHeader := "Bearer " + secretToken

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			slog.Debug("mTLS Verbindung verifiziert", "client_cn", clientCert.Subject.CommonName)
		}

		token := r.Header.Get("Authorization")
		if token != expectedHeader {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
